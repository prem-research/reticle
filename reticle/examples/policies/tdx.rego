# TDX attestation policy
# ============================================================================
# Queried by reticle as `data.tdx.allow` (see reticle/src/lib.rs -> attest_tdx,
# WithPolicy::new("tdx.allow", quote)). The engine expects `allow` to evaluate
# to a BOOLEAN; anything else makes libattest error out (see validation.rs).
#
# `input` is the serialized `TdxQuoteBody` (tdx-attest/src/dcap/types.rs). Only
# the TD *measurement* body reaches Rego — every cryptographic check (QE report
# signature, ISV signature, QE identity, platform TCB level, and the
# report_data/nonce match) has ALREADY been enforced in Rust by
# TdxQuoteVerifier before this policy runs. This policy's job is purely to
# appraise *which* TD measurements you are willing to trust.
#
# Serialized input shape (field names are the raw struct identifiers, note the
# `seamsttributes` typo is intentional and must be matched verbatim):
#
#   {
#     "tee_tcb_svn":    [ 16 ints ],
#     "mrseam":         "<96 hex chars>",   # SHA-384
#     "mrsignerseam":   "<96 hex chars>",   # SHA-384
#     "seamsttributes": [ 8 ints ],
#     "tdattributes":   [ 8 ints ],
#     "xfam":           [ 8 ints ],
#     "mrtd":           "<96 hex chars>",   # SHA-384
#     "mrconfigid":     "<96 hex chars>",
#     "mrowner":        "<96 hex chars>",
#     "mrownerconfig":  "<96 hex chars>",
#     "rtmr":           [ "<96 hex>", "<96 hex>", "<96 hex>", "<96 hex>" ],
#     "report_data":    "<128 hex chars>"   # the nonce; verified in Rust
#   }
#
# Appraisal strategy — a baseline that stays portable across hosts:
#
#   * INVARIANTS (always enforced, machine-independent):
#       - DEBUG attribute bit clear — off-TD debug exposes TD memory
#       - tdattributes restricted to an allowed-bits mask
#       - xfam restricted to an allowed-bits mask
#       - mrsignerseam == all zeros — Intel-signed production TDX module
#       - seamsttributes == all zeros — required for production modules
#       - tee_tcb_svn >= a component-wise minimum — anti-rollback floor for
#         the TDX module (SVNs only increase with security patches)
#       - mrconfigid / mrowner / mrownerconfig == all zeros — no
#         owner-defined config in use (change if you use them)
#
#   * IMAGE MEASUREMENTS (environment-specific): mrtd, mrseam and the RTMRs
#     are left unpinned by default because they legitimately vary per host
#     (TDX module version), per firmware build (mrtd) or per boot/VM config
#     (memory map, kernel, cmdline, initrd land in RTMR[0..2]). The values
#     observed on the known-good baseline TD are documented next to each
#     field — pin them once your fleet's values are catalogued.
# ============================================================================
package tdx

import rego.v1

# ---------------------------------------------------------------------------
# Reference values
# ---------------------------------------------------------------------------
# Baseline captured from a known-good TD (Azure TDX host, July 2026). Each
# entry may also be supplied out-of-band via `data.tdx.reference.<field>`
# (reticle loads data JSON files alongside policies), which takes precedence
# over the inline value.
#
# Hex fields are compared case-insensitively. Any reference field left as its
# empty default (empty string / empty array) is treated as "don't care" and
# skips that check, so you can enable checks incrementally.
# ---------------------------------------------------------------------------

reference := object.union(inline_reference, data_reference)

inline_reference := {
	# MRTD: SHA-384 over the initial TD contents (the TDVF/OVMF firmware
	# image). Varies per firmware build, so it is not pinned yet; pin it (or
	# override per-environment via a data file) once your images are fixed.
	# Observed baseline: 7348651a34b2d2d3462822e3a750ec6110125f36757c78480bbfc69cc0d21fb001a1ced3ee19747dda8f750c3bc8f876
	"mrtd": "",
	# MRSEAM: hash of the TDX module itself. Varies with the module version
	# installed on each host, so it is not pinned; trust is anchored instead
	# on mrsignerseam (Intel-signed) plus the tee_tcb_svn_min floor below.
	# Observed baseline: aef4ed3e686fe6cf44c9a8d1cc63105443b558ac4f40c282abf78271e9a4586c50408c8584c7b43fd21edb736700ba5f
	"mrseam": "",
	# All zeros == TDX module signed by Intel (production). Keep pinned.
	"mrsignerseam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	# No owner-provided TD configuration in use; all three stay zero.
	"mrconfigid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"mrowner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"mrownerconfig": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	# RTMRs vary per host/boot config, so they are unpinned by default:
	#   rtmr[0] firmware config + TD HOB (memory map -> differs per VM shape)
	#   rtmr[1] kernel                rtmr[2] cmdline / initrd
	#   rtmr[3] runtime / application extensions
	# Observed baseline (pin once your fleet's values are catalogued):
	#   [0] 1186572fbf5ba745c0a78870c91b136407a28523c8cd5914c86c1bca61c9e767245b403ad4966b8322728bff66893640
	#   [1] 94f3c46bfc3898702ccbdbd4bcaf13b65319bae159d7f6b69d7407e229a5cca453453082233fbf1a8802bdc9a620b929
	#   [2] eb58944d4dcde0d57e09664799f2e3e18aed927d52aac4342b21b9d39132ed3cca75901257543e5670dc64e7311bb594
	#   [3] 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
	"rtmr": ["", "", "", ""],
	# Component-wise MINIMUM for the TDX module TCB SVNs (input must be >= in
	# every position). SVNs only increase with security patches, so this is an
	# anti-rollback floor rather than an exact pin. [] to skip.
	"tee_tcb_svn_min": [7, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
	# Must be all zeros on production TDX modules; exact match. [] to skip.
	"seamsttributes": [0, 0, 0, 0, 0, 0, 0, 0],
	# ALLOWED-bits mask (little-endian bytes of the 64-bit ATTRIBUTES field):
	# any input bit outside the mask rejects the TD. Baseline permits only
	# SEPT_VE_DISABLE (bit 28 -> byte 3, 0x10). DEBUG (bit 0) stays
	# hard-rejected by `debug_disabled` even if you widen this mask. [] to
	# skip.
	"tdattributes_allowed": [0, 0, 0, 16, 0, 0, 0, 0],
	# ALLOWED-bits mask for XFAM (extended CPU features the TD may use). A TD
	# using a subset passes; unexpected features reject. Baseline = x87/SSE
	# (bits 0-1), AVX (2), AVX-512 (5-7), PKRU (9), AMX (17-18). Widen when
	# your fleet enables more (e.g. CET bits 11-12). [] to skip.
	"xfam_allowed": [231, 2, 6, 0, 0, 0, 0, 0],
}

# path-based lookup so this is safe even when no `data.tdx` document is loaded
data_reference := object.get(data, ["tdx", "reference"], {})

# ---------------------------------------------------------------------------
# Top-level decision
# ---------------------------------------------------------------------------
default allow := false

allow if {
	debug_disabled
	mrtd_ok
	mrseam_ok
	mrsignerseam_ok
	mrconfigid_ok
	mrowner_ok
	mrownerconfig_ok
	rtmrs_ok
	tee_tcb_svn_ok
	seamsttributes_ok
	xfam_ok
	tdattributes_ok
}

# ---------------------------------------------------------------------------
# TD ATTRIBUTES — the DEBUG bit (bit 0 of octet 0) MUST be clear, otherwise the
# TD can be single-stepped / introspected and offers no confidentiality. This
# check is unconditional; it cannot be skipped via the reference values.
# ---------------------------------------------------------------------------
debug_disabled if bits.and(input.tdattributes[0], 1) == 0

# ---------------------------------------------------------------------------
# Hex measurement checks. Each rule passes when the reference is unset ("")
# OR the (case-insensitive) hex matches.
# ---------------------------------------------------------------------------
mrtd_ok if hex_match(reference.mrtd, input.mrtd)

mrseam_ok if hex_match(reference.mrseam, input.mrseam)

mrsignerseam_ok if hex_match(reference.mrsignerseam, input.mrsignerseam)

mrconfigid_ok if hex_match(reference.mrconfigid, input.mrconfigid)

mrowner_ok if hex_match(reference.mrowner, input.mrowner)

mrownerconfig_ok if hex_match(reference.mrownerconfig, input.mrownerconfig)

# every RTMR index must match its (optional) reference entry
rtmrs_ok if {
	every i, ref in reference.rtmr {
		hex_match(ref, input.rtmr[i])
	}
}

# ---------------------------------------------------------------------------
# Byte-array checks.
# ---------------------------------------------------------------------------

# anti-rollback floor: every SVN component must be >= its reference minimum
tee_tcb_svn_ok if svn_at_least(reference.tee_tcb_svn_min, input.tee_tcb_svn)

# exact match: production TDX modules report all-zero SEAM attributes
seamsttributes_ok if bytes_match(reference.seamsttributes, input.seamsttributes)

# masks: no input bit may fall outside the allowed set
xfam_ok if bytes_within_mask(reference.xfam_allowed, input.xfam)

tdattributes_ok if bytes_within_mask(reference.tdattributes_allowed, input.tdattributes)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# case-insensitive hex equality; empty reference == "don't care"
hex_match(ref, got) if ref == ""

hex_match(ref, got) if {
	ref != ""
	lower(ref) == lower(got)
}

# exact byte-array equality; empty reference == "don't care"
bytes_match(ref, got) if count(ref) == 0

bytes_match(ref, got) if {
	count(ref) > 0
	ref == got
}

# component-wise minimum; empty reference == "don't care"
svn_at_least(min, got) if count(min) == 0

svn_at_least(min, got) if {
	count(min) > 0
	every i, m in min {
		got[i] >= m
	}
}

# every input bit must lie within the allowed mask; empty == "don't care"
bytes_within_mask(allowed, got) if count(allowed) == 0

bytes_within_mask(allowed, got) if {
	count(allowed) > 0
	every i, b in got {
		bits.and(b, bits.xor(allowed[i], 255)) == 0
	}
}
