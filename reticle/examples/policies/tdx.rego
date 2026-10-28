# Client::attest_quote supplies {manifest: PodManifest, claims: TdxQuoteBody}
# after Rust verifies the quote and its manifest-bound nonce. Hardware fields
# live under input.claims; the `seamsttributes` spelling matches the Rust type.
# PodManifest has no tee_type; Client::attest selects this policy for TDX.
#
# ClientBuilder loads https://trustbase.prem.io/measurements.json into
# data.measurements. Require the named workload/release and its TDX
# measurements; missing references and revoked Init-Data deny access.
# The manifest selects reference values, while the quote must prove a match.
# This admits any matching workload/release in the catalog. Add an explicit
# workload/version allowlist if the caller requires a narrower selection.
package tdx

import rego.v1

workload := data.measurements.workloads[input.manifest.workload_id]
reference := workload.releases[input.manifest.podvm_version].tdx

# Platform baseline retained from the original demo. Tune these independently
# of workload measurements for the platforms your deployment supports.
tee_tcb_svn_min := [7, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
tdattributes_allowed := [0, 0, 0, 16, 0, 0, 0, 0]
xfam_allowed := [231, 2, 6, 0, 0, 0, 0, 0]
zero_measurement := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

default allow := false

allow if {
	data.measurements.schema_version == 1
	initdata_not_revoked
	measurements_match
	debug_disabled
	svn_at_least(tee_tcb_svn_min, input.claims.tee_tcb_svn)
	input.claims.seamsttributes == [0, 0, 0, 0, 0, 0, 0, 0]
	hex_equal(zero_measurement, input.claims.mrsignerseam)
	hex_equal(zero_measurement, input.claims.mrowner)
	hex_equal(zero_measurement, input.claims.mrownerconfig)
	bytes_within_mask(tdattributes_allowed, input.claims.tdattributes)
	bytes_within_mask(xfam_allowed, input.claims.xfam)
}

measurements_match if {
	hex_equal(reference.mr_td, input.claims.mrtd)
	is_array(input.claims.rtmr)
	count(input.claims.rtmr) == 4
	hex_equal(reference.rtmr_0, input.claims.rtmr[0])
	hex_equal(reference.rtmr_1, input.claims.rtmr[1])
	hex_equal(reference.rtmr_2, input.claims.rtmr[2])

	# Bind the selected workload's init-data to the measured configuration.
	hex_equal(workload.initdata.mr_config_id, input.claims.mrconfigid)
}

# Revocations identify Init-Data by digest, even if registered under another ID.
# Rust omits an empty revoked list when serializing the catalog into Rego.
initdata_not_revoked if {
	hex_string(workload.initdata.sha256, 64)
	revoked := object.get(data.measurements, "revoked", [])
	is_array(revoked)
	every entry in revoked {
		hex_string(entry.sha256, 64)
		lower(entry.sha256) != lower(workload.initdata.sha256)
	}
}

# MRSEAM and RTMR[3] have no entries in the current measurements schema.
# This demo leaves them unpinned; add deployment-specific checks if needed.
debug_disabled if bits.and(input.claims.tdattributes[0], 1) == 0

# All measurement comparisons are mandatory. Malformed references never match.
hex_equal(expected, actual) if {
	hex_string(expected, 96)
	hex_string(actual, 96)
	lower(expected) == lower(actual)
}

hex_string(value, length) if {
	is_string(value)
	count(value) == length
	regex.match("^[0-9a-fA-F]+$", value)
}

svn_at_least(minimum, actual) if {
	byte_array(actual, count(minimum))
	every i, minimum_byte in minimum {
		actual[i] >= minimum_byte
	}
}

bytes_within_mask(allowed, actual) if {
	byte_array(actual, count(allowed))
	every i, byte in actual {
		bits.and(byte, bits.xor(allowed[i], 255)) == 0
	}
}

byte_array(value, length) if {
	is_array(value)
	count(value) == length
	every byte in value {
		is_number(byte)
		byte >= 0
		byte <= 255
		floor(byte) == byte
	}
}
