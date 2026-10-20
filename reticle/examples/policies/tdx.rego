# Demo TDX policy, queried as data.tdx.allow.
# Client::attest_quote supplies {manifest: PodManifest, claims: TdxQuoteBody}
# after Rust verifies the quote and its manifest-bound nonce. Hardware fields
# live under input.claims; the `seamsttributes` spelling matches the Rust type.
#
# ClientBuilder loads https://trustbase.prem.io/measurements.json into
# data.measurements. Require the named workload/release and its TDX
# measurements; missing references deny access.
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
	input.manifest.tee_type == "Tdx"
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
	count(input.claims.rtmr) == 4
	hex_equal(reference.rtmr_0, input.claims.rtmr[0])
	hex_equal(reference.rtmr_1, input.claims.rtmr[1])
	hex_equal(reference.rtmr_2, input.claims.rtmr[2])
	# Bind the selected workload's init-data to the measured configuration.
	hex_equal(workload.initdata.mr_config_id, input.claims.mrconfigid)
}

# MRSEAM and RTMR[3] have no entries in the current measurements schema.
# This demo leaves them unpinned; add deployment-specific checks if needed.
debug_disabled if bits.and(input.claims.tdattributes[0], 1) == 0

# All measurement comparisons are mandatory. Empty references never match.
hex_equal(expected, actual) if {
	count(expected) == 96
	lower(expected) == lower(actual)
}

svn_at_least(minimum, actual) if {
	count(actual) == count(minimum)
	every i, floor in minimum {
		actual[i] >= floor
	}
}

bytes_within_mask(allowed, actual) if {
	count(actual) == count(allowed)
	every i, byte in actual {
		bits.and(byte, bits.xor(allowed[i], 255)) == 0
	}
}
