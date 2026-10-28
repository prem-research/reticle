# SEV-SNP policy, queried as data.sev.allow.
# Reticle supplies {manifest: PodManifest, claims: SevClaims} after verifying
# the SEV quote, certificate chain, and manifest-bound nonce. PodManifest
# contains workload_id and podvm_version; it has no tee_type field.
#
# ClientBuilder loads https://trustbase.prem.io/measurements.json into
# data.measurements. Require both the launch measurement for the selected
# workload/release and the same workload's non-revoked Init-Data host_data.
package sev

import rego.v1

workload := data.measurements.workloads[input.manifest.workload_id]
reference := workload.releases[input.manifest.podvm_version].snp

default allow := false

allow if {
	data.measurements.schema_version == 1
	initdata_not_revoked
	input.claims.vmpl == 1
	input.claims.policy.debug_allowed == false
	input.claims.policy.migrate_ma_allowed == false
	hex_equal(workload.initdata.host_data, input.claims.host_data, 64)
	measurement_matches
}

# SNP references are keyed by virtual CPU model. SevClaims does not expose
# that model, so accept any listed measurement for this workload/release.
measurement_matches if {
	is_object(reference)
	some model, expected in reference
	hex_equal(expected, input.claims.measurement, 96)
}

# Revocations identify Init-Data by digest, even if registered under another ID.
# Rust omits an empty revoked list when serializing the catalog into Rego.
# Reject malformed lists or digests instead of silently skipping entries.
initdata_not_revoked if {
	hex_string(workload.initdata.sha256, 64)
	revoked := object.get(data.measurements, "revoked", [])
	is_array(revoked)
	every entry in revoked {
		hex_string(entry.sha256, 64)
		lower(entry.sha256) != lower(workload.initdata.sha256)
	}
}

# Require complete hexadecimal values; absent or malformed values never match.
hex_equal(expected, actual, length) if {
	hex_string(expected, length)
	hex_string(actual, length)
	lower(expected) == lower(actual)
}

hex_string(value, length) if {
	is_string(value)
	count(value) == length
	regex.match("^[0-9a-fA-F]+$", value)
}

# This example accepts any matching catalog workload/release. Add an explicit
# workload/version allowlist and reported_tcb/current_tcb floors if required
# by your deployment; this policy imposes no TCB floor.
# Catalog revocations apply to the snapshot fetched at ClientBuilder::build;
# this policy cannot enforce catalog freshness or AMD certificate revocation.
