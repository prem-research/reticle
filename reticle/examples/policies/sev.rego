# Demo SEV-SNP policy, queried as data.sev.allow.
# Input: {manifest: PodManifest, claims: SevClaims}. Rust verifies the quote,
# certificate chain, and manifest-bound nonce before this policy runs.
#
# Golden values come from data.measurements.workloads[workload_id].releases
# [podvm_version].snp, a map of vCPU model names to launch measurement hex.
# SevClaims does not expose a vCPU model, so this demo accepts any configured
# model for that workload/release. The manifest's generation is not a model.
#
# Check the quote's host_data against the selected workload's init-data as
# well as its launch measurement. Both reference values come from
# https://trustbase.prem.io/measurements.json.
package sev

import rego.v1

workload := data.measurements.workloads[input.manifest.workload_id]
reference := workload.releases[input.manifest.podvm_version].snp

default allow := false

allow if {
	# Serde encodes Tee::Sev(generation) as {"Sev": "Milan"}, for example.
	input.manifest.tee_type.Sev in {"Naples", "Rome", "Milan", "Genoa", "Turin", "Venice"}
	input.manifest.tee_type.Sev in {"Naples", "Rome", "Milan", "Genoa", "Turin", "Venice"}
	input.claims.vmpl == 0
	input.claims.policy.debug_allowed == false
	input.claims.policy.migrate_ma_allowed == false
	count(workload.initdata.host_data) == 64
	lower(input.claims.host_data) == lower(workload.initdata.host_data)
	measurement_matches
}

measurement_matches if {
	is_object(reference)
	some model, expected in reference
	count(expected) == 96
	lower(input.claims.measurement) == lower(expected)
}

# Add deployment-specific TCB floors using claims.reported_tcb/current_tcb,
# and any required guest-policy flags. This demo does not impose a TCB floor
# or restrict the catalog to a particular caller-expected workload/version.
