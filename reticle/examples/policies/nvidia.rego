# NVIDIA policy, queried as data.nvidia.allow.
# Input: {manifest: PodManifest, claims: DecodedClaims}, where claims contains
# overall_claims and gpu_claims (a map keyed by GPU submodule ID).
# Serde preserves the x-nvidia-* names from types.rs; use bracket access.
# Rust verifies JWT signatures, expiration, submodule digests, measurement
# success, and nonces. The GPU nonce binds to the CPU report; CPU attestation
# and its manifest binding have already passed before this evaluation.
#
# The measurements catalog contains CPU launch and Init-Data references, not
# GPU golden values or an expected GPU inventory. CPU policy must enforce those
# measurements; here require a known workload/release and non-revoked Init-Data,
# then appraise NVIDIA's signed results for every GPU.
package nvidia

import rego.v1

workload := data.measurements.workloads[input.manifest.workload_id]

default allow := false

allow if {
	data.measurements.schema_version == 1
	is_object(workload.releases[input.manifest.podvm_version])
	initdata_not_revoked
	input.claims.overall_claims["x-nvidia-ver"] == "3.0"
	input.claims.overall_claims["x-nvidia-overall-att-result"] == true
	is_object(input.claims.gpu_claims)
	is_object(input.claims.overall_claims.submods)
	count(input.claims.gpu_claims) > 0

	# Reject detached GPUs that are not listed in the signed overall result,
	# as well as listed GPUs that have no detached claims.
	object.keys(input.claims.gpu_claims) == object.keys(input.claims.overall_claims.submods)
	every _, gpu in input.claims.gpu_claims {
		gpu_allowed(gpu)
	}

	# A detached token repeated under different submodule IDs is not another GPU.
	ueids := {gpu.ueid | some gpu in input.claims.gpu_claims}
	count(ueids) == count(input.claims.gpu_claims)
}

# Match CPU policies: revocations apply by Init-Data digest, including aliases.
# Rust omits an empty revoked list. Malformed lists or digests deny access.
initdata_not_revoked if {
	hex_string(workload.initdata.sha256, 64)
	revoked := object.get(data.measurements, "revoked", [])
	is_array(revoked)
	every entry in revoked {
		hex_string(entry.sha256, 64)
		lower(entry.sha256) != lower(workload.initdata.sha256)
	}
}

hex_string(value, length) if {
	is_string(value)
	count(value) == length
	regex.match("^[0-9a-fA-F]+$", value)
}

gpu_allowed(gpu) if {
	is_object(gpu)
	is_string(gpu.ueid)
	count(trim_space(gpu.ueid)) > 0
	gpu.measres == "success"

	# Optional in the Rust type, mandatory for this policy: missing claims deny.
	gpu.secboot == true
	gpu.dbgstat == "disabled"
	object.get(gpu, "x-nvidia-attestation-warning", null) == null
	object.get(gpu, "x-nvidia-mismatch-measurement-records", []) == []
	gpu["x-nvidia-gpu-arch-check"] == true
	cert_chain_allowed(gpu["x-nvidia-gpu-attestation-report-cert-chain"])
	gpu["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] == true
	gpu["x-nvidia-gpu-attestation-report-parsed"] == true
	gpu["x-nvidia-gpu-attestation-report-nonce-match"] == true
	gpu["x-nvidia-gpu-attestation-report-signature-verified"] == true
	gpu["x-nvidia-gpu-driver-rim-fetched"] == true
	gpu["x-nvidia-gpu-driver-rim-schema-validated"] == true
	cert_chain_allowed(gpu["x-nvidia-gpu-driver-rim-cert-chain"])
	gpu["x-nvidia-gpu-driver-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-driver-rim-version-match"] == true
	gpu["x-nvidia-gpu-driver-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-vbios-rim-fetched"] == true
	gpu["x-nvidia-gpu-vbios-rim-schema-validated"] == true
	cert_chain_allowed(gpu["x-nvidia-gpu-vbios-rim-cert-chain"])
	gpu["x-nvidia-gpu-vbios-rim-version-match"] == true
	gpu["x-nvidia-gpu-vbios-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-vbios-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-vbios-index-no-conflict"] == true
}

# These nested objects survive Rust deserialization without field validation.
# Require affirmative certificate and revocation status for all three chains.
cert_chain_allowed(chain) if {
	is_object(chain)
	chain["x-nvidia-cert-status"] == "valid"
	chain["x-nvidia-cert-ocsp-status"] == "good"
	object.get(chain, "x-nvidia-cert-revocation-reason", null) == null

	# Older 3.0 responses omit these OCSP details; if present, require success.
	object.get(chain, "x-nvidia-cert-ocsp-nonce-matches", true) == true
	object.get(chain, "x-nvidia-cert-ocsp-response-valid", true) == true
}

# This accepts any catalog workload/release and NVIDIA-appraised GPU model,
# driver, and VBIOS. Add deployment-specific allowlists and expected GPU IDs or
# counts if needed. GPU absence bypasses this policy in Client::attest; callers
# requiring GPUs must also require the NVIDIA module in the attestation result.
# Catalog revocations use the snapshot fetched at ClientBuilder::build, and
# certificate status is NVIDIA's signed appraisal, not a fresh OCSP query here.
