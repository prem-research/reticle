# Demo NVIDIA policy, queried as data.nvidia.allow.
# Input: {manifest: PodManifest, claims: DecodedClaims}, where claims contains
# overall_claims and gpu_claims (a map keyed by GPU submodule ID).
# Serde preserves the x-nvidia-* names from types.rs; use bracket access.
# Rust verifies JWT signatures, expiration, submodule digests, measurement
# success, and nonces. The GPU nonce binds to the CPU report; CPU attestation
# and its manifest binding have already passed before this evaluation.
#
# There are no GPU golden values in the current measurements schema. Require
# a known workload/release, then appraise NVIDIA's signed results for every
# GPU. Add model/driver/VBIOS allowlists for deployment-specific restrictions.
package nvidia

import rego.v1

default allow := false

allow if {
	is_object(data.measurements.workloads[input.manifest.workload_id].releases[input.manifest.podvm_version])
	input.claims.overall_claims["x-nvidia-overall-att-result"] == true
	count(input.claims.gpu_claims) > 0
	# Reject detached GPUs that are not listed in the signed overall result,
	# as well as listed GPUs that have no detached claims.
	object.keys(input.claims.gpu_claims) == object.keys(input.claims.overall_claims.submods)
	every id, gpu in input.claims.gpu_claims {
		gpu_allowed(gpu)
	}
}

gpu_allowed(gpu) if {
	gpu.measres == "success"
	gpu["x-nvidia-gpu-arch-check"] == true
	gpu["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"] == true
	gpu["x-nvidia-gpu-attestation-report-parsed"] == true
	gpu["x-nvidia-gpu-attestation-report-nonce-match"] == true
	gpu["x-nvidia-gpu-attestation-report-signature-verified"] == true
	gpu["x-nvidia-gpu-driver-rim-fetched"] == true
	gpu["x-nvidia-gpu-driver-rim-schema-validated"] == true
	gpu["x-nvidia-gpu-driver-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-driver-rim-version-match"] == true
	gpu["x-nvidia-gpu-driver-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-vbios-rim-fetched"] == true
	gpu["x-nvidia-gpu-vbios-rim-schema-validated"] == true
	gpu["x-nvidia-gpu-vbios-rim-version-match"] == true
	gpu["x-nvidia-gpu-vbios-rim-signature-verified"] == true
	gpu["x-nvidia-gpu-vbios-rim-measurements-available"] == true
	gpu["x-nvidia-gpu-vbios-index-no-conflict"] == true
}

# secboot and dbgstat are optional in GpuClaims. This demo relies on NVIDIA's
# appraisal above; add explicit requirements if your deployment supplies them.
