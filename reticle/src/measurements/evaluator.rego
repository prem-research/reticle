package reticle

import rego.v1

policy := data.agent_policy.policy_data

vfio := [device |
	some container in policy.containers
	some device in object.get(container, "devices", [])
	device.container_path == policy.devices.vfio.device_path
]

cdi := {trim_space(gpu) |
	some container in policy.containers
	some gpu in split(object.get(container.OCI.Annotations, "cdi.k8s.io/gpu", ""), ",")
	trim_space(gpu) != ""
}

gpus := count(vfio) if {
	is_array(policy.containers)
	count(vfio) == count(cdi)
}
