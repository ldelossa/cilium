#! /bin/bash -efux

cilium_gw1="cluster1"
cilium_gw2="cluster2"

k8s_node_2_docker() {
	local cluster_id="$1"
	echo "cluster$1-control-plane"
}

service_subnet="192.168.0.0/24"

kind_config() {
	local CLUSTER_NAME="$1"

	cat <<EOF
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
name: ${CLUSTER_NAME}
nodes:
  - role: control-plane
networking:
  disableDefaultCNI: true
  ipFamily: ipv4
  podSubnet: 10.0.0.0/16
  kubeProxyMode: none
  serviceSubnet: ${service_subnet}
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:5000"]
      endpoint = ["http://kind-registry:5000"]
EOF
}

cluster_config() {
	local CLUSTER_NAME="$1"
	local CLUSTER_ID="$2"
	cat <<EOF
EOF
}

load_images() {
	local cluster_name="$1"

	kind load docker-image ${LOCAL_CLUSTERMESH_IMAGE} --name ${cluster_name}
	kind load docker-image ${LOCAL_AGENT_IMAGE} --name ${cluster_name}
	kind load docker-image ${LOCAL_OPERATOR_IMAGE} --name ${cluster_name}
	kind load docker-image ${LOCAL_HUBBLE_RELAY_IMAGE} --name ${cluster_name}
}

install_cluster() {
	local cluster_name="$1"
	local cluster_id="$2"
	local node_port="$3"

	local chart_directory="${ROOT_DIR}/install/kubernetes/cilium"

	local gw_ip=$(kubectl --context "kind-${cluster_name}" get nodes -o json |
			jq -r '.items[] | .status .addresses[] | select(.type=="InternalIP") | .address')

	cluster_config "${cluster_name}" "${cluster_id}" |
		${CILIUM_CLI} install \
			--helm-set=cluster.id="${cluster_id}" \
			--helm-set=cluster.name="${cluster_name}" \
			--context "kind-${cluster_name}" \
			--helm-set=debug.enabled=true \
			--helm-set=ipv4.enabled=true \
			--helm-set=ipv6.enabled=false \
			--helm-set=kubeProxyReplacement=true \
			--helm-set=image.repository=${DOCKER_REGISTRY}/${DOCKER_DEV_ACCOUNT}/cilium-dev \
			--helm-set=image.useDigest=false \
			--helm-set=image.tag=${LOCAL_IMAGE_TAG} \
			--helm-set=image.pullPolicy=Never \
			--helm-set=operator.image.repository=${DOCKER_REGISTRY}/${DOCKER_DEV_ACCOUNT}/operator \
			--helm-set=operator.image.suffix="" \
			--helm-set=operator.image.tag=${LOCAL_IMAGE_TAG} \
			--helm-set=operator.image.useDigest=false \
			--helm-set=operator.image.pullPolicy=Never \
			--helm-set=ipam.mode=kubernetes \
			--helm-set=bpf.masquerade=true \
			--helm-set=bpf.monitorAggregation=none \
			--helm-set=bpf.lbExternalClusterIP=true \
			--helm-set=socketLB.enabled=true \
			--helm-set=endpointHealthChecking.enabled=false \
			--helm-set=socketLB.hostNamespaceOnly=true \
			--helm-set=devices=eth+ \
			--helm-set=hubble.enabled=true \
			--helm-set=hubble.relay.enabled=true \
			--helm-set=hubble.relay.image.override=${DOCKER_REGISTRY}/${DOCKER_DEV_ACCOUNT}/hubble-relay:${LOCAL_IMAGE_TAG} \
			--helm-set=hubble.relay.image.useDigest=false \
			--helm-set=hubble.relay.image.pullPolicy=Never \
			--helm-set=clustermesh.useAPIServer=true \
			--helm-set=clustermesh.apiserver.kvstoremesh.enabled=false \
			--helm-set=clustermesh.apiserver.image.override=${DOCKER_REGISTRY}/${DOCKER_DEV_ACCOUNT}/clustermesh-apiserver:${LOCAL_IMAGE_TAG} \
			--helm-set=clustermesh.apiserver.image.useDigest=false \
			--helm-set=clustermesh.apiserver.image.pullPolicy=Never \
			--helm-set=clustermesh.config.enabled=true \
			--helm-set=clustermesh.config.enableClusterAwareAddressing=true \
			--helm-set=clustermesh.config.hasOverlappingPodCIDR=true \
			--helm-set enterprise.clustermesh.enableOverlappingPodCIDRSupport=true \
			--helm-set=enterprise.ciliummesh.enabled=true \
			--helm-set=tunnel=vxlan \
			--helm-set=autoDirectNodeRoutes=false \
			--helm-set=k8s.requireIPv4PodCIDR=true \
			--helm-set=k8s.requireIPv6PodCIDR=false \
			--chart-directory ${chart_directory} \
			--helm-set clustermesh.apiserver.service.nodePort=$node_port \
			--helm-set clustermesh.apiserver.tls.authMode=legacy \
			--wait \
			#

	${CILIUM_CLI} clustermesh status \
			--context "kind-${cluster_name}" \
			--wait \
			#
}

attach_to_docker_network() {

	local network="$1"
	local container="$2"

	docker network create "$network"
	docker network connect "$network" "$container"
}

format_cluster_id() {
	local cluster_id="$1"
	printf '%d' "$cluster_id"
}

add_endpoint() {
	local cluster_id="$(format_cluster_id "$1")"
	local name="$2"
	local what="$3"
	local labels="$4"
	shift 4

	# local network="cilium-mesh-net-$cluster_id"
	local network="kind"

	#
	# create container and install some packets
	#
	local container_id=$(docker ps -q -f name=$name)
	if [ -z "$container_id" ]; then
		docker run --privileged=true -dti --network "$network" --name "$name" "$what" $@
		local ip=$(docker container inspect $name |
				jq -r ".[0].NetworkSettings.Networks[\"$network\"].IPAddress")
		local gw_ip=$(docker container inspect $(k8s_node_2_docker "$cluster_id") |
				jq -r ".[0].NetworkSettings.Networks[\"$network\"].IPAddress")

		docker exec -ti "$name" apt update
		docker exec -ti "$name" apt install curl iproute2 -y
		docker exec -ti "$name" ip r a $service_subnet dev eth0 via "$gw_ip"
	fi

	local context="kind-cluster$cluster_id"
	local ip=$(docker container inspect $name |
			jq -r ".[0].NetworkSettings.Networks[\"$network\"].IPAddress")

	cilium status --context "$context" --wait --wait-duration 1m

	labels=$(for label in ${labels//,/ }; do echo "    ${label//=/: }"; done)

	kubectl --context $context apply -f - <<EOF
apiVersion: "isovalent.com/v1alpha1"
kind: IsovalentMeshEndpoint
metadata:
  name: "$name"
  namespace: "default"
  labels:
$labels
    name: "$name"
spec:
  ip: "$ip"
EOF
}

# disconnect all clients, stop and remove them, remove network
full_network_down() {
	local network="$1"

	for container in $(docker network inspect "$network" |
			jq -r '.[0].Containers | .[] | .Name'); do
		docker stop "$container"
		docker rm "$container"
	done

	docker network rm "$network"
}

# Start the registry at localhost:5000
kind_registry() {
	local reg_name="kind-registry"
	local reg_port="5000"

	local running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
	if [[ "${running}" != "true" ]]; then
		local retry_count=0
		while ! docker pull registry:2; do
			retry_count=$((retry_count+1))
			if [[ "$retry_count" -ge 10 ]]; then
				die "ERROR: 'docker pull registry:2' failed $retry_count times. Please make sure docker is running"
			fi
			echo "docker pull registry:2 failed. Sleeping for 1 second and trying again..."
			sleep 1
		done
		docker run \
			-d --restart=always \
			-p "$reg_port:5000" \
			--name "$reg_name" \
			registry:2
	fi
}

case ${1:-} in
	up)
		kind_registry

		kind_config "${cilium_gw1}" | kind create cluster --config=-
		kind_config "${cilium_gw2}" | kind create cluster --config=-
		;;
	down)
		kind delete cluster --name "${cilium_gw1}"
		kind delete cluster --name "${cilium_gw2}"

		full_network_down kind
		;;
	check)
		kind get clusters 2>&1 | fgrep -w "${cilium_gw1}"
		kind get clusters 2>&1 | fgrep -w "${cilium_gw2}"
		;;
	load-images)
		docker images | awk '/^localhost.*cilium-mesh/ {print $1}' | xargs -I'{}' docker push '{}':cilium-mesh
		load_images "$cilium_gw1"
		load_images "$cilium_gw2"
		;;
	install)
		install_cluster "${cilium_gw1}" 1 32379
		kubectl --context kind-"${cilium_gw1}" get secret -n kube-system cilium-ca -o yaml |
			kubectl --context kind-"${cilium_gw2}" create -f -
		install_cluster "${cilium_gw2}" 2 32380

		cilium --context kind-"${cilium_gw1}" status --wait
		cilium --context kind-"${cilium_gw2}" status --wait
		cilium --context kind-"${cilium_gw1}" clustermesh status --wait
		cilium --context kind-"${cilium_gw2}" clustermesh status --wait

		${CILIUM_CLI} clustermesh connect \
			--context "kind-${cilium_gw1}" \
			--destination-context "kind-${cilium_gw2}" \
			#

		cilium --context kind-"${cilium_gw1}" status --wait
		cilium --context kind-"${cilium_gw2}" status --wait
		cilium --context kind-"${cilium_gw1}" clustermesh status --wait
		cilium --context kind-"${cilium_gw2}" clustermesh status --wait
		;;
	ep-add|endpoint-add)
		shift
		add_endpoint "$@"
		;;
	ep-del|endpoint-del)
		name="$2"
		docker stop "$name"
		docker rm "$name"
		;;
	ep-ls|endpoint-ls)
		id="$2"
		docker network inspect "cilium-mesh-net-$(format_cluster_id $id)" |
			jq '.[0].Containers | .[] | .Name + " " + .IPv4Address'
		;;
	*)
		echo "unknown or empty command '${1:-}'" >&2
		exit 1
		;;
esac
