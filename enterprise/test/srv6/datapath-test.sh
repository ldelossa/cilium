#!/usr/bin/env bash
set -eux
PS4='+[\t] '

# This script tests the SRv6 datapath in the following SRv6 VPNv4 setup:
#
#   - cilium node connected to the external node via L2 kind network,
#   - pod on the cilium node communicates via SRv6 VPNv4 with the netns on the external node,
#   - the cilium side is configured using IsovalentVRF + IsovalentSRv6EgressPolicy (see ./manifests/ folder),
#   - the external node is configured using iproute2: netns + veth and SRv6 encap/decap routes.
#
# The datapath functionality is verified using ping in the "cilium node" -> "external node" direction
# and using iperf (TCP + UDP) in both directions.
#
# The test expects a kind k8s cluster with SRv6 enabled and matching the configuration defined in the env vars below.
# The script requires kubectl access to the kind cluster and docker access to the cluster's containers.

#
#  +-------------------------------------+            +-----------------------------------------------+
#  |                         cilium node |            | external node                                 |
#  | +---------------+                   |            |            +-------+      +-----------------+ |
#  | | pod           |  VRF +            |  kind net  |            |  vrf  |      | netns           | |
#  | |               |  SRv6 Policy      +------------+   End.DT4  |    ---+------+---              | |
#  | | 10.244.0.0/16 |  to 10.100.1.0/24 |   (IPv6)   |            |       | veth | 10.100.1.100/24 | |
#  | +---------------+                   |            |            +-------+      +-----------------+ |
#  |                    SID: allocated   |            | SID: fd00:aa:bb::100                          |
#  +-------------------------------------+            +-----------------------------------------------+

srv6_encap_mode="${SRV6_ENCAP_MODE:-srh}"          # "srh" / "reduced"
sid_manager_enabled="${SID_MANGER_ENABLED:-false}" # "true" / "false"

cilium_node_name="kind-worker"
external_node_name="external-node"

kind_network="kind-cilium"
pod_cidr="10.244.0.0/16"
vpn_peer_ip="10.100.1.100"
vpn_peer_gw_ip="10.100.1.1"
vpn_prefix_len="24"
service_vip="10.200.0.0"

external_sid="fd00:aa:bb::100"
sid_wait_seconds="60"

cilium_node_exec="docker exec -t ${cilium_node_name}"
external_node_exec="docker exec -t ${external_node_name}"

#
# ########## TOPOLOGY SETUP ##########
#

# deploy non-k8s node in the kind-cilium network
#
# NOTE: the reason why we don't just use a kind k8s node without cilium here is that the kind node images
# contain old version of iproute2 package, which does not support reduced SRv6 encap mode. This can be consolidated later.
docker run --privileged --rm --network "${kind_network}" --name "${external_node_name}" -d nicolaka/netshoot:v0.11 sleep infinity

${external_node_exec} sysctl -wq net.ipv6.conf.all.disable_ipv6=0
${external_node_exec} sysctl -wq net.ipv6.conf.default.disable_ipv6=0
${external_node_exec} sysctl -wq net.ipv6.conf.all.forwarding=1
${external_node_exec} sysctl -wq net.ipv6.conf.default.forwarding=1

cilium_node_ipv6=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "${cilium_node_name}")
external_node_ipv6=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "${external_node_name}")

#
# ########## CILIUM NODE SRv6 SETUP ##########
#

# route to the VPN peer's SID
${cilium_node_exec} ip -6 route add "${external_sid}/128" via "${external_node_ipv6}"

# deploy test manifests
manifests_dir=$(dirname "$0")/manifests
if [ "${sid_manager_enabled}" = "true" ]; then
  kubectl apply -f "${manifests_dir}/vrf-locator-pool.yaml"
else
  kubectl apply -f "${manifests_dir}/vrf-default-locator.yaml"
fi
kubectl apply -f "${manifests_dir}/srv6-policy.yaml"
kubectl apply -f "${manifests_dir}/service.yaml"
kubectl apply -f "${manifests_dir}/pod.yaml"

# wait for the service to come up
kubectl wait --for=condition=Ready pod/httpbin-vrf1 --timeout=120s

# wait for the netshoot pod to come up
kubectl wait --for=condition=Ready pod/netshoot-vrf1 --timeout=120s

# wait for SID allocation
agent_pod_name=$(kubectl get pod -n kube-system -l app.kubernetes.io/name=cilium-agent --field-selector spec.nodeName="${cilium_node_name}" -o=jsonpath='{.items[0].metadata.name}')
for ((i=1; i <= sid_wait_seconds; i++)); do
  allocated_sid=$(kubectl exec "${agent_pod_name}" -n kube-system -c cilium-agent -- cilium-dbg bpf srv6 sid -o json | jq -r '.[0].SID')
  if [ -z "${allocated_sid}" ] || [ "${allocated_sid}" == "null" ]; then
    if [ "$i" -lt $sid_wait_seconds ]; then
      echo "waiting for SID allocation..."
      sleep 1
    else
      echo "ERROR: SID was not allocated"
      exit 1
    fi
  else
    break
  fi
done

#
# ########## EXTERNAL NODE SRv6 SETUP ##########
#
host_if_name="eth0"
vrf_if_name="vrf1"
vrf_table_id="100"
ns_name="peer1"
veth_if_host_name="veth-peer1"
veth_if_ns_name="veth0"

# route to the cilium-allocated SID
${external_node_exec} ip -6 route add "${allocated_sid}/128" via "${cilium_node_ipv6}"

# VRF
${external_node_exec} ip link add "${vrf_if_name}" type vrf table "${vrf_table_id}"
${external_node_exec} ip link set "${vrf_if_name}" up
${external_node_exec} ip route add table "${vrf_table_id}" unreachable default metric 4278198272
${external_node_exec} sysctl -wq "net.vrf.strict_mode=1"

# netns + veth
${external_node_exec} ip netns add "${ns_name}"
${external_node_exec} ip link add "${veth_if_host_name}" type veth peer name "${veth_if_ns_name}"
${external_node_exec} ip link set "${veth_if_ns_name}" netns "${ns_name}"

# enslave veth to VRF
${external_node_exec} ip link set "${veth_if_host_name}" master "${vrf_if_name}"

# veth - host side
${external_node_exec} ip addr add "${vpn_peer_gw_ip}/${vpn_prefix_len}" dev "${veth_if_host_name}"
${external_node_exec} ip link set "${veth_if_host_name}" up

# veth - peer side
${external_node_exec} ip netns exec "${ns_name}" ip addr add "${vpn_peer_ip}/${vpn_prefix_len}" dev "${veth_if_ns_name}"
${external_node_exec} ip netns exec "${ns_name}" ip link set "${veth_if_ns_name}" up
${external_node_exec} ip netns exec "${ns_name}" ip route add default via "${vpn_peer_gw_ip}"

# disable reverse path filtering
${external_node_exec} sysctl -wq "net.ipv4.conf.all.rp_filter=0"
${external_node_exec} sysctl -wq "net.ipv4.conf.${host_if_name}.rp_filter=0"
${external_node_exec} sysctl -wq "net.ipv4.conf.${veth_if_host_name}.rp_filter=0"
${external_node_exec} sysctl -wq "net.ipv4.conf.${vrf_if_name}.rp_filter=0"

# SRv6 decap
${external_node_exec} ip -6 route add "${external_sid}/128" encap seg6local action End.DT4 vrftable "${vrf_table_id}" dev "${vrf_if_name}"

# SRv6 encap
iproute_encap_mode="encap"
if [ "${srv6_encap_mode}" == "reduced" ]; then
  iproute_encap_mode="encap.red"
fi
${external_node_exec} ip -4 route add "${pod_cidr}" vrf "${vrf_if_name}" encap seg6 mode "${iproute_encap_mode}" segs "${allocated_sid}" dev "${host_if_name}"
${external_node_exec} ip -4 route add "${service_vip}/32" vrf "${vrf_if_name}" encap seg6 mode "${iproute_encap_mode}" segs "${allocated_sid}" dev "${host_if_name}"
${external_node_exec} ip -6 route add "${allocated_sid}/128" vrf "${vrf_if_name}" via "${cilium_node_ipv6}" dev "${host_if_name}"

#
# ########## TEST ##########
#
netshoot_pod_name="netshoot-vrf1"
netshoot_pod_ip=$(kubectl get pod "${netshoot_pod_name}" --template '{{.status.podIP}}')

# ping from the k8s pod to the remote peer
kubectl exec -t "${netshoot_pod_name}" -- ping -c 3 -w 10 -s 1400 "${vpn_peer_ip}"

# curl from external node to the k8s pod
${external_node_exec} ip netns exec "${ns_name}" curl -s -m 10 "http://${service_vip}:80/get"

# helper func used to assert that the json output ($1) is equal to the expected value ($3) at the provided path ($2)
jq_assert_eq () {
  res=$(echo "$1" | jq -r "$2")
  if [ "${res}" != "$3" ]; then
    echo "$2 is not equal $3"
    exit 1
  fi
}

# helper func used to assert that the json output ($1) is lower than / equal to the expected value ($3) at the provided path ($2)
jq_assert_le () {
  res=$(echo "$1" | jq -r "$2")
  if [ "${res}" -gt "$3" ]; then
    echo "$2 is not lower than or equal $3"
    exit 1
  fi
}

# iperf - TCP bidirectional
iperf_output=$(${external_node_exec} ip netns exec "${ns_name}" iperf3 -c "${netshoot_pod_ip}" --bidir --set-mss=1350 --bitrate=1m --time 5 --connect-timeout 1000 --json)
set +x
jq_assert_eq "${iperf_output}" '.error' "null"
jq_assert_le "${iperf_output}" '.end.sum_sent.retransmits' "5"
jq_assert_le "${iperf_output}" '.end.sum_sent_bidir_reverse.retransmits' "5"
set -x

# iperf - UDP bidirectional
iperf_output=$(${external_node_exec} ip netns exec "${ns_name}" iperf3 -c "${netshoot_pod_ip}" --bidir --udp --length=1350 --bitrate=1m --time 5 --connect-timeout 1000 --json)
set +x
jq_assert_eq "${iperf_output}" '.error' "null"
jq_assert_le "${iperf_output}" '.end.sum.lost_packets' "5"
jq_assert_le "${iperf_output}" '.end.sum_bidir_reverse.lost_packets' "5"
set -x

#
# ########## CLEANUP ##########
#
docker stop -t 0 "${external_node_name}"
