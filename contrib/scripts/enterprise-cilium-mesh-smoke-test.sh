#! /bin/bash -efux

service_ip() {
	local name="$1"
	local context="${2:-kind-cluster1}"
	kubectl --context "$context" get svc "$name" -o json | jq -r '.spec.clusterIP'
}

die() {
	echo "$@" >&2
	exit 1
}

# A simple cilium mesh service pointing to run=nginx endpoints
svc_config() {
	local name="$1"
	cat <<EOF
apiVersion: v1
kind: Service
metadata:
  name: $name
  annotations:
    io.cilium/global-service: "true"
    com.isovalent/cilium-mesh: "true"
  labels:
    test: "smoke-test"
spec:
  type: ClusterIP
  ports:
  - port: 80
  selector:
    run: $name
EOF
}

# ingress policy for GW2: allow ingress from app=client
ingress_policy_config() {
	cat <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-nginx
  namespace: default
  labels:
    test: "smoke-test"
spec:
  podSelector:
    matchLabels:
      run: nginx
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: client
      ports:
        - port: 80
EOF
}

# egress policy for GW1: allow egress to run=nginx
egress_policy_config() {
	cat <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-forbidden-fruit
  labels:
    test: "smoke-test"
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              run: nginx
      ports:
        - port: 80
EOF
}

#
# Check that versions are ok
#
cilium_cli_ver=$(cilium version | head -1 | cut -f2 -d.)
[ -n "$cilium_cli_ver" -a "$cilium_cli_ver" -ge "15" ] ||
	die "cilium-cli version should be >= v0.15"

# We only want to cleanup everything
if [ -n "${1:-}" -a "${1:-}" = "cleanup" ]; then

	for context in kind-cluster1 kind-cluster2; do
		kubectl --context "$context" delete netpol -l test=smoke-test
		kubectl --context "$context" delete svc -l test=smoke-test
		kubectl --context "$context" delete ime -l test=smoke-test
	done

	# delete containers by hands, sync with ep-add
	docker rm -f client
	docker rm -f clientbad
	docker rm -f server1
	docker rm -f server2
	docker rm -f forbidden-fruit

	exit 0
fi

#
# good client, allowed to reach nginx
#
contrib/scripts/enterprise-kind-cilium-mesh.sh ep-add 1 client ubuntu app=client,test=smoke-test

#
# bad client, not allowed to reach nginx
#
contrib/scripts/enterprise-kind-cilium-mesh.sh ep-add 1 clientbad ubuntu app=clientbad,test=smoke-test

#
# nginx backends and services
#
contrib/scripts/enterprise-kind-cilium-mesh.sh ep-add 2 server1 nginx run=nginx,test=smoke-test
contrib/scripts/enterprise-kind-cilium-mesh.sh ep-add 2 server2 nginx run=nginx,test=smoke-test
svc_config nginx | kubectl --context kind-cluster1 apply -f -
svc_config nginx | kubectl --context kind-cluster2 apply -f -

#
# A forbidden service, clients aren't allowed to reach it (egress policy)
#
contrib/scripts/enterprise-kind-cilium-mesh.sh ep-add 2 forbidden-fruit nginx run=forbidden-fruit,test=smoke-test
svc_config forbidden-fruit | kubectl --context kind-cluster1 apply -f -
svc_config forbidden-fruit | kubectl --context kind-cluster2 apply -f -

# Network policies:
#   * allow client -> nginx
#   * deny bad_client -> nginx [ingress at gw2]
#   * deny * -> forbidden-fruit [egress at gw1]

egress_policy_config  | kubectl --context kind-cluster1 apply -f -
ingress_policy_config | kubectl --context kind-cluster2 apply -f -

#
# Finally test that everything works as expected
#

nginx_cluster_ip=$(service_ip nginx)
ff_cluster_ip=$(service_ip forbidden-fruit)

client_ep_id=$(kubectl -n kube-system --context kind-cluster1 exec ds/cilium -it -- cilium endpoint list -o json |
	tr -d '\n' | jq '.[].status.identity | select(.labels[] == "k8s:app=client") | .id' )
clientbad_ep_id=$(kubectl -n kube-system --context kind-cluster1 exec ds/cilium -it -- cilium endpoint list -o json |
	tr -d '\n' | jq '.[].status.identity | select(.labels[] == "k8s:app=clientbad") | .id' )
server_1_id=$(kubectl -n kube-system --context kind-cluster2 exec ds/cilium -it -- cilium endpoint list -o json |
	tr -d '\n' | jq '.[].status.identity | select(.labels[] == "k8s:name=server1") | .id' )
server_2_id=$(kubectl -n kube-system --context kind-cluster2 exec ds/cilium -it -- cilium endpoint list -o json |
	tr -d '\n' | jq '.[].status.identity | select(.labels[] == "k8s:name=server2") | .id' )
forbidden_fruit_id=$(kubectl -n kube-system --context kind-cluster2 exec ds/cilium -it -- cilium endpoint list -o json |
	tr -d '\n' | jq '.[].status.identity | select(.labels[] == "k8s:name=forbidden-fruit") | .id' )

docker exec -ti client curl -s --connect-timeout 2.718 ${nginx_cluster_ip} -o /dev/null ||
	die "client should have been able to connect to nginx=${nginx_cluster_ip}"
kubectl --namespace kube-system --context kind-cluster1 -c cilium-agent exec ds/cilium -it -- \
	hubble observe --color never -t policy-verdict --from-identity ${client_ep_id} --to-identity ${server_1_id} --to-identity ${server_2_id} --last 1 | grep "EGRESS ALLOWED" ||
	die "no allowed egress policy verdict in hubble flows"
kubectl --namespace kube-system --context kind-cluster2 -c cilium-agent exec ds/cilium -it -- \
	hubble observe --color never -t policy-verdict --from-identity ${client_ep_id} --to-identity ${server_1_id} --to-identity ${server_2_id} --last 1 | grep "INGRESS ALLOWED" ||
	die "no allowed ingress policy verdict in hubble flows"

docker exec -ti clientbad curl --connect-timeout 3.145 ${nginx_cluster_ip} &&
	die "clientbad should not have been able to connect to nginx=${nginx_cluster_ip}"
kubectl --namespace kube-system --context kind-cluster2 -c cilium-agent exec ds/cilium -it -- \
	hubble observe --color never -t policy-verdict --from-identity ${clientbad_ep_id} --to-identity ${server_1_id} --to-identity ${server_2_id} --last 1 | grep "INGRESS DENIED" ||
	die "no denied ingress policy verdict in hubble flows"

docker exec -ti client     curl --connect-timeout 1.414 ${ff_cluster_ip}    &&
	die "client should not have been able to connect to forbidden-fruit=${ff_cluster_ip}"
kubectl --namespace kube-system --context kind-cluster1 -c cilium-agent exec ds/cilium -it -- \
	hubble observe --color never -t policy-verdict --from-identity ${client_ep_id} --to-identity ${forbidden_fruit_id} --last 1 | grep "EGRESS DENIED" ||
	die "no denied egress policy verdict in hubble flows"

docker exec -ti clientbad curl --connect-timeout 1.618 ${ff_cluster_ip}    &&
	die "clientbad should not have been able to connect to forbidden-fruit=${ff_cluster_ip}"
kubectl --namespace kube-system --context kind-cluster1 -c cilium-agent exec ds/cilium -it -- \
	hubble observe --color never -t policy-verdict --from-identity ${clientbad_ep_id} --to-identity ${forbidden_fruit_id} --last 1 | grep "EGRESS DENIED" ||
	die "no denied egress policy verdict in hubble flows"

exit 0
