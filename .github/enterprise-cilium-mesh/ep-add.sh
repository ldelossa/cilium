#! /bin/bash -efu

context="$1"
cluster_name="$2"
network="$3"
name="$4"
what="$5"
labels="$6"
service_subnet="$7"
shift 7

#
# create container and install some packets
#
docker run --privileged=true -dti --network "$network" --name "$name" "$what" $@

# Endpoint IP
ip=$(docker container inspect $name |
                jq -r ".[0].NetworkSettings.Networks[\"$network\"].IPAddress")

# Gateway IP
gw_ip=$(docker container inspect "${cluster_name}-control-plane" |
                jq -r ".[0].NetworkSettings.Networks[\"$network\"].IPAddress")

docker exec "$name" apt update
docker exec "$name" apt install curl iproute2 -y
docker exec "$name" ip r a $service_subnet dev eth0 via "$gw_ip"

cilium status --context "$context" --wait --wait-duration 1m

# convert a=b,c=d,e=f,... to yaml
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
