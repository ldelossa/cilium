#!/usr/bin/env bash

set -e # Exit if any command has a non-zero exit status.
set -u # Exit in error if there is a reference to a non previously defined variable.
set -o pipefail # Exit if any command in a pipeline fails, that return code will be used as the return code of the whole pipeline.

function check_bash_version() {
    if [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
        echo -e "\033[31mERROR: You should use a version of bash >= 5.x.x\033[0m"
        exit 1
    fi
}

function deploy_cilium() {
    helm upgrade --install cilium-enterprise isovalent/cilium --version "${1}" --namespace kube-system \
    -f ./compat/cilium-enterprise-values.yaml --wait
}

function deploy_dnsproxy() {
    helm upgrade --install cilium-dnsproxy isovalent/cilium-dnsproxy --version "${1}" --namespace kube-system --wait
}

function apply_policy() {
    kubectl apply -f ./compat/fqdn-policy-egress.yaml
}

function remove_policy() {
    kubectl delete -n cilium-test-1 ciliumnetworkpolicy/client-egress-to-fqdns-cilium-io
}

function cilium_conn_test() {
    cmd_ec=0
    cilium connectivity test --namespace kube-system --test to-fqdn --external-target google.com || cmd_ec=$?
}

function test_dns() {
    cmd_ec=0
    kubectl exec -n cilium-test-1 deploy/client -- nslookup cilium.io || cmd_ec=$?
    kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 cilium.io || cmd_ec=$?
    kubectl exec -n cilium-test-1 deploy/client -- nslookup google.com || cmd_ec=$?
}

function test_curl() {
    cmd_ec=0
    kubectl exec -n cilium-test-1 deploy/client -- curl --max-time 10 google.com || cmd_ec=$?
}

function delete_tests() {
    kubectl delete ns cilium-test-1
}

function bring_cilium_down() {
    # Retrieve the number of cilium instances available.
    nb_cilium_instances_ok=$(kubectl -n kube-system get ds/cilium -o jsonpath='{.status.numberAvailable}')
    echo "Number of Cilium instances available: ${nb_cilium_instances_ok}"

    # Change the image of cilium for an invalid one to bring Cilium down.
    kubectl -n kube-system set image ds/cilium cilium-agent=cilium-cee/no-such-image-lol/
    sleep 2
    # The rollout for a broken daemonset is mandatory, otherwise it will stop in the middle.
    kubectl rollout restart daemonset cilium -n kube-system
    sleep 2

    TIMEOUT_SEC=180
    start_time="$(date -u +%s)"

    while :
    do
        # Timeout in case the status never changed.
        current_time="$(date -u +%s)"
        elapsed_seconds=$((current_time-start_time))
        if [ $elapsed_seconds -gt $TIMEOUT_SEC ]; then
            echo -e "\033[31mTimeout of $TIMEOUT_SEC sec\033[0m"
            exit 1
        fi

        # Retrieve the number of generation.
        nb_generation=$(kubectl -n kube-system get ds/cilium -o jsonpath='{.metadata.generation}')
        echo "Number of Cilium generation after bringing Cilium down: ${nb_generation}"

        # Retrieve the number of observed generation which should be equal to the number of generation when Cilium instances are updated.
        nb_observed_generation=$(kubectl -n kube-system get ds/cilium -o jsonpath='{.status.observedGeneration}')
        echo "Number of Cilium observed generation after bringing Cilium down: ${nb_observed_generation}"
        if [[ "${nb_generation}" != "${nb_observed_generation}" ]]; then
            echo "Number of Cilium generation is not equal to observed generation: generation ${nb_generation}, observed generation ${nb_observed_generation}"
            sleep 3 # Wait a bit before retrying
            continue
        fi

        # Retrieve the number of cilium instances now unavailable after bringing Cilium down.
        nb_cilium_instances_nok=$(kubectl -n kube-system get ds/cilium -o jsonpath='{.status.numberUnavailable}')
        echo "Number of Cilium instances unavailable: ${nb_cilium_instances_nok}"
        # Check if all the cilium instances are now down.
        if [[ "${nb_cilium_instances_nok}" != "${nb_cilium_instances_ok}" ]]; then
            echo "Cilium is not fully down, expected ${nb_cilium_instances_ok}, got ${nb_cilium_instances_nok}"
            sleep 3 # Wait a bit before retrying
        else
            echo "Cilium is fully down, got $nb_cilium_instances_nok instances unavailable"
            break
        fi
    done
}

function uninstall_everything() {
    helm uninstall cilium-dnsproxy cilium-enterprise --namespace kube-system --wait
}

function assert_success() {
    if [[ "${cmd_ec}" != "0" ]]; then
        echo -e "\033[31m${1} failed\033[0m"
        ec=2
        it_ec=2
    else
        echo -e "\033[32m${1} succeeded\033[0m"
        return 0
    fi
}

function assert_failure() {
    if [[ "${cmd_ec}" == "0" ]]; then
        echo -e "\033[31m${1} succeeded when it should have failed\033[0m"
        ec=2
        it_ec=2
    else
        echo -e "\033[32m${1} should fail and it did\033[0m"
        return 0
    fi
}


function run_tests() {
    cilium_conn_test
    assert_success "cilium connectivity tests"
    test_curl
    assert_success "curling google.com"
    test_dns
    assert_success "testing dns"
    apply_policy
    test_curl
    assert_failure "curling google.com"
    bring_cilium_down
    test_dns
    assert_success "testing dns with cilium down"
    test_curl
    assert_failure "curling google.com with cilium down"
    remove_policy
}

check_bash_version

fqdn_v="$1"
#shellcheck disable=SC2206
fqdn_versions=(${fqdn_v//;/ })
cilium_v="$2"
#shellcheck disable=SC2206
cilium_versions=(${cilium_v//;/ })


# Exit code is the global return code.
ec=0
# Iteration exit code is the return code of the current iteration.
it_ec=0
# Command exit code is the return code of the last command within the current iteration.
cmd_ec=0
mismatch_versions=()

kind create cluster --config=./compat/kind-config.yaml
fv="${fqdn_versions[-1]}"
for cv in "${cilium_versions[@]}"; do
    deploy_cilium "v${cv}"
    cilium status --wait --namespace kube-system
    echo "Running cilium version ${cv} with fqdn-proxy version ${fv}..."
    it_ec=0
    deploy_dnsproxy "v${fv}"
    run_tests
    if [[ "${it_ec}" != 0 ]]; then
        mismatch_versions+=("fqdn_proxy ${fv} with upgrade to cilium ${cv}")
        echo -e "\033[31mFQDN-Proxy v${fv} is incompatible with upgrade to Cilium v${cv}\033[0m"
    fi
done
kind delete cluster

kind create cluster --config=./compat/kind-config.yaml
cv="${cilium_versions[-1]}"
for fv in "${fqdn_versions[@]}"; do
    deploy_cilium "v${cv}"
    cilium status --wait --namespace kube-system
    echo "Running cilium version ${cv} with fqdn-proxy version ${fv}..."
    it_ec=0
    deploy_dnsproxy "v${fv}"
    run_tests
    if [[ "${it_ec}" != 0 ]]; then
        mismatch_versions+=("cilium ${cv} with upgrade to fqdn_proxy ${fv}")
        echo -e "\033[31mCilium v${cv} is incompatible with upgrade to FQDN-Proxy v${fv}\033[0m"
    fi
done
kind delete cluster

if [[ "${ec}" != 0 ]]; then
    echo -e "\033[31mNot all tests passed\033[0m"
    echo -e "The following fqdn-proxy and cilium versions have negative interactions:"
    for mv in "${mismatch_versions[@]}"; do
        echo "    ${mv}"
    done
    exit ${ec}
fi
