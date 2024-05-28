#!/usr/bin/env bash

set -eu -o pipefail

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
