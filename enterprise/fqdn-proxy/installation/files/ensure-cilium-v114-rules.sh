#!/bin/sh
# Cilium v1.13 and v1.14 use different TPROXY rules. This script ensures
# the system is running with the Cilium v1.14 rule, which ensures
# cilium-dnsproxy v1.14 can be used with cilium-agent v1.13
if [ "$CILIUM_ENABLE_IPV4" != "true" ] && [ "$CILIUM_ENABLE_IPV6" != "true" ]; then
  echo "Unable to determine configured IP families. Please fix cilium-config ConfigMap."
  exit 1
fi

for ipfamily in ipv4 ipv6; do
  case "$ipfamily" in
  ipv4)
    if [ "$CILIUM_ENABLE_IPV4" != "true" ]; then
      continue
    fi
    iptables="iptables -w 5"
    localhost="127.0.0.1"
    wildcard="0.0.0.0"
    ;;
  ipv6)
    if [ "$CILIUM_ENABLE_IPV6" != "true" ]; then
      continue
    fi
    iptables="ip6tables -w 5"
    localhost="::1"
    wildcard="::"
    ;;
  esac

  for proto in tcp udp; do
    rule_match="-p $proto -m mark --mark 0x11270200 -m comment --comment \"cilium: TPROXY to host cilium-dns-egress proxy\""
    cilium_v114_rule="$rule_match -j TPROXY --on-port 10001 --on-ip $localhost --tproxy-mark 0x200/0xffffffff"
    cilium_v113_rule="$rule_match -j TPROXY --on-port 10001 --on-ip $wildcard --tproxy-mark 0x200/0xffffffff"

    until $iptables -t mangle -S CILIUM_PRE_mangle | grep -qF -- "$rule_match"; do
      echo "Waiting for $ipfamily/$proto TPROXY rule ($rule_match). Is cilium-agent running?"
      sleep 1;
    done

    echo "Ensuring Cilium v1.14 $ipfamily/$proto TPROXY rule is installed..."
    if ! $iptables -t mangle -S CILIUM_PRE_mangle | grep -qF -- "$cilium_v114_rule" ; then
      sh -xc "$iptables -t mangle -A CILIUM_PRE_mangle $cilium_v114_rule"
    fi

    echo "Ensuring Cilium v1.13 $ipfamily/$proto TPROXY rule is removed..."
    if $iptables -t mangle -S CILIUM_PRE_mangle | grep -qF -- "$cilium_v113_rule" ; then
      sh -xc "$iptables -t mangle -D CILIUM_PRE_mangle $cilium_v113_rule"
    fi
  done # proto
done # ipfamily
