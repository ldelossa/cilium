FQDN-Proxy ("cilium-dnsproxy")
============================

This codebase is the FQDN-Proxy code from the cilium codebase
modularized as its own program, meant to run as its own deployment (daemonset).

Normally, Cilium runs a DNS proxy server that intercepts DNS packets so that it can
look up IP addresses to enforce L7 policies that are based on FQDN rules.
When Cilium goes down this causes all pod-based DNS requests on its node to fail.

When FQDN-Proxy is deployed Cilium still runs its own DNS proxy server, but
the DNS requests are now routed to the FQDN-Proxy K8s Service which will continue
to service DNS requests even if Cilium is down. The FQDN-Proxy deployment
is a Daemonset (that is run on each node). This ensures that DNS
requests are served by an HA service.


How to Publish a New Version
----------------------------

### Ensure that the semantic version is up to date in the repository

The following files contain references to the semantic version of the codebase and should
be up to date before the image or helm chart is published:

- ./installation/Chart.yaml (run `make -C installation update-chart to update it base on the `VERSION` file in the root directory of the repository)
- ./installation/README.md (run `./installation/test.sh` to generate this file).

### Run Compatibility Tests

In order to run the compatibility tests you must have kind, helm, kubectl, and cilium-cli installed.

Run the compatibility tests within the `scripts` directory. The first argument to the script is
a semicolon delimited list of FQDN-Proxy versions to test (in ascending order). The second argument
is a semicolon delimited list of Cilium versions to test (in ascending order). For example:

```bash
cd scripts
# The following line will test FQDN-Proxy versions "1.12.8-1.13.1" against
# Cilium versions "1.12.6-1.12.8"
./compat-test.sh "1.12.8;1.13.0;1.13.1" "1.12.6;1.12.7;1.12.8"
```

In the example above `compat-test.sh` will test FQDN-Proxy version 1.13.1 with Cilium
version 1.12.6, then upgrade Cilium to 1.12.7, then 1.12.8. Finally, it will test
Cilium version 1.12.8 with FQDN-Proxy version 1.12.8, then upgrade FQDN-Proxy to 1.13.0,
then 1.13.1.

After the script runs it will generate a list of potential upgrade problems. Note that the 
method of testing high availability for FQDN-Proxy involves bringing the Cilium damonset "down"
in a clumsy way and can lead to false negative results. Failures should be individually
run to verify them. Making this test more robust is being tracked by [this issue](https://github.com/isovalent/cilium-cli-ci/issues/6).

Once you have obtained compatibility results you can update the compatibility matrix in
this readme as well as the [Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/blob/master/docs/operations-guide/features/dnsproxy-ha/index.rst#versions-compatibility).

### Publish release notes

After releasing a new version of FQDN-Proxy, create a new page with the
customer-facing release notes of the new release in
in the [Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/tree/main/docs/operations-guide/releases/release-notes)
repo.

### Bump FQDN-Proxy version in Cilium Enterprise

After releasing a new version of FQDN-Proxy, update the FQDN-Proxy version in
the [isovant/cilium](https://github.com/isovalent/cilium/)
CI workflows and the Atlantis plugin (for v1.14 and older).

Compatibility Matrix with Cilium
--------------------------------

Please refer to the docs for the [Compatibility Matrix](https://docs.isovalent.com/operations-guide/releases/version-compatibility.html)

Backporting FQDN-Proxy Bug Fixes
--------------------------------
In the event that FQDN-Proxy needs a backported bug fix then new patch releases of FQDN-Proxy will be released
and the version should be documented in the Compatibility Matrix 
in this README and [the Cilium Enterprise Docs](https://github.com/isovalent/cilium-enterprise-docs/blob/master/docs/operations-guide/features/dnsproxy-ha/index.rst#versions-compatibility).
Though we have not done this yet, we will also document the Cilium
library version overlap (so as to extend the Compatibility matrix) in FQDN-Proxy patch releases.

Hotfix Process
--------------
To create a hotfix image follow these instructions:

1. Make sure that your hotfix has been reviewed and tested (preferably in a PR).
2. Once your hotfix has been tested and approved create a new
   branch in this repository with the naming pattern
   `hf/<base branch>/<base tag>-<GH issue number>`, for example
   `hf/v1.13/v1.13-255`. **DO NOT** mention the customer's name
   in the hotfix branch. **DO NOT** create a new pull request.
   The hotfix workflow will be able to publish the image from the
   branch.
3. Wait for the hotfix image to be published.
4. Verify that the image is published at `quay.io/isovalent/cilium-dnsproxy:<base-tag>-<GH issue number>`
