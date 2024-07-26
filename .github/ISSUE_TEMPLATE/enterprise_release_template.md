---
name: Release a new version of Cilium Enterprise vX.Y.Z-cee.1
about: Create a checklist for an upcoming OSS-derived release
title: 'vX.Y.Z-cee.1 release'
labels: kind/release
assignees: ''

---

_WIP, derived from [The OG Cilium Enterprise release resource]_

_Tip of the day: Create a release using [this handy bash function]!_

_If you need help: ask in #enterprise-release._

## Prepare images

- [ ] Check whether we should make a corresponding Cilium OSS release first
  - Coordinate with the OSS release manager. They will have performed their release ritual but held off tagging until our release is ready as well.
- [ ] Check that there are no [release blockers] for the targeted release version.
- [ ] Check that there are no [pending backports] for the targeted release version.
- [ ] Ensure that outstanding [backport PRs] are merged.
- [ ] Synchronize the Isovalent tree to the upstream tree
  - Click the Run workflow button here: [mirror-upstream-workflow]
- [ ] Cherry-pick commits from the upstream tree since the last sync. You will have to determine the commit hash of the commit the OSS release will tag. Either check the `cilium/cilium` repo or use something like: `git fetch upstream && git log upstream/vX.Y --grep "release vX.Y.Z"` assuming that `upstream` points to `cilium/cilium`.

        # You need to tweak these three parameters.
        OSS_RELEASE_COMMIT_SHA=YOU_NEED_TO_FIND_THIS_YOURSELF
        VERSION=X.Y
        PR=pr/$USER/vX.Y.Z-prep

        # You can just copy & paste the rest.
        OSS_SYNC_TAG=oss-sync-${VERSION}-$(date +%Y-%m-%d)
        OSS_BRANCH=v${VERSION}
        CEE_BRANCH=v${VERSION}-ce
        LAST_OSS_COMMIT_SYNCED=$(git tag --sort=-creatordate | grep oss-sync-${VERSION} -m1)
        git fetch origin
        git fetch origin ${OSS_BRANCH}:${OSS_BRANCH}
        git fetch origin ${CEE_BRANCH}:${CEE_BRANCH}
        git checkout -B ${PR} ${CEE_BRANCH}
        git tag -m ${OSS_SYNC_TAG} ${OSS_SYNC_TAG} ${OSS_RELEASE_COMMIT_SHA}
        git cherry-pick -x --signoff ${LAST_OSS_COMMIT_SYNCED}..${OSS_RELEASE_COMMIT_SHA}

  - [ ] Resolve all conflicts that come up.
    - First conflict is typically in the "Update image digests" commit. Skip this one since it contains OSS image digests.
      - [ ] `git cherry-pick --skip`
    - Subsequent conflicts may require more indepth manual resolution.
      - Sometimes, we may have already backported the change; can `git cherry-pick --skip`.
      - Sometimes, there may be minor conflicts in files that contain versions.
      - If the conflict is surprising or unclear, raise a Slack thread with the relevant authors to make sure that the backport is correctly resolved.
      - [ ] `git cherry-pick --continue`
    - Final commit to cherry-pick has the message `Prepare for release vX.Y.Z`
      - Manually amend this commit to update:
        - [ ] `VERSION` file
        - [ ] `git checkout --ours install/kubernetes/cilium/{Chart.yaml,README.md,values.yaml}`
        - [ ] `make -C install/kubernetes`
        - [ ] for `>=v1.15-ce`: `RELEASE=yes make -C enterprise/fqdn-proxy/installation`
        - [ ] for `<v1.14-ce`:
          - [ ] run `make -C install/kubernetes MAKEFILE_VALUES=Makefile.enterprise.values cilium/values.yaml` and make sure the values.yaml points to the correct image tags.
        - [ ] run `make -C Documentation update-helm-values`
        - [ ] `git diff` and manually inspect that all of the changes make sense in the Cilium Enterprise tree. Digests will be removed (e.g. in `install/kubernetes/cilium/README`), the quay.io repositories will change to Isovalent, and the versions should have the `-cee.1` suffix.
        - [ ] `git cherry-pick --continue`
        - [ ] Update the commit message to reflect the correct enterprise version `vX.Y.Z-cee.1`
- [ ] Open a pull request with this branch against the Isovalent repository
  - `gh pr create -B ${CEE_BRANCH} --label "release-note/oss-sync"` (NOTE: Make sure this is against Isovalent tree!)
  - [ ] Wait for CI images to build+push
  - [ ] Run end-to-end CI tests by posting a comment `/test-backport-X.Y`
- [ ] Merge the PR. Then push the new OSS sync tag:

        git push origin ${OSS_SYNC_TAG}

- [ ] Tag the release
  - [ ] `git fetch origin`
  - [ ] `git checkout origin/vX.Y-ce`
  - [ ] `git tag vX.Y.Z-cee.1 && git push origin vX.Y.Z-cee.1`
- [ ] Check draft release from [releases] page
  - [ ] Select the `vX.Y.Z-cee.1` tag created from the previous step.
  - [ ] Generate the release notes by selecting `Generate release notes`.
  - [ ] Ensure that `Set as the latest release` is only checked for the latest minor release. Ex: If you are releasing v1.13.3, v1.12.10, and v1.11.17, only v1.13.3 should have this checked.
- [ ] Generate tiered images
  - [ ] Go to https://github.com/isovalent/cilium/actions/workflows/enterprise-build-images-tiered-releases.yaml and run workflow with `vX.Y.Z-cee.1` in `Tag to release tiered images for` field.
  - [ ] Click on the started action and approve deployment (it should be approvable by `release-manager` team)
  - [ ] Check in after some time to see whether the action succeeded. If it didn't, raise this issue in #enterprise-release slack channel.

## Prepare Helm & documentation

_Handy tip: If you ever feel unsure, you can always look at how the previous release was done. You'll see useful example PRs, and you can ask the previous release manager if something remains unclear or you need a review._

- [ ] Wait for the images to build at [build-images-releases] workflow
  - You can check quay.io whether the images matching your tag have appeared: [quay-agent], [quay-operator]
  - [ ] For `<v1.14-ce`, this workflow also generates the `vX.Y.Z-cee.1-gen-tag` tag, which includes the generated code. Verify that the tag is created. If it isn't, for some reason, you can use the `atlantis-gen` workflow to generate it.
- [ ] Build the helm charts for the release via [helm-repo] workflow. You can check whether they were picked up with:

        helm repo add isovalent https://helm.isovalent.com
        helm repo update
        helm search repo isovalent/cilium --versions | grep X.Y.Z

- [ ] Update the "umbrella" [helm-charts]
  - Clone the [helm-charts] repository locally. Check out branch `master` for the latest Cilium version, or branch `vX.Y` otherwise.
  - Update `cilium-enterprise/Chart.yaml`, and then run `test.sh`. Create a PR against your base branch: `master` (for the latest Cilium version) or `vX.Y`.
  - Example PR: https://github.com/isovalent/helm-charts/pull/389/files
  - [ ] Merge the PR
  - [ ] Create a release: https://github.com/isovalent/helm-charts/releases/new
    - You can use Github's 'tag on publish' feature: Enter your desired tag in the tag field of the form (it should say something like 'Create new tag: vX.Y.Z on publish'). Make sure you select the same branch you merged your PR into.
- [ ] Update the version in the cilium enterprise docs.
  - If you are releasing the very first (non-beta) enterprise release for a minor version, you will have to create a new branch in the enterprise docs repo. The enterprise docs are structured so that the latest version is on the `master` branch, and older releases on `x.y` branches. Example: If `1.12.3` is the latest OSS version, and so far only 1.12.2-cee.beta1 has been released, you'll have to create a branch `1.12` off `master` to release `1.12.3-cee.1`.
  - [ ] Create a PR which updates the toplevel `CILIUM_VERSION` and `CILIUM_UMBRELLA_VERSION` (and `DNS_PROXY_VERSION` for `>=1.15-ce`) files to your newly released version. Target the PR at the `X.Y` branch. If there is no such branch, and you are releasing the latest minor, target `main`. Update the version compatibility matrix CSV files (`docs/operations-guide/releases/X.Y-versions.csv`) with the proper supported software versions (ex: what version of Hubble-Enterprise works with this version of Cilium)
- [ ] If this is a new minor release version, check for a staging documentation branch.
  - [ ] Check if there is a `cilium/x.y-ce` branch in the cilium-enterprise-docs repository that needs to be merged. ([v1.16-ce example](https://github.com/isovalent/cilium-enterprise-docs/tree/cilium/v1.16-ce)). Open a PR to merge that branch into the `main` branch. This branch will contain documentation for new Cilium Enterprise features being released with the new minor version.
  - Make sure you merge this branch _after_ the previous minor version branch has been created. For example, before merging the `cilium/v1.16-ce` branch, make sure you have already created and pushed the v1.15 branch in the steps prior.
- [ ] Prepare artifacts for Azure Marketplace build
  - [ ] The release series is listed in the `CILIUM_VERSIONS.yaml` file in [Azure Marketplace CNAB]. Ignore these steps if the x.y versions do not match. Follow the instructions in the [README.md](https://github.com/isovalent/external-azure-marketplace-cnab/blob/main/README.md) to create artifacts for the new release.
- [ ] Follow https://github.com/isovalent/cilium-enterprise-docs/blob/main/scripts/release-notes/README.md
      to generate release notes.
- [ ] Update https://isogo.to/releases
  - [ ] Move the entry for the current release from planned to past.
  - [ ] Add an entry for the next release and its planned date.
- [ ] Announce release in [#release-announce](https://app.slack.com/client/T40ANG0TH/C043UEUA12T)

[Azure Marketplace CNAB]: https://github.com/isovalent/external-azure-marketplace-cnab
[#azure-partnership-internal]: https://isovalent.slack.com/archives/C0354JHPVT7
[backport PRs]: https://github.com/isovalent/cilium/pulls?q=is%3Apr+is%3Aopen+label%3Aenterprise-backport%2FX.Y
[build-images-releases]: https://github.com/isovalent/cilium/actions/workflows/build-images-releases.yaml
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[helm-charts]: https://github.com/isovalent/helm-charts
[helm-repo]: https://github.com/isovalent/helm-repo/actions/workflows/generate.yaml
[kubeval]: https://github.com/instrumenta/kubeval
[kubeform]: https://github.com/yannh/kubeconform
[mirror-upstream-workflow]: https://github.com/isovalent/cilium/actions/workflows/mirror-upstream.yaml
[pending backports]: https://github.com/isovalent/cilium/labels/enterprise-backport-pending%2FX.Y
[releases]: https://github.com/isovalent/cilium/releases
[release blockers]: https://github.com/isovalent/cilium/labels/release-blocker%2FX.Y-ce
[The OG Cilium Enterprise release resource]: https://docs.google.com/document/d/1-VNR7IwdQecWCtIiEChvfvUyit-kkRt-LVkavIDjHDU/edit
[this handy bash function]: https://github.com/isovalent/cilium/blob/default/create_release_issues.bash
[quay-agent]: https://quay.io/repository/isovalent/cilium?tab=tags&tag=latest
[quay-operator]: https://quay.io/repository/isovalent/operator?tab=tags&tag=latest
