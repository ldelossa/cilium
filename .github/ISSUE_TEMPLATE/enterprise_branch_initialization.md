---
name: Create a new stable enterprise branch (v1.X-ce)
about: A checklist for initialization of the enterprise-only bits for a new stable branch
title: 'v1.X-ce branch initialization'
assignees: ''
---

_If you need help: ask in #enterprise-release._

After OSS has created a new stable branch (say, [v1.13]), it's time to also
create the corresponding enterprise branch, and initialize it with all the magic
sprinkles that make up the enterprise edition.

On a high level, we need to adjust CI to now care about `-ce` branches and add
some automation details.

## Prepare the branch

- [ ] Create a PR that updates the `.github/workflows/mirror-upstream.yaml`
      file to also include the new `v1.X`, so that the Isovalent fork also
      mirrors the new branch:
  - [ ] Add the "v1.X" to the [`BRANCHES`]
  - [ ] Potentially extend the [`PATHSPEC`] of mirrored CI workflows. A
        `grep issue_comment ./.github/workflows/* -R -l` on
        `cilium/cilium` gives you the list.
- [ ] Once merged, trigger the workflow.
- [ ] Create the new enterprise branch, i.e. `git switch` to the new branch,
      then `git branch v1.XX-ce`. Push it to the fork.

(We don't add the things below directly at this point so that there's a chance
to do review on a PR.)

## CI and Makefiles

- [ ] Change all references to `1.X` to `1.X-ce` in
      `.github/workflows/build-image-*.yaml`, for inspiration again see [this PR
      for v1.13].
- [ ] Add the enterprise variants of the Makefile definitions:
  - [ ] `install/kubernetes/Makefile.enterprise.values`: Base it on the OSS
        `Makefile.values`, but replace the image registries with their Isovalent
        counterparts, i.e. `quay.io/cilium` becomes `quay.io/isovalent` or
        `quay.io/isovalent-dev` as appropriate. See [this diff] for reference.
  - [ ] `install/kubernetes/Makefile.enterprise.digests` is just a copy of the
        OSS variant.
  - [ ] Change `install/kubernetes/Makefile` so that `MAKEFILE_VALUES` points to
        the newly created `Makefile.enterprise.values`.
- [ ] Add "Call closer" workflow `.github/workflows/call-closer.yaml` which
      will take care of closing backport tracking issues. This can be done by
      copying the corresponding workflow from a previous `v1.X-ce` branch and
      adjusting the branch name and label. See [this v1.14 PR] for an example.
- [ ] Delete enterprise/cilium-cli directory:

        git rm -r enterprise/cilium-cli

## Forward port Workflows with pull_request targets

Most of the GitHub workflow definitions can live in the `default` branch, but
stuff which should run when on a `pull_request` trigger needs to be in the
base/target branch of a PR for GitHub to consider it. Workflows which are not in
OSS thus need to be forward ported from the last stable enterprise branch.
Here's a likely not exhaustive list of what needs to come with:

- [ ] `close-fixed-issues.yaml`: You need to change the `branches` in the `on`
      section to match the new branch name.


[v1.13]: https://github.com/cilium/cilium/tree/v1.13
[this diff]: https://github.com/isovalent/cilium/pull/746#issuecomment-1437703837
[this PR for v1.13]: https://github.com/isovalent/cilium/pull/574
[`BRANCHES`]: https://github.com/isovalent/cilium/blob/db3697989ca5224b246e358867107cc28c3d25ba/.github/workflows/mirror-upstream.yaml#L28
[`PATHSPEC`]: https://github.com/isovalent/cilium/blob/db3697989ca5224b246e358867107cc28c3d25ba/.github/workflows/mirror-upstream.yaml#L65
[this v1.14 PR]: https://github.com/isovalent/cilium/pull/1629
