# `cilium-cli` Enterprise Edition Release Process

Release process and checklist for `cilium-cli` enterprise edition.

> [!NOTE]
> `isovalent` is used as the remote for the enterprise repository, to avoid
> accidental pushes of enterprise sources to the open source repository. You
> may need to adjust the remote to match your local settings.

### Define environment variables

Find the OSS version in https://github.com/cilium/cilium-cli/releases, and
verify that main-ce branch contains the commit used to build the OSS release.

Define the `CEE_VERSION` and `CEE_VERSION_TAG` variables. For example, if you
are releasing v0.16.17-cee.1 based on v0.16.17 OSS:

    export CEE_VERSION=v0.16.17-cee.1
    export CEE_VERSION_TAG=enterprise/cilium-cli/${CEE_VERSION}

## Tag a release

Update your local checkout:

    git checkout main-ce
    git pull isovalent main-ce

Set the commit you want to tag:

    export COMMIT_SHA=<commit-sha-to-release>

Usually this is the most recent commit on `main-ce`, i.e.

    export COMMIT_SHA=$(git rev-parse isovalent/main-ce)

Then tag and push the release:

    git tag -a $CEE_VERSION_TAG -m "$CEE_VERSION release" $COMMIT_SHA && git push isovalent $CEE_VERSION_TAG

Then, go to
https://github.com/isovalent/cilium/actions/workflows/enterprise-release-cilium-cli.yaml?query=event%3Apush
and you can stare at the Github Actions output while it creates a release.

## Review release draft and publish

The release goes to another repository https://github.com/isovalent/cilium-cli-releases. This is
a public repository that's used to host cilium-cli binary releases without any source code.

Go to https://github.com/isovalent/cilium-cli-releases/releases and you'll see a newly created
draft. Click on "Edit draft" button, review the draft, and then click on "Publish release" if
everything looks ok.

## Update Cilium Enterprise Docs

After the release is published, make a PR to update the
[`CILIUM_CLI_VERSION`](https://github.com/isovalent/cilium-enterprise-docs/blob/main/CILIUM_CLI_VERSION)
in the [cilium-enterprise-docs repo](https://github.com/isovalent/cilium-enterprise-docs).
