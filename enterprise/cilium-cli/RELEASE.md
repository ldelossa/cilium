# `cilium-cli` Enterprise Edition Release Process

Release process and checklist for `cilium-cli` enterprise edition.

> [!NOTE]
> `isovalent` is used as the remote for the enterprise repository, to avoid
> accidental pushes of enterprise sources to the open source repository. You
> may need to adjust the remote to match your local settings.

### Define environment variables

Define the `OSS_VERSION`, `CEE_VERSION` and `CEE_VERSION_TAG` variables. For
example, if you are releasing v0.16.11-cee.1 based on v0.16.11 OSS:

    export OSS_VERSION=v0.16.11
    export CEE_VERSION=${OSS_VERSION}-cee.1
    export CEE_VERSION_TAG=enterprise/cilium-cli/${CEE_VERSION}

### Update upstream release

In this directory, update to the given `cilium-cli` OSS upstream version:

    go get github.com/cilium/cilium-cli@${OSS_VERSION}
    go mod tidy
    git add go.mod go.sum

## Prepare the release

Release notes need to be added to the  `release-notes` directory with a
filename `$CEE_VERSION.md` (e.g. `release-notes/v0.15.0-cee.1.md`) before you
make a release. Also update the versions in the section at the top so the
environment variable definitions can be copied for the next release.

    git checkout -b pr/prepare-${CEE_VERSION}
    git add RELEASE.md release-notes/$CEE_VERSION.md
    git commit -s -m "enterprise/cilium-cli: prepare for $CEE_VERSION release"
    git push isovalent HEAD

Then open a pull request against `main-ce` branch. Wait for the PR to be reviewed and merged.

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
