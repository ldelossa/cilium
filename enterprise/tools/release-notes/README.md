# release-notes.sh (work in progress)

This is a work-in-progress tool to generate release notes for Isovalent
Enterprise Cilium releases.

## Prerequisite

### [gh](https://cli.github.com/)

Install `gh` and run `gh auth login` to login to your GitHub account.

## Examples

To generate release notes for `v1.14.7-cee.1`:

    ./release-notes.sh v1.14.6-cee.1 v1.14.7-cee.1
