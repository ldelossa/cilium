#!/usr/bin/env bash

set -e
set -u

REPO_OSS="cilium/cilium"
REPO_CEE="isovalent/cilium"

if [[ "$#" -ne 2 ]]; then
    echo "Usage: $0 <start> <end>"
    exit 1
fi
START="$1"
END="$2"

get_commits() {
    local start="$1"
    local end="$2"

    git log --format='%H' ${start}..${end}
}

get_upstream() {
    local commit="$1"

    git show --format=%b --no-patch "${commit}" | \
        sed -n 's/^\[ upstream commit \(.*\) \]$/\1/p'
}

get_prs() {
    local repo="$1"
    local commit="$2"
    local base="$3"

    gh -R ${repo} pr list \
        --search "${commit} ${base} is:merged" \
        --json number,title,url,body
}

get_len() {
    local prs="$1"

    echo "${prs}" | jq 'length'
}

print_commit() {
    local commit="$1"

    git show -s --pretty=ref "${commit}"
}

print_pr() {
    local pr="$1"

    echo "${pr}" | jq -r '"- \(.[0].title) (`#\(.[0].number) <\(.[0].url)>`_)"'
    notes=$(echo "${pr}" | jq '.[0].body' | sed -n 's/.*```release-note\\r\\n\(.*\)\\r\\n```\\r\\n.*/\1/p')
    if [[ -n "${notes}" ]]; then
        echo "    ${notes}"
    fi
}

i=0
last_pr=""
for commit in $(get_commits "${START}" "${END}"); do
    upstream="$(get_upstream ${commit})"

    if [[ -n "${upstream}" ]]; then
        # Search upstream, main branch
        prs="$(get_prs "${REPO_OSS}" "${upstream}" "base:main")"
        len="$(get_len "${prs}")"

        if [[ "${len}" -eq 0 ]]; then
            # Search upstream, any branch
            prs="$(get_prs "${REPO_OSS}" "${upstream}" "")"
            len="$(get_len "${prs}")"

            if [[ "${len}" -eq 0 ]]; then
                # Search CEE, any branch
                prs="$(get_prs "${REPO_CEE}" "${commit}" "")"
                len="$(get_len "${prs}")"

                if [[ "${len}" -eq 0 ]]; then
                    echo "No PR for upstream $(print_commit ${upstream})"
                    continue
                fi
            fi
        fi
    else
        # Search CEE, any branch
        prs="$(get_prs "${REPO_CEE}" "${commit}" "")"
        len="$(get_len "${prs}")"

        if [[ "${len}" -eq 0 ]]; then
            echo "No upstream for $(print_commit ${commit})"
            continue
        fi
    fi

    number=$(echo "${prs}" | jq '.[0].number')
    if [[ "${number}" == "${last_pr}" ]]; then
        continue
    else
        last_pr="${number}"
    fi

    print_pr "${prs}"

    #i=$((i + 1))
    #if [[ "${i}" -ge 100 ]]; then
        #exit 0
    #fi
done
