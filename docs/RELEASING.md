# Releasing uBixGate

GitHub is the public home and where releases are published. Development happens on a
GitLab instance that push-mirrors protected branches and tags to GitHub. GitHub Actions
builds, signs and publishes each release from its tag. Nobody uploads a binary by hand.

## The branch model

| Branch | Role |
|---|---|
| `dev` | Where work lands, by merge request, through the gate. |
| `main` | The release branch. Protected, GitHub's default branch, never pushed to by hand. |

**Promotion.** When every check passes on a push to `dev`, a GitLab job fast-forwards
`main` to that commit (`bin/promote.sh`). It never forces, does nothing if `main` already
contains the commit, and fails closed: if it cannot reach the remote or resolve `main`, it
promotes nothing. If `main` is not an ancestor of the commit, someone wrote to `main`
directly, and the job refuses.

**Tags are cut on `main`.** The release workflow refuses a tag whose commit is not on
`main`, including when it is started by hand.

**The mirror** carries `dev`, `main` and tags to GitHub. Do not push to GitHub directly.
It may push to more than one GitHub repository, but only `ubixsys/ubixgate` publishes
releases: the release workflow skips itself anywhere else, so each version has one set of
downloads and one signature identity.

**If promotion stops**, open the `promote-to-main` job on the latest `dev` pipeline. It
names the cause: a diverged `main` (land the missing commits on `dev` by merge request;
never force-push `main`), an expired token or branch protection (refresh
`GITLAB_PROMOTE_TOKEN`), or a failed check (fix `dev`). Promotion is idempotent, so
re-running the pipeline for the tip of `dev` is always safe.

## What a release publishes

For a tag such as `v0.1.0-beta.1`, the [release workflow](../.github/workflows/release.yml)
creates a GitHub Release holding:

| Asset | What it is |
|---|---|
| `ubixgate-<tag>-<os>-<arch>.tar.gz` | Linux and macOS, amd64 and arm64: the binary, `LICENSE` and `README.md` |
| `ubixgate-<tag>-windows-<arch>.zip` | The same for Windows, amd64 and arm64 (built, not tested) |
| `SHA256SUMS` | SHA-256 of every archive |
| `SHA256SUMS.sigstore.json` | A keyless cosign signature bundle for `SHA256SUMS` |

The release notes are the tag's section of [CHANGELOG.md](../CHANGELOG.md). A tag with a
`-` suffix (`-beta.N`, `-rc.N`) is marked as a pre-release.

The same run pushes the container image `ghcr.io/ubixsys/ubixgate:<version>` (the tag
without its `v`, for linux/amd64 and linux/arm64), plus `<major>.<minor>` and `latest`
for a release without a pre-release suffix, and signs it with keyless cosign. The GitHub
Release is created only after the image is pushed. Only `ubixsys/ubixgate` publishes: the
image never goes under any other GitHub account.

**First release only:** a new GitHub package starts out private. After the first image
is pushed, a maintainer sets `ghcr.io/ubixsys/ubixgate` to public (Package settings,
Change visibility) and links it to the repository, or `helm install` fails to pull it.

## Cutting a release

1. On a branch, move the `[Unreleased]` entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading. Land it on `dev` by merge request.
2. Wait for `promote-to-main` to fast-forward `main` to that commit.
3. Tag `main` and push the tag to GitLab, never to GitHub:

   ```sh
   git fetch origin && git tag -a vX.Y.Z -m vX.Y.Z origin/main && git push origin vX.Y.Z
   ```

4. Watch the Release workflow on `ubixsys/ubixgate`. If the mirrored tag did not start it,
   run `gh workflow run Release --repo ubixsys/ubixgate --ref vX.Y.Z`.

## Verifying a download

```sh
sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ubixsys/ubixgate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The container image:

```sh
cosign verify ghcr.io/ubixsys/ubixgate:0.1.0-beta.1 \
  --certificate-identity-regexp '^https://github.com/ubixsys/ubixgate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

What the version number promises is in [VERSIONING.md](VERSIONING.md).
