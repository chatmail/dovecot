# Chatmail Relay Dovecot Notes

This repository contains [Chatmail Relay](https://github.com/chatmail/relay)'s
downstream rebuild of Debian's `dovecot` source package (upstream 2.3.21). It
tracks Debian's packaging closely.

## Continuous Integration

The GitHub Actions workflows under `.github/workflows/` are modelled after
how Debian builds and checks this package:

| Part                             | Function                                                      | Upstream Reference                                                                                                                                                      |
|----------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `build`                          | `gbp buildpackage`                                            | [git-buildpackage manual](https://gbp.sigxcpu.org/manual)                                                                                                               |
| pipeline shape                   | (build → autopkgtest → reprotest)                             | [salsa-ci pipeline](https://salsa.debian.org/salsa-ci-team/pipeline) [`recipes/debian.yml`](https://salsa.debian.org/salsa-ci-team/pipeline/-/raw/master/salsa-ci.yml)) |
| `autopkgtest`                    | `debian/tests` DEP-8 in tests in Incus systemd containers     | [`ci.debian.net`](https://ci.debian.net) / [debci](https://ci.debian.net) [autopkgtest](https://salsa.debian.org/ci-team/autopkgtest)                                   |
| `autopkgtest-build-incus / -lxd` | testbed build, its alias format drives image lookup)          | [`tools/autopkgtest-build-lxd`](https://salsa.debian.org/ci-team/autopkgtest/-/raw/master/tools/autopkgtest-build-lxd)                                                  |
| `reprotest`                      | [Reproducible Builds](https://reproducible-builds.org/) check | [reprotest](https://salsa.debian.org/reproducible-builds/reprotest] ([manpage](https://manpages.debian.org/unstable/reprotest/reprotest.1.en.html))                     |
| Incus                            | system containers                                             | [Incus](https://linuxcontainers.org/incus/docs/)                                                                                                                        |
| Upstream                         | Package overview and uild history                             | [Debian dovecot packaging](https://salsa.debian.org/debian/dovecot) and [package tracker](https://tracker.debian.org/pkg/dovecot)                                       |

### reprotest: disabled upstream, enabled here

Debian currently disables reprotest for dovecot, reasons' beyong the one failing test are unclear: `debian/salsa-ci.yml` says

```yaml
# The test suite does not pass reprotest
variables:
  SALSA_CI_DISABLE_REPROTEST: 1
```

Since we build/run as unpriviledged user, we enabled the test.

## Workflow layout

- **`ci`** (`build-staging-deb.yml`): runs on PRs, fans out a bookworm/trixie x amd64/arm64 matrix, each combination calling the reusable
  pipeline: 
- **`deb pipeline`** (`pipeline.yml`): used through `workflow_call`; one distro/arch combination: `build (→ autopkgtest → reprotest)`, the latter two on only on amd64
  as reproducibility is unlikely to depend on architecture.
- **`release`** (`build-deb.yml`): runs on `master` and `upstream/*` tags; builds and publishes the `.deb`s and `.buildinfo` to download.delta.chat and GitHub Releases.

## Versioning
We add a downstream suffix (`...+chatmailN`); as installs are dpkg-pinned, version ordering relative to Debian's own revisions is irrelevant. Furthermore, we're locked on Dovecot 2.3 due to compatibility-breaking changes ([See relay issue](https://github.com/chatmail/relay/issues/476)) and there won't be any new Upstream 2.3.x relaeases from Debian; this is the last unstable version.
