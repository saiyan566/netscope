# Public Publication Checklist

Use this before making the repository public.

## Required

- [ ] Replace `whatarsal` placeholders.
- [ ] Pick and confirm the license.
- [ ] Review `SECURITY.md`.
- [ ] Review `CONTRIBUTING.md`.
- [ ] Review `CODE_OF_CONDUCT.md`.
- [ ] Run `make test`.
- [ ] Run `make release`.
- [ ] Install from the generated tarball and run `netscope doctor`.
- [ ] Install from the generated `.deb` and run `netscope doctor`.
- [ ] Confirm `README.md` install commands point to the real repo.
- [ ] Confirm no private targets, test reports, local paths, or secrets are committed.

## Recommended

- [ ] Enable GitHub Discussions.
- [ ] Enable GitHub Security Advisories.
- [ ] Add repository topics: `security`, `scanner`, `recon`, `rust`, `go`, `linux`, `cli`, `bug-bounty`.
- [ ] Add branch protection for `main`.
- [ ] Require CI to pass before merge.
- [ ] Create a draft release before publishing.
- [ ] Add screenshots or terminal examples to the README.

## Do Not Publish

- Private target lists
- API tokens
- Bug bounty program data that is not public
- Scan output from third-party assets
- Local build artifacts from `build/`, `dist/`, or `engine/target/`
