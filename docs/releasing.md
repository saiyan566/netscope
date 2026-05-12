# Releasing Netscope

This guide explains how to publish Netscope so other Linux users can install it.

## 1. Prepare Repository Metadata

Before each public release, confirm repository metadata points to `saiyan566/netscope` or your chosen release repository:

- `README.md`
- `scripts/install-release.sh`
- `scripts/package-deb.sh`
- `packaging/arch/PKGBUILD`
- `.github/ISSUE_TEMPLATE/config.yml`

Search for stale placeholders:

```sh
grep -R "YOUR_GITHUB_USERNAME\\|whatarsal" .
```

## 2. Run Local Checks

```sh
gofmt -w cmd/netscope/*.go
cargo fmt --manifest-path engine/Cargo.toml
make test
make release
```

Release artifacts are written to `dist/`:

```txt
netscope_0.3.0-beta_linux_amd64.tar.gz
netscope_0.3.0-beta_amd64.deb
checksums.txt
```

## 3. Push to GitHub

```sh
git init
git add .
git commit -m "Initial Netscope release"
git branch -M main
git remote add origin https://github.com/saiyan566/netscope.git
git push -u origin main
```

## 4. Create a Release Tag

```sh
git tag v0.3.0-beta
git push origin v0.3.0-beta
```

The GitHub Actions release workflow builds artifacts and opens a draft GitHub Release.

Review the draft release, confirm the assets, then publish it.

## 5. Public Install Commands

After publishing the release, users can install with:

```sh
curl -fsSL https://raw.githubusercontent.com/saiyan566/netscope/main/scripts/install-release.sh | sh
```

Or with an explicit repository:

```sh
curl -fsSL https://raw.githubusercontent.com/saiyan566/netscope/main/scripts/install-release.sh | NETSCOPE_REPO=saiyan566/netscope sh
```

Debian/Ubuntu users can install the `.deb`:

```sh
wget https://github.com/saiyan566/netscope/releases/download/v0.3.0-beta/netscope_0.3.0-beta_amd64.deb
sudo apt install ./netscope_0.3.0-beta_amd64.deb
```

## 6. APT and Pacman Repositories

For true:

```sh
sudo apt install netscope
sudo pacman -S netscope
```

you need either official distro packaging or your own signed package repository.

Start with GitHub Releases first, then add:

- AUR package: `netscope-bin`
- Signed APT repository
- Signed pacman repository

## 7. Release Checklist

- `make test` passes.
- `make release` creates tarball, `.deb`, and checksums.
- `netscope doctor` works from the packaged binary.
- `README.md` examples match the released CLI.
- `CHANGELOG.md` has the new version and date.
- `SECURITY.md` has a working private report path.
- GitHub Release notes mention safety and authorized use.
- Assets include `checksums.txt`.

## 8. Version Upgrade Flow

For the next release:

1. Update `VERSION`, `version` in `cmd/netscope/main.go`, and `engine/Cargo.toml`.
2. Update package versions in `packaging/arch/PKGBUILD` when needed.
3. Update `CHANGELOG.md`.
4. Run `VERSION=x.y.z make release`.
5. Commit.
6. Tag `vx.y.z`.
7. Publish the GitHub Release.
