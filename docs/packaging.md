# Packaging Netscope

Netscope can be installed into `~/.local/bin` with `make install`, or packaged as native Linux packages.

## Release Tarball

Build a GitHub Release style tarball and checksums:

```sh
make release
ls dist/
```

Install from a downloaded tarball:

```sh
tar -xzf netscope_0.3.0-beta_linux_amd64.tar.gz
cd netscope_0.3.0-beta_linux_amd64
sh install.sh
netscope doctor
```

After the GitHub repository is public, users can use:

```sh
curl -fsSL https://raw.githubusercontent.com/saiyan566/netscope/main/scripts/install-release.sh | sh
```

## Debian and Ubuntu

Build a local `.deb`:

```sh
make package-deb
sudo apt install ./dist/netscope_0.3.0-beta_amd64.deb
netscope doctor
```

To make `sudo apt install netscope` work on one machine, create a local apt repo:

```sh
make package-deb
sh scripts/setup-local-apt-repo.sh
sudo apt install netscope
```

For public `sudo apt install netscope`, publish the `.deb` to a signed apt repository or submit it to distro packaging channels.

## Arch Linux

Build a local pacman package on Arch Linux:

```sh
make package-arch
sudo pacman -U dist/arch/netscope-0.3.0_beta-1-x86_64.pkg.tar.zst
netscope doctor
```

To make `sudo pacman -S netscope` work on one machine, create a local pacman repo:

```sh
make package-arch
sh scripts/setup-local-pacman-repo.sh
sudo pacman -S netscope
```

For public `sudo pacman -S netscope`, publish the package to an Arch repository or submit a cleaned-up PKGBUILD to AUR.
