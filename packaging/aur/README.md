# AUR packaging

`PKGBUILD` in this directory is prepared for publication to the Arch User
Repository as package `sindook` (source build). The build was verified from
a pristine v0.8.1 tarball: the binary reports `sindook 0.8.1` and `selftest`
passes with the same flags used by `scripts/verify-reproducibility.sh`.

## Publication steps (requires the maintainer's AUR SSH key)

    git clone ssh://aur@aur.archlinux.org/sindook.git
    cp packaging/aur/PKGBUILD sindook/
    cd sindook
    makepkg --printsrcinfo > .SRCINFO
    git add PKGBUILD .SRCINFO
    git commit -m "sindook 0.8.1-1"
    git push

Publication is a maintainer action because it requires the AUR account's
SSH key; nothing in CI holds that credential.

## Version bumps

1. Update `pkgver`, reset `pkgrel` to 1, and replace `sha256sums` with the
   SHA-256 of the new `https://github.com/ruddro-roy/sindook/archive/refs/tags/v<VERSION>.tar.gz`
   (the source tarball is not in the release `checksums.txt`; compute it
   with `curl -fsSL -o - <url> | sha256sum`).
2. Re-run the tarball build check (build, `--version`, `selftest`) before
   publishing.
