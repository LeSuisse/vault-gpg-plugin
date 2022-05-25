{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/41cc1d5d9584103be4108c1815c350e07c807036.tar.gz";
    sha256 = "sha256:1zwbkijhgb8a5wzsm1dya1a4y79bz6di5h49gcmw6klai84xxisv";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.findutils
    pkgs.gitMinimal
    pkgs.zip
    pkgs.go_1_18
    pkgs.gnupg
    pkgs.rekor-cli
  ];
}
