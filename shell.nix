{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/01441e14af5e29c9d27ace398e6dd0b293e25a54.tar.gz";
    sha256 = "sha256:0yvkamjbk3aj4lvhm6vdgdk4b2j0xdv3gx9n4p7wfky52j2529dy";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go_1_20
    pkgs.gitMinimal
    pkgs.goreleaser
    pkgs.syft
    pkgs.cosign
    pkgs.golangci-lint
  ];
}
