{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/69b9a8c860bdbb977adfa9c5e817ccb717884182.tar.gz";
    sha256 = "sha256:12ljkkjg3gicamvryxr2bnfcdb05qdlbc5wv4lcw9sxamszp4cp7";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go_1_23
    pkgs.gitMinimal
    pkgs.goreleaser
    pkgs.syft
    pkgs.cosign
    pkgs.golangci-lint
  ];
}
