{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/7e0743a5aea1dc755d4b761daf75b20aa486fdad.tar.gz";
    sha256 = "sha256:1zs1l3aivfwxmdrjvkiwqqj50z4yww5rx41m5b3qi6jv9pd9185r";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.findutils
    pkgs.gitMinimal
    pkgs.zip
    pkgs.go_1_20
    pkgs.gnupg
    pkgs.rekor-cli
  ];
}
