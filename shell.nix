{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/5c37ad87222cfc1ec36d6cd1364514a9efc2f7f2.tar.gz";
    sha256 = "1r74afnalgcbpv7b9sbdfbnx1kfj0kp1yfa60bbbv27n36vqdhbb";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.findutils
    pkgs.gitMinimal
    pkgs.zip
    pkgs.go_1_17
    pkgs.gnupg
    pkgs.rekor-cli
  ];
}
