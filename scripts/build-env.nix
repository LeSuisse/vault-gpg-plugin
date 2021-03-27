{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/c0e881852006b132236cbf0301bd1939bb50867e.tar.gz") {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.findutils
    pkgs.gitMinimal
    pkgs.zip
    pkgs.go_1_16
  ];
}
