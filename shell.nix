{ pkgs ? import (
  fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/dac74fead8737d6bf0823f22da26c7344f69bc0a.tar.gz";
    sha256 = "0m0bqkh4bmlg5djb9bmyrpa1s4kwy2klil36487vyqkbdxnl76f7";
  }
) {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.findutils
    pkgs.gitMinimal
    pkgs.zip
    pkgs.go_1_16
  ];
}
