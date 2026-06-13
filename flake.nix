{
  description = "sconce dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        # `nix develop` provides the host tools sconce's tests and scripts
        # assume. The Rust toolchain itself is NOT provided here — rustup /
        # your host toolchain own that (rust-toolchain.toml pins the channel);
        # this shell only bridges the gap.
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.git       # archiver reads git trees; fixtures build small repos
            pkgs.unzip     # validate produced archives in tests/scripts
            pkgs.bash      # scripts use `set -euo pipefail`
            pkgs.coreutils # `mktemp -d`, `sha256sum`, consistent across OSes
          ];
        };
      });
}
