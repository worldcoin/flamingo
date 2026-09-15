{
  root,
  nixpkgs,
  rust-overlay,
}:
let
  lib = nixpkgs.lib;
in
# The images are linux-only, but the shell should work on whatever people develop on.
lib.genAttrs
  [
    "x86_64-linux"
    "aarch64-linux"
    "x86_64-darwin"
    "aarch64-darwin"
  ]
  (
    system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
    in
    {
      default = pkgs.mkShell {
        buildInputs = lib.optionals pkgs.stdenv.isLinux [
          pkgs.minijail
          pkgs.libcap
        ];
        packages = with pkgs; [
          (rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml"))
          clang
          pkg-config
          jq
        ];
        LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
      };
    }
  )
