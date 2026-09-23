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
      rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml")).override {
        targets = [ "wasm32-unknown-unknown" ];
      };
      llvm = pkgs.llvmPackages;
      wasmBindgenCli = pkgs.rustPlatform.buildRustPackage rec {
        pname = "wasm-bindgen-cli";
        version = "0.2.126";
        src = pkgs.fetchurl {
          name = "${pname}-${version}.tar.gz";
          url = "https://static.crates.io/crates/${pname}/${pname}-${version}.crate";
          hash = "sha256-ji6/bu+Hw05mI0fx3d++pUEwS7cpRxHtLCrNh0bMW1A=";
        };
        cargoHash = "sha256-VucqkXbCi4qtQzY/HrXiDnbSURsagPsdNVMn1Tw3UiY=";
        doCheck = false;
      };
      firefoxAvailable = lib.meta.availableOn pkgs.stdenv.hostPlatform pkgs.firefox;
      firefoxBinary = if pkgs.stdenv.isDarwin then
        "${pkgs.firefox}/Applications/Firefox.app/Contents/MacOS/firefox"
      else
        "${pkgs.firefox}/bin/firefox";
    in
    {
      default = pkgs.mkShell ({
        buildInputs = lib.optionals pkgs.stdenv.isLinux [
          pkgs.minijail
          pkgs.libcap
        ];
        packages = with pkgs; [
          rustToolchain
          clang
          protobuf
          pkg-config
          jq
          llvm.clang-unwrapped
          llvm.bintools-unwrapped
          wasmBindgenCli
          binaryen
          nodejs
        ] ++ lib.optionals firefoxAvailable [
          firefox
          geckodriver
        ];
        LIBCLANG_PATH = "${llvm.libclang.lib}/lib";
        CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
        AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";
        CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER = "${wasmBindgenCli}/bin/wasm-bindgen-test-runner";
        WASM_BINDGEN_USE_BROWSER = "1";
      } // lib.optionalAttrs firefoxAvailable {
        GECKODRIVER = "${pkgs.geckodriver}/bin/geckodriver";
        GECKODRIVER_ARGS = "--binary ${firefoxBinary}";
      });
    }
  )
