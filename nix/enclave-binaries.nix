{
  root,
  pkgs,
  crane,
}:
let
  lib = pkgs.lib;

  # The same rust-toolchain.toml cargo already uses, so a channel bump moves the enclaves
  # and the hosts together instead of drifting. rust-overlay carries the component hashes,
  # so there is no hash to paste in here and none to go stale.
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml");
  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  # Enforce the repository's dependency bans before a direct Nix build fetches anything.
  dependencyPolicy = builtins.fromTOML (builtins.readFile (root + "/deny.toml"));
  lockPackages = (builtins.fromTOML (builtins.readFile (root + "/Cargo.lock"))).package;
  allowedPackage = package:
    !(builtins.elem package.name (map (ban: ban.name) dependencyPolicy.bans.deny))
    && (!(lib.hasPrefix "git+" (package.source or ""))
      || lib.any (url:
        lib.hasPrefix "git+${url}?" package.source
        || lib.hasPrefix "git+${url}#" package.source
      ) dependencyPolicy.sources.allow-git);

  publicVendorDir =
    assert lib.assertMsg (lib.all allowedPackage lockPackages)
      "Public enclave builds reject banned dependencies and unapproved Git sources (deny.toml).";
    craneLib.vendorCargoDeps {
      cargoLock = root + "/Cargo.lock";
    };

  # An external executable or model dropped into the checkout must never become
  # a compiler input (including through include_bytes!) or an image input.
  publicSource = lib.cleanSourceWith {
    src = root;
    filter = path: type:
      type == "directory"
      || lib.hasSuffix ".rs" path
      || builtins.elem (builtins.baseNameOf path) [ "Cargo.toml" "Cargo.lock" "rust-toolchain.toml" ]
      || path == toString (root + "/verifier/sandbox-client/worker.policy");
  };

  commonArgs = {
    strictDeps = true;

    # Crane resolves the public workspace while preparing dependencies, including the
    # Linux-only worker process. Prefer Nix's Minijail instead of its Cargo fallback,
    # which expects the complete upstream repository around the vendored Rust crates.
    nativeBuildInputs = with pkgs; [
      clang
      pkg-config
      protobuf
    ];
    buildInputs = with pkgs; [
      minijail
      libcap
    ];
    LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

    # LLVM's LICM scalar promotion orders work by pointer value, so rustc (1.97 and 1.98
    # both) emits different code for the same input under different address-space layouts —
    # the same commit measured different PCRs on different machines. Nix disables ASLR in
    # builds, which hides it locally: each machine is self-consistent and machines disagree.
    # Disabling the promotion makes codegen address-independent, verified by building the
    # enclave under ASLR and varied stack rlimits and getting identical bytes. The cost is
    # one loop optimization. Do not drop this without re-running that experiment.
    RUSTFLAGS = "-C llvm-args=-disable-licm-promotion";
  };

  version = (builtins.fromTOML (builtins.readFile (root + "/Cargo.toml"))).workspace.package.version;

  buildEnclaveBin = pname: craneLib.buildPackage (commonArgs // {
    inherit pname version;
    src = publicSource;
    cargoVendorDir = publicVendorDir;
    cargoExtraArgs = "--locked --bin ${pname}";
  });
in {
  verifier-enclave = buildEnclaveBin "verifier-enclave";
}
