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

  # The biometric-engines rev pinned by the root lockfile, so the assets grafted into the
  # vendor tree below cannot come from a different commit than the crates built against them.
  lockedFaceEngineRev =
    let
      lock = builtins.fromTOML (builtins.readFile (root + "/Cargo.lock"));
      sources = lib.unique (
        lib.filter (source: source != null && lib.hasInfix "worldcoin/biometric-engines" source) (
          map (package: package.source or null) lock.package
        )
      );
    in
    assert lib.assertMsg (lib.length sources == 1) (
      "expected one worldcoin/biometric-engines git source in Cargo.lock,"
      + " found "
      + toString (lib.length sources)
    );
    lib.last (lib.splitString "#" (lib.head sources));

  # Fetched here rather than taken as a flake input so there is no second pin to keep in
  # step with Cargo.lock. This is a private repo, and `builtins.fetchGit` runs on the host
  # with the host's git credentials — a credential helper or an ssh agent. No secret
  # reaches a derivation or the store. crane resolves the crates themselves the same way.
  biometricEngines = builtins.fetchGit {
    url = "https://github.com/worldcoin/biometric-engines";
    rev = lockedFaceEngineRev;
    allRefs = true;
  };

  # NOTE: Temporary - while we keep around biometric-engines as a build dep
  # face-engine's consts.rs reads its default graph configs with
  # include_str!("../../../assets/..."), which resolves only in a monorepo checkout —
  # cargo vendors every crate standalone. That path lands at the root of the vendored
  # checkout, one level above the crate directories, so restoring assets/ there satisfies
  # it without patching the crate. Nothing verifies the addition: cargo writes
  # `{"files":{}}` as the checksum manifest for vendored git crates.
  verifierVendorDir = craneLib.vendorCargoDeps {
    cargoLock = root + "/Cargo.lock";
    overrideVendorGitCheckout =
      packages: drv:
      if
        lib.any (package: lib.hasInfix "worldcoin/biometric-engines" (package.source or "")) packages
      then
        pkgs.runCommandLocal "biometric-engines-checkout-with-assets" { } ''
          cp -R --no-preserve=mode,ownership ${drv} $out
          chmod -R u+w $out
          cp -R ${biometricEngines}/assets $out/assets
        ''
      else
        drv;
  };

  commonArgs = {
    strictDeps = true;

    # Crane resolves the whole workspace while preparing dependencies, including the
    # Linux-only worker process. Prefer Nix's Minijail instead of its Cargo fallback,
    # which expects the complete upstream repository around the vendored Rust crates.
    nativeBuildInputs = with pkgs; [
      clang
      pkg-config
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

  buildEnclaveBin =
    {
      pname,
      extraArgs ? { },
    }:
    craneLib.buildPackage (
      commonArgs
      // extraArgs
      // {
        inherit pname version;
        src = root;
        cargoVendorDir = verifierVendorDir;
        cargoExtraArgs = "--locked --bin ${pname}";
      }
    );
in
{
  di-enclave = buildEnclaveBin {
    pname = "di-enclave";
  };
  verifier-enclave = buildEnclaveBin {
    pname = "verifier-enclave";
  };
}
