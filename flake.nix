{
  description = "flamingo-verifier — reproducible Nitro enclave images";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-util = {
      url = "github:monzo/aws-nitro-util";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      rust-overlay,
      nitro-util,
      ...
    }:
    let
      root = ./.;
      # EIFs are linux/amd64 only, so there is nothing to gain from other systems here.
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      enclaveBins = import ./nix/enclave-binaries.nix {
        inherit root pkgs crane;
      };
      faceModels = import ./nix/face-models.nix {
        inherit pkgs;
      };
      enclaveImages = import ./nix/enclave-images.nix {
        inherit system pkgs nitro-util enclaveBins;
        workerBootstrapConfig = ./config/worker-bootstrap.json;
      };
    in
    {
      packages.${system} = builtins.removeAttrs enclaveBins [ "verifier-worker" ] // enclaveImages;

      # Opt-in prototype outputs; public flake checks must never resolve private dependencies.
      privatePackages.${system} = {
        verifier-worker = enclaveBins.verifier-worker;
        verifierModels = faceModels.package;
        verifier-worker-runtime = import ./nix/worker-runtime.nix {
          inherit pkgs;
          worker = enclaveBins.verifier-worker;
          models = faceModels.package;
        };
      };

      faceModels = faceModels.metadata;

      devShells = import ./nix/dev-shells.nix {
        inherit root nixpkgs rust-overlay;
      };
    };
}
