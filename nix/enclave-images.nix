{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
}:
let
  nitroLib = nitro-util.lib.${system};
  nitroBlobs = nitroLib.blobs.x86_64;
  # aws-nitro-util still pins v1.2.3; v1.5.0 fixes init's mount-root setup.
  enclaveInit = pkgs.fetchurl {
    name = "nitro-init-1.5.0";
    url = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/2950b3699d81ad304df2458915688a552734833d/blobs/x86_64/init";
    hash = "sha256-dV5lC3Mnd7eYy57CQ+5AK+9IJveJzwGh5FO7ckIHwAU=";
  };

  # WIP-107 registrations a billing enclave holds: about 72 MiB of state, twice that while a new
  # billing stream catches up. The bound is in the EIF's environment, so it is measured.
  billingMaxRegistrations = 4194304;

  buildEnclaveImage =
    {
      workload,
      pname,
      billing ? false,
    }:
    let
      version = enclaveBins.${pname}.version;
      env = [
        "RUST_LOG=warn"
        "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      ]
      ++ pkgs.lib.optional billing "FLAMINGO_BILLING_MAX_REGISTRATIONS=${toString billingMaxRegistrations}";
      imageName = "flamingo-verifier-${workload}-enclave";

      root = pkgs.buildEnv {
        name = "${pname}-root";
        paths = [
          enclaveBins.${pname}
          pkgs.cacert
        ];
        pathsToLink = [
          "/bin"
          "/etc"
        ];
        # Nitro mounts /tmp noexec. Keep staging on the executable root filesystem,
        # not a Nix store symlink; bootstrap restores its private mode after Nix normalization.
        postBuild = pkgs.lib.optionalString (workload == "verifier") ''
          mkdir -p "$out/worker-runtime"
        '';
      };

      dockerArchive = pkgs.dockerTools.buildLayeredImage {
        name = imageName;
        tag = version;
        created = "1970-01-01T00:00:01Z";
        contents = [ root ];
        config = {
          Entrypoint = [ "/bin/${pname}" ];
          Env = env;
        };
      };

      ociImage =
        pkgs.runCommand "${pname}-oci-${version}"
          {
            nativeBuildInputs = [ pkgs.skopeo ];
          }
          ''
            mkdir -p "$out"
            skopeo --tmpdir "$TMPDIR" --insecure-policy copy \
              "docker-archive:${dockerArchive}" \
              "oci:$out:${version}"
          '';

      eif = nitroLib.buildEif {
        name = pname;
        inherit version;
        arch = "x86_64";
        kernel = nitroBlobs.kernel;
        kernelConfig = nitroBlobs.kernelConfig;
        nsmKo = nitroBlobs.nsmKo;
        init = pkgs.runCommand "nitro-init-1.5.0" { } ''
          install -m755 ${enclaveInit} "$out"
        '';
        copyToRoot = root;
        copyToRootWithClosure = true;
        entrypoint = "/bin/${pname}";
        env = pkgs.lib.concatMapStrings (var: "${var}\n") env;
      };
    in
    {
      oci = ociImage;
      inherit eif;
    };

  verifier = buildEnclaveImage {
    workload = "verifier";
    pname = "verifier-enclave";
  };
  # Bills under WIP-107, so it is only ready once its host follows a Billing Contract.
  # TODO: Make this the only verifier image once every environment has a Billing Contract.
  verifierBilling = buildEnclaveImage {
    workload = "verifier";
    pname = "verifier-enclave";
    billing = true;
  };
in
{
  verifier-oci = verifier.oci;
  verifier-eif = verifier.eif;
  verifier-billing-oci = verifierBilling.oci;
  verifier-billing-eif = verifierBilling.eif;
}
