{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
  verifierModels,
}:
let
  nitroLib = nitro-util.lib.${system};
  nitroBlobs = nitroLib.blobs.x86_64;

  buildEnclaveImage =
    {
      workload,
      pname,
      extraRoot ? [ ],
    }:
    let
      version = enclaveBins.${pname}.version;
      imageName = "flamingo-verifier-${workload}-enclave";

      root = pkgs.buildEnv {
        name = "${pname}-root";
        paths = [
          enclaveBins.${pname}
          pkgs.cacert
        ]
        ++ extraRoot;
        pathsToLink = [
          "/bin"
          "/etc"
          "/models"
        ];
      };

      dockerArchive = pkgs.dockerTools.buildLayeredImage {
        name = imageName;
        tag = version;
        created = "1970-01-01T00:00:01Z";
        contents = [ root ];
        config = {
          Entrypoint = [ "/bin/${pname}" ];
          Env = [
            "RUST_LOG=info"
            "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
          ];
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
        init = nitroBlobs.init;
        copyToRoot = root;
        copyToRootWithClosure = true;
        entrypoint = "/bin/${pname}";
        env = ''
          RUST_LOG=info
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
        '';
      };
    in
    {
      oci = ociImage;
      inherit eif;
    };

  verifier = buildEnclaveImage {
    workload = "verifier";
    pname = "verifier-enclave";
    extraRoot = [ verifierModels ];
  };
in
{
  verifier-oci = verifier.oci;
  verifier-eif = verifier.eif;
}
