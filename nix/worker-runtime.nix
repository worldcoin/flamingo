{
  pkgs,
  worker,
  models,
}:
let
  # Only the executable's runtime references, never the build closure or host store.
  closure = pkgs.closureInfo { rootPaths = [ worker ]; };
in
pkgs.runCommand "verifier-worker-runtime-${worker.version}" { } ''
  mkdir -p "$out/bin" "$out/nix/store" "$out/models"
  cp ${worker}/bin/verifier-worker "$out/bin/verifier-worker"
  cp ${models}/models/*.onnx "$out/models/"
  while IFS= read -r path; do
    if [ "$path" != "${worker}" ]; then
      cp -aL "$path" "$out/nix/store/"
    fi
  done < ${closure}/store-paths
  # Deployment must additionally ensure root ownership, including on single-user Nix hosts.
  chmod -R a-w "$out"
''
