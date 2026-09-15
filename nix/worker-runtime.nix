{
  pkgs,
  worker,
}:
pkgs.runCommand "verifier-worker-runtime-${worker.version}"
  { nativeBuildInputs = [ pkgs.pax-utils ]; }
  ''
    mkdir -p "$out/bin"
    cp ${worker}/bin/verifier-worker "$out/bin/verifier-worker"

    # Resolve ELF dependencies without executing the worker. Copy only the
    # interpreter and shared libraries, retaining their absolute Nix paths.
    lddtree -l ${worker}/bin/verifier-worker > runtime-paths
    while IFS= read -r path; do
      if [ "$path" = "${worker}/bin/verifier-worker" ]; then
        continue
      fi
      case "$path" in
        /nix/store/*) ;;
        *) echo "unexpected runtime dependency: $path" >&2; exit 1 ;;
      esac
      mkdir -p "$out$(dirname "$path")"
      cp -L "$path" "$out$path"
    done < runtime-paths

    # Deployment must additionally ensure root ownership on single-user Nix hosts.
    chmod -R a-w "$out"
  ''
