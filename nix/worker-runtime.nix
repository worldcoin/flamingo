{
  pkgs,
  worker,
}:
pkgs.runCommand "verifier-worker-runtime-${worker.version}"
  { nativeBuildInputs = [ pkgs.binutils ]; }
  ''
    # Fail the build if a toolchain/dependency change reintroduces runtime libraries.
    readelf -lW ${worker}/bin/verifier-worker > program-headers
    readelf -dW ${worker}/bin/verifier-worker > dynamic-section
    if grep -q INTERP program-headers || grep -q '(NEEDED)' dynamic-section; then
      echo "worker must not require an ELF interpreter or shared libraries" >&2
      exit 1
    fi

    install -Dm555 ${worker}/bin/verifier-worker "$out/bin/verifier-worker"
    # Deployment must additionally ensure root ownership on single-user Nix hosts.
    chmod -R a-w "$out"
  ''
