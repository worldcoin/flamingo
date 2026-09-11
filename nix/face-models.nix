{
  pkgs,
}:
let
  lib = pkgs.lib;

  # Revision and digest are reviewed as one pair: the revision says which Hugging Face
  # snapshot to take the file from, the digest pins the bytes, and the digest is what ends
  # up measured into PCR0.
  sources = {
    "face_embedding_generator.onnx" = {
      repo = "FaceEmbeddingGenerator";
      rev = "5fcbd28a5304ca1f1a186c300261ebccafb5eeec";
      hash = "3a5807e26adff1a6a25ac50dc0139cb6c5c87cbcb0594bd7065fa29bd185e19c";
    };
    "rgbnet.onnx" = {
      repo = "RGBNet";
      rev = "e81cff53eaeb3881d18415407fc1a7b07c2b0600";
      hash = "25bfb4cd007f616da02e6a8484121f97a5bced67f0485d234f88220958603638";
    };
  };

  modelUrl =
    file: source: "https://huggingface.co/Worldcoin/${source.repo}/resolve/${source.rev}/onnx/${file}";

  # A derivation cannot hold the token these repositories need without putting it in the
  # store, and `impureEnvVars` reads the builder's environment, not the caller's. So
  # scripts/fetch-face-models.sh curls each file and adds it to the store under this exact
  # fixed-output hash, leaving the fetch already satisfied.
  fetchModel =
    file: source:
    pkgs.fetchurl {
      name = file;
      url = modelUrl file source;
      sha256 = source.hash;
    };

  package = pkgs.runCommandLocal "flamingo-verifier-models" { } (
    ''
      mkdir -p $out/models
    ''
    + lib.concatStrings (
      lib.mapAttrsToList (file: source: "cp ${fetchModel file source} $out/models/${file}\n") sources
    )
  );
in
{
  inherit package;

  # Where scripts/fetch-face-models.sh reads the model URLs and store paths from, so the source of
  # truth for a revision stays in one place.
  metadata = lib.mapAttrs (file: source: {
    url = modelUrl file source;
    inherit (source) hash;
    storePath = (fetchModel file source).outPath;
  }) sources;
}
