# syntax=docker/dockerfile:1
# Base image for deploy repos, which add the paired EIF at /home/enclave.eif.
FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
USER root
WORKDIR /app

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package flamingo-verifier-provisioner

FROM public.ecr.aws/amazonlinux/amazonlinux:2023
RUN dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
    awscli-2 tar gzip binutils && dnf clean all
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/flamingo-verifier-provisioner \
    /usr/local/bin/flamingo-verifier-provisioner
ENTRYPOINT ["/usr/local/bin/flamingo-verifier-provisioner"]
