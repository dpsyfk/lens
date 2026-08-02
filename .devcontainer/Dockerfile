FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        curl \
        jq \
        libelf-dev \
        libssl-dev \
        linux-libc-dev \
        lld \
        llvm \
        pkg-config \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*
