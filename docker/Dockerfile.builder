FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y ca-certificates \
 && update-ca-certificates \
 && apt-get update

# Build essentials
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc g++ \
    cmake ninja-build \
    git wget curl \
    libssl-dev \
    python3 \
    pkg-config \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------
# Tigress (lightweight C obfuscator)
# ----------------------------------------------------------------
WORKDIR /tmp
COPY tigress_4.0.11-1_all.deb.zip /tmp/tigress_4.0.11-1_all.deb.zip
RUN unzip -q /tmp/tigress_4.0.11-1_all.deb.zip -d /tmp && \
    dpkg -i /tmp/tigress_4.0.11-1_all.deb || apt-get -f install -y && \
    rm -f /tmp/tigress_4.0.11-1_all.deb.zip /tmp/tigress_4.0.11-1_all.deb

# Verify Tigress installation
RUN tigress --version

WORKDIR /build
