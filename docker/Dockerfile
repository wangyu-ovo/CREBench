FROM ubuntu:22.04
# Force platform to x86_64

RUN apt-get update \
 && apt-get install -y ca-certificates \
 && update-ca-certificates \
 && apt-get update

 
ARG TARGETPLATFORM
ARG NODE_VERSION=20.20.2
ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y \
    sudo curl netcat \
    build-essential pkg-config gdb gdbserver \
    python3-dev python3-pip python3-venv \
    libssl-dev libffi-dev \
    libtbb2 libtbb-dev libjpeg-dev libpng-dev libtiff-dev \
    bsdmainutils file \
    sagemath sqlmap nikto apktool \
    libc6-i386 libc6-dev:i386 gcc-multilib \
    g++-multilib \
    wget jq vim \
    p11-kit p11-kit-modules \
    rustc cargo sleuthkit \
    openjdk-17-jdk openjdk-17-jre \
    && rm -rf /var/lib/apt/lists/*

# Install a modern Node.js runtime for Codex CLI. Ubuntu 22.04's default
# nodejs package is too old for current Codex builds.
RUN curl -fsSLO https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz && \
    tar -xzf node-v${NODE_VERSION}-linux-x64.tar.gz -C /usr/local --strip-components=1 && \
    rm -f node-v${NODE_VERSION}-linux-x64.tar.gz && \
    node --version && npm --version

# Keep both `python3` and `python` available, with `python` resolving to Python 3.
RUN ln -sf /usr/bin/python3 /usr/local/bin/python

# Install radare2
WORKDIR /tmp
RUN curl -LO https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_5.8.8_amd64.deb && \
    curl -LO https://github.com/radareorg/radare2/releases/download/5.8.8/radare2-dev_5.8.8_amd64.deb && \
    apt-get install -y ./radare2_5.8.8_amd64.deb ./radare2-dev_5.8.8_amd64.deb && \
    rm -f ./radare2-dev_5.8.8_amd64.deb ./radare2_5.8.8_amd64.deb

# Install Ghidra from local archive
COPY ghidra_11.0.1_PUBLIC_20240130.zip /tmp/ghidra_11.0.1_PUBLIC_20240130.zip
RUN unzip -d /opt/ghidra /tmp/ghidra_11.0.1_PUBLIC_20240130.zip && \
    rm /tmp/ghidra_11.0.1_PUBLIC_20240130.zip
RUN mkdir /opt/ghidra/customScripts/
COPY ghidra_scripts/DecompileToJson.java  /opt/ghidra/customScripts/DecompileToJson.java
COPY ghidra_scripts/DisassembleToJson.java  /opt/ghidra/customScripts/DisassembleToJson.java
COPY ghidra_scripts/decompile.sh  /opt/ghidra/customScripts/decompile.sh
COPY ghidra_scripts/disassemble.sh  /opt/ghidra/customScripts/disassemble.sh

# Install signsrch with a fixed signature database path.
COPY signsrch /opt/signsrch/signsrch-bin
COPY signsrch.sig /opt/signsrch/signsrch.sig
RUN chmod 0755 /opt/signsrch/signsrch-bin && \
    printf '%s\n' '#!/bin/sh' \
    'exec /opt/signsrch/signsrch-bin -s /opt/signsrch/signsrch.sig "$@"' \
    > /usr/local/bin/signsrch && \
    chmod 0755 /usr/local/bin/signsrch

# Install python packages required by the reverse agent and bundled reference implementations.
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install pwntools gmpy2 angr chepy gostcrypto pyserpent

# Force Chrome to use the system CA store
RUN ln -s -f /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so
RUN ln -s -f /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib/firefox/libnssckbi.so || true

# Create a non-root user with sudo permissions
ARG HOST_UID=1000
ARG USERNAME=ctfplayer
ARG USER_UID=$HOST_UID
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Switch to user
USER $USERNAME
WORKDIR /home/$USERNAME
RUN mkdir public
