# Base container image for non-KVM Helios PR CI jobs (ubuntu-24.04 amd64 and arm64).
# Pre-bakes apt packages, the pinned Rust nightly toolchain, and host CI binaries
# so PR check/test/wasm-build jobs skip per-job package and tool installation.
#
# Also builds the TPM2-enabled RISC-V EDK2 OVMF firmware (`RiscVVirtQemu`) in an
# isolated builder stage so only the 32 MiB flash images enter the final image
# (helios#1292). Ubuntu 24.04's distro `qemu-efi-riscv64` omits `TPM2_ENABLE`.

FROM ubuntu:24.04 AS edk2-riscv64

ARG DEBIAN_FRONTEND=noninteractive
ARG EDK2_TAG=edk2-stable202611

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        gcc-riscv64-linux-gnu \
        git \
        iasl \
        python3 \
        uuid-dev \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    git clone --depth 1 --branch "${EDK2_TAG}" https://github.com/tianocore/edk2.git /src/edk2; \
    cd /src/edk2; \
    git submodule update --init --depth 1; \
    make -C BaseTools -j"$(nproc)"; \
    bash -c 'set -eo pipefail; \
        export WORKSPACE=/src/edk2; \
        export PACKAGES_PATH=/src/edk2; \
        export PYTHON_COMMAND=python3; \
        export GCC_RISCV64_PREFIX=riscv64-linux-gnu-; \
        source edksetup.sh; \
        set -u; \
        build -a RISCV64 -t GCC -b RELEASE -n "$(nproc)" \
            -p OvmfPkg/RiscVVirt/RiscVVirtQemu.dsc \
            -D RISCVVIRT_PEI_BOOTING=TRUE \
            -D TPM2_ENABLE=TRUE \
            -D TPM2_CONFIG_ENABLE=TRUE'; \
    mkdir -p /out/usr/share/helios-edk2-riscv64; \
    cp /src/edk2/Build/RiscVVirtQemu/RELEASE_GCC/FV/RISCV_VIRT_CODE.fd \
        /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_CODE.fd; \
    cp /src/edk2/Build/RiscVVirtQemu/RELEASE_GCC/FV/RISCV_VIRT_VARS.fd \
        /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_VARS.fd; \
    truncate -s 32M \
        /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_CODE.fd \
        /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_VARS.fd; \
    test -s /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_CODE.fd; \
    test -s /out/usr/share/helios-edk2-riscv64/RISCV_VIRT_VARS.fd

FROM ubuntu:24.04

LABEL org.opencontainers.image.source=https://github.com/helios-kernel/helios

ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive
ARG RUST_TOOLCHAIN=nightly-2026-11-03
ARG CARGO_NEXTEST_VERSION=0.9.152
ARG CARGO_DENY_VERSION=0.22.0
ARG WASM_TOOLS_VERSION=1.263.0
ARG UV_VERSION=0.13.9
ARG ZIG_VERSION=0.13.0
ARG GH_VERSION=2.105.0
ARG ORAS_VERSION=1.4.0
ARG WASI_SDK_VERSION=34

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        acl \
        attr \
        btrfs-progs \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        erofs-utils \
        file \
        git \
        gzip \
        jq \
        just \
        libclang-dev \
        libudev-dev \
        lld \
        llvm \
        ninja-build \
        pkg-config \
        python3 \
        python3-venv \
        sudo \
        tar \
        unzip \
        xz-utils \
        zstd \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    WASI_SDK_PATH=/opt/wasi-sdk-34 \
    PATH="/usr/local/cargo/bin:/usr/local/zig:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
    && rustup component add rust-src clippy rustfmt llvm-tools \
    && rustup target add \
        aarch64-unknown-none \
        riscv64gc-unknown-none-elf \
        x86_64-unknown-none \
        wasm32-wasip3 \
        wasm32-wasip1-threads \
        wasm32-wasip1 \
        wasm32-unknown-unknown \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu \
    && chmod -R a+rX "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN set -eu; \
    case "${TARGETARCH}" in \
        amd64) \
            gnu_triple="x86_64-unknown-linux-gnu"; \
            musl_triple="x86_64-unknown-linux-musl"; \
            linux_arch="x86_64"; \
            zig_arch="x86_64"; \
            nextest_sha="d039b43c3e0958441b6ad0a39c8884d018b3d2e8fb9928f209074b1100b5e17a"; \
            deny_sha="98c56e6a408bfa5c3c60744b6015aaa6aa08f743fdeb88386d06fca035bb1786"; \
            wasm_tools_sha="21c036c1740a0552124c79c6e2170cb61c5b016005671a6d5bc06cf642165431"; \
            uv_sha="a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5"; \
            zig_sha="d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"; \
            gh_sha="79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f"; \
            oras_sha="d8e1dce2fd8ce996f1d901845b688eb0cf505a6082897606f053825bb47935d1"; \
            wasi_sdk_arch="x86_64"; \
            wasi_sdk_sha="b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4"; \
            ;; \
        arm64) \
            gnu_triple="aarch64-unknown-linux-gnu"; \
            musl_triple="aarch64-unknown-linux-musl"; \
            linux_arch="aarch64"; \
            zig_arch="aarch64"; \
            nextest_sha="ca1f81a5b86533eb45ab97e0064aa88e925e53aab9a698ca6331a7cad1f85f07"; \
            deny_sha="4818d44cdcac285776336504fca722493ab634d3377b94a462e98aad3f41484a"; \
            wasm_tools_sha="773b5e6bf957f0d93a9a337c9c5fc4c35509706301a80799f57a76fa367fd1ca"; \
            uv_sha="0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d"; \
            zig_sha="041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556"; \
            gh_sha="b1278c75107423d818f1937fd92cafc9e5e9b606631568f68d7fb816f5885a02"; \
            oras_sha="0791fc200831563e498638d30e8ee8aac20ad1da2610760120fe3f770e12a8a4"; \
            wasi_sdk_arch="arm64"; \
            wasi_sdk_sha="f7e243dff54d60bcc576e94d6166b69f410f2500ae4a9ceef34315be10e77971"; \
            ;; \
        *) \
            echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; \
            exit 1; \
            ;; \
    esac; \
    work="$(mktemp -d)"; \
    trap 'rm -rf "$work"' EXIT; \
    fetch() { \
        curl --fail --silent --show-error --location --retry 5 --retry-all-errors --output "$2" "$1"; \
        echo "$3  $2" | sha256sum --check -; \
    }; \
    fetch "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-${CARGO_NEXTEST_VERSION}/cargo-nextest-${CARGO_NEXTEST_VERSION}-${gnu_triple}.tar.gz" \
        "${work}/nextest.tar.gz" "${nextest_sha}"; \
    tar -xzf "${work}/nextest.tar.gz" -C /usr/local/cargo/bin cargo-nextest; \
    fetch "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/cargo-deny-${CARGO_DENY_VERSION}-${musl_triple}.tar.gz" \
        "${work}/cargo-deny.tar.gz" "${deny_sha}"; \
    tar -xzf "${work}/cargo-deny.tar.gz" --strip-components=1 -C /usr/local/cargo/bin \
        "cargo-deny-${CARGO_DENY_VERSION}-${musl_triple}/cargo-deny"; \
    fetch "https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VERSION}/wasm-tools-${WASM_TOOLS_VERSION}-${linux_arch}-linux.tar.gz" \
        "${work}/wasm-tools.tar.gz" "${wasm_tools_sha}"; \
    tar -xzf "${work}/wasm-tools.tar.gz" --strip-components=1 -C /usr/local/bin \
        "wasm-tools-${WASM_TOOLS_VERSION}-${linux_arch}-linux/wasm-tools"; \
    fetch "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${gnu_triple}.tar.gz" \
        "${work}/uv.tar.gz" "${uv_sha}"; \
    tar -xzf "${work}/uv.tar.gz" --strip-components=1 -C /usr/local/bin \
        "uv-${gnu_triple}/uv" "uv-${gnu_triple}/uvx"; \
    fetch "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${zig_arch}-${ZIG_VERSION}.tar.xz" \
        "${work}/zig.tar.xz" "${zig_sha}"; \
    mkdir -p /usr/local/zig; \
    tar -xJf "${work}/zig.tar.xz" --strip-components=1 -C /usr/local/zig; \
    ln -sf /usr/local/zig/zig /usr/local/bin/zig; \
    fetch "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
        "${work}/gh.tar.gz" "${gh_sha}"; \
    tar -xzf "${work}/gh.tar.gz" --strip-components=2 -C /usr/local/bin \
        "gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh"; \
    fetch "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${TARGETARCH}.tar.gz" \
        "${work}/oras.tar.gz" "${oras_sha}"; \
    tar -xzf "${work}/oras.tar.gz" -C /usr/local/bin oras; \
    fetch "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/wasi-sdk-${WASI_SDK_VERSION}.0-${wasi_sdk_arch}-linux.tar.gz" \
        "${work}/wasi-sdk.tar.gz" "${wasi_sdk_sha}"; \
    mkdir -p "${WASI_SDK_PATH}"; \
    tar -xzf "${work}/wasi-sdk.tar.gz" --strip-components=1 -C "${WASI_SDK_PATH}"; \
    chmod -R a+rX "${WASI_SDK_PATH}"; \
    chmod 0755 /usr/local/cargo/bin/cargo-nextest /usr/local/cargo/bin/cargo-deny /usr/local/bin/wasm-tools /usr/local/bin/uv /usr/local/bin/uvx /usr/local/bin/gh /usr/local/bin/oras; \
    rustc --version; \
    cargo --version; \
    just --version; \
    cmake --version; \
    ninja --version; \
    clang --version; \
    printf '#include <stdint.h>\nuint32_t x = 1;\n' | clang -x c -fsyntax-only --target=wasm32 -ffreestanding -; \
    cargo nextest --version; \
    cargo deny --version; \
    wasm-tools --version; \
    uv --version; \
    zig version; \
    gh --version; \
    oras version; \
    setfacl --version; \
    mkfs.btrfs --version; \
    command -v mkfs.erofs

COPY --from=edk2-riscv64 /out/usr/share/helios-edk2-riscv64 /usr/share/helios-edk2-riscv64

RUN test -s /usr/share/helios-edk2-riscv64/RISCV_VIRT_CODE.fd \
    && test -s /usr/share/helios-edk2-riscv64/RISCV_VIRT_VARS.fd
