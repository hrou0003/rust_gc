# Use .NET SDK as base
FROM mcr.microsoft.com/dotnet/sdk:9.0

# Install required packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    gdb \
    lldb \
    strace \
    valgrind \
    linux-tools-generic \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    jq \
    ripgrep \
    fd-find \
    cmake \
    python3 \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Install Rust - will be overridden by devcontainer feature but good for standalone use
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile default
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Rust components
RUN /root/.cargo/bin/rustup component add \
    rust-src \
    rust-analyzer \
    clippy \
    rustfmt

# Install useful Rust tools
RUN /root/.cargo/bin/cargo install \
    cargo-watch \
    cargo-edit \
    cargo-expand \
    cargo-outdated

# Install .NET tools
RUN dotnet tool install --global dotnet-sos \
    && dotnet tool install --global dotnet-dump \
    && dotnet tool install --global dotnet-trace \
    && dotnet tool install --global dotnet-counters \
    && dotnet tool install --global dotnet-gcdump \
    && dotnet tool install --global dotnet-monitor

# Add .NET tools to PATH
ENV PATH="$PATH:/root/.dotnet/tools"

# Configure SOS extension for native debugging
RUN /root/.dotnet/tools/dotnet-sos install

# Create directories for logs and dumps
RUN mkdir -p /var/log/gc /var/dumps /workspace

COPY ./ ./rust_gc

WORKDIR /workspace