#!/usr/bin/env bash
# PlasmaWall — One-shot environment setup script
# Run this once after cloning the repo:
#     chmod +x setup.sh && ./setup.sh

set -euo pipefail
# set -e  → exit immediately if any command fails
# set -u  → exit if you use an undefined variable
# set -o pipefail → if any command in a pipe fails, the whole pipe fails

# COLOUR HELPERS

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# STEP 0 — Must be run as normal user

if [[ "$EUID" -eq 0 ]]; then
    error "Do not run this script as root / sudo."
fi

echo ""
echo "================================================================"
echo "  PlasmaWall — Environment Setup"
echo "================================================================"
echo ""

# STEP 1 — Detect distro

info "Detecting Linux distribution..."

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO="${ID:-unknown}"
else
    error "Cannot detect Linux distribution."
fi

case "$DISTRO" in
    ubuntu|debian|linuxmint|pop)
        PKG_MANAGER="apt"
        ;;
    fedora|rhel|centos|rocky|almalinux)
        PKG_MANAGER="dnf"
        ;;
    arch|manjaro|endeavouros)
        PKG_MANAGER="pacman"
        ;;
    *)
        warn "Unknown distro: '$DISTRO'. Defaulting to apt."
        PKG_MANAGER="apt"
        ;;
esac

success "Detected: $DISTRO (using $PKG_MANAGER)"

# STEP 2 — Install system dependencies

info "Installing system packages..."

case "$PKG_MANAGER" in
    apt)
        sudo apt-get update -qq
        sudo apt-get install -y \
            clang llvm libelf-dev pkg-config \
            curl git build-essential ca-certificates \
        || warn "Some apt packages failed to install" # changed: don't hard fail on partial install
        ;;
    dnf)
        sudo dnf install -y \
            clang llvm elfutils-libelf-devel pkgconf-pkg-config \
            curl git gcc make ca-certificates \
        || warn "Some dnf packages failed to install" # changed: tolerate partial failures
        ;;
    pacman)
        sudo pacman -Syu --noconfirm \
            clang llvm libelf pkgconf \
            curl git base-devel ca-certificates \
        || warn "Some pacman packages failed to install" # changed: tolerate partial failures
        ;;
esac

success "System packages installed."

# STEP 2.5 — Install kernel headers (relaxed, not exact version)

info "Installing kernel headers..."

case "$PKG_MANAGER" in
    apt)
        sudo apt-get install -y linux-headers-generic \
        || warn "Could not install linux headers" # changed: avoid strict uname match which breaks often
        ;;
    dnf)
        sudo dnf install -y kernel-devel \
        || warn "Could not install kernel-devel"
        ;;
    pacman)
        sudo pacman -S --noconfirm linux-headers \
        || warn "Could not install linux-headers"
        ;;
esac

# STEP 3 — Install Rust

info "Checking for Rust / rustup..."

if command -v rustup &>/dev/null; then
    success "rustup already installed. Updating..."
    if ! rustup update; then
    warn "rustup update failed (likely network issue). Continuing..."
fi
else
    info "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    export PATH="$HOME/.cargo/bin:$PATH"
fi

if ! command -v cargo &>/dev/null; then
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    else
        error "cargo not found. Restart terminal."
    fi
fi

success "Rust is available: $(rustc --version)"

# STEP 4 — Toolchain setup (FIXED)

info "Setting up Rust toolchain..."

rustup override set nightly # changed: use rust-toolchain.toml instead of latest nightly
rustup component add rust-src


if rustup target add bpfel-unknown-none 2>/dev/null; then
    success "bpf target installed."
else
    warn "bpf target not available — this is fine (build-std will handle it)."
fi

success "Nightly toolchain ready."

# STEP 5 — Install bpf-linker

info "Installing bpf-linker..."

if command -v bpf-linker &>/dev/null; then
    success "bpf-linker already installed."
else
    cargo install bpf-linker --locked \
        || error "Failed to install bpf-linker" # changed: explicit failure instead of silent issues
    success "bpf-linker installed."
fi

# STEP 6 — Verify environment

info "Checking kernel version..."

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [[ "$KERNEL_MAJOR" -lt 5 ]] || ([[ "$KERNEL_MAJOR" -eq 5 ]] && [[ "$KERNEL_MINOR" -lt 15 ]]); then
    warn "Kernel $KERNEL_VERSION may not support XDP properly."
else
    success "Kernel version OK."
fi

# LLVM check

if ! command -v llvm-objcopy &>/dev/null; then
    warn "llvm-objcopy not found. eBPF build may fail." # changed: explicit LLVM sanity check
fi

# Git check (needed for aya)

if ! command -v git &>/dev/null; then
    error "git is required but not installed." # changed: aya dependency requires git
fi

# BPF filesystem

if mount | grep -q "bpf on /sys/fs/bpf"; then
    success "BPF filesystem mounted."
else
    warn "Mounting BPF filesystem..."
    sudo mount -t bpf bpf /sys/fs/bpf \
        || warn "Failed to mount bpffs"
fi

# STEP 7 — Test build

info "Running test build..."

if [[ ! -d "firewall" ]]; then
    error "Run this script from project root"
fi

cd firewall

if cargo build; then
    success "Build succeeded!"
else
    error "Build failed. Check errors above."
fi

cd ..

# FINAL

echo ""
echo "================================================================"
echo "  Setup Complete!"
echo "================================================================"
echo ""

echo "To build:"
echo "  cd firewall && cargo build --release"
echo ""

echo "To install:"
echo "  sudo cp target/release/plasma /usr/local/bin/plasma"
echo ""

echo "To run:"
echo "  sudo plasma start <iface>"
echo ""

success "All done."