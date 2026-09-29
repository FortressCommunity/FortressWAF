#!/usr/bin/env bash
set -euo pipefail

REPO="FortressWAF/FortressWAF"
INSTALL_DIR="${INSTALL_DIR:-/opt/fortresswaf}"
CONFIG_DIR="${CONFIG_DIR:-/etc/fortresswaf}"
DATA_DIR="${DATA_DIR:-/var/lib/fortresswaf}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }
head()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

Sudo() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    sudo "$@"
  else
    "$@"
  fi
}

usage() {
  cat <<EOF
Usage: curl -sSL https://install.fortresswaf.io | bash [-- [options]]

Options:
  --docker          Install via Docker (default: auto-detect)
  --binary          Install as binary (requires Go)
  --port PORT       Set listen port (default: 80,443)
  --domain DOMAIN   Set protected domain
  --upstream URL    Set upstream backend URL
  --dir PATH        Set install directory (default: /opt/fortresswaf)
  --help            Show this help

Examples:
  curl -sSL https://install.fortresswaf.io | bash
  curl -sSL https://install.fortresswaf.io | bash -s -- --docker --domain example.com --upstream https://myapp.com
EOF
  exit 0
}

detect_os() {
  case "$(uname -s)" in
    Linux*)  OS=linux;;
    Darwin*) OS=macos;;
    *)       error "Unsupported OS: $(uname -s)"; exit 1;;
  esac

  if command -v docker &>/dev/null; then
    HAS_DOCKER=true
  else
    HAS_DOCKER=false
  fi

  if command -v cargo &>/dev/null; then
    HAS_RUST=true
  else
    HAS_RUST=false
  fi
}

install_deps() {
  head "Checking Dependencies"

  if [ "$HAS_DOCKER" = true ]; then
    info "Docker found: $(docker --version 2>/dev/null)"
    if ! docker info &>/dev/null; then
      warn "Docker daemon not running. Attempting to start..."
      Sudo systemctl start docker 2>/dev/null || Sudo service docker start 2>/dev/null || true
      sleep 2
      if docker info &>/dev/null; then
        info "Docker daemon started"
      else
        warn "Could not start Docker daemon. You may need to start it manually: sudo systemctl start docker"
      fi
    fi
  else
    warn "Docker not found"
  fi

  if [ "$HAS_RUST" = true ]; then
    info "Rust found: $(cargo --version)"
  else
    warn "Rust (cargo) not found"
  fi

  if ! command -v curl &>/dev/null; then
    error "curl required. Install: apt install curl / brew install curl"
    exit 1
  fi
}

setup_dirs() {
  head "Creating Directories"

  Sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" 2>/dev/null || {
    error "Failed to create directories. Try with sudo or set --dir to writable path"
    exit 1
  }
  info "Install: $INSTALL_DIR"
  info "Config:  $CONFIG_DIR"
  info "Data:    $DATA_DIR"
}

gen_config() {
  head "Generating Config"

  local domain="${DOMAIN:-example.com}"
  local upstream="${UPSTREAM:-http://localhost:3000}"
  local port_http="${PORT_HTTP:-80}"
  local port_https="${PORT_HTTPS:-443}"

  cat > /tmp/fortresswaf.yml <<YAML
sites:
  - name: my-site
    domains:
      - "$domain"
    upstream: "$upstream"
    port: $port_https
    tls: true
    waf_enabled: true

logging:
  level: info
  format: text
  output: stdout

tls:
  enabled: true
  min_version: "1.2"

redis:
  enabled: false

jwt:
  enabled: false

graphql:
  enabled: false

websocket:
  enabled: false

siem:
  enabled: false
YAML

  Sudo mv /tmp/fortresswaf.yml "$CONFIG_DIR/config.yml"
  info "Config written: $CONFIG_DIR/config.yml"
}

install_docker() {
  head "Installing via Docker"

  if [ "$HAS_DOCKER" = false ]; then
    warn "Docker not found. Installing Docker..."

    if [ "$OS" = linux ]; then
      if [ -t 0 ]; then
        curl -fsSL https://get.docker.com | Sudo bash
      else
        warn "Non-interactive mode. Install Docker manually then re-run: curl -fsSL https://get.docker.com | bash"
        warn "Continuing with build from source..."
      fi
    elif [ "$OS" = macos ]; then
      error "Install Docker Desktop manually: https://docker.com"
      exit 1
    fi
  fi

  if ! docker info &>/dev/null; then
    warn "Docker daemon not running. Starting..."
    Sudo dockerd &>/dev/null &
    for i in 1 2 3 4 5; do
      sleep 2
      docker info &>/dev/null && break
    done
  fi

  IMAGE="ghcr.io/fortresswaf/fortresswaf:latest"
  info "Pulling FortressWAF Docker image ($IMAGE)..."
  Sudo docker pull "$IMAGE" 2>/dev/null || {
    warn "Image not found on ghcr, building locally..."
    if [ ! -d "/tmp/fortresswaf-src" ]; then
      git clone --depth 1 "https://github.com/$REPO.git" /tmp/fortresswaf-src 2>/dev/null
    fi
    Sudo docker build -t fortresswaf:local /tmp/fortresswaf-src
    IMAGE="fortresswaf:local"
  }

  cat > "$INSTALL_DIR/docker-compose.yml" <<YAML
version: '3'
services:
  fortresswaf:
    image: $IMAGE
    container_name: fortresswaf
    restart: unless-stopped
    ports:
      - "${PORT_HTTP:-80}:80"
      - "${PORT_HTTPS:-443}:443"
    volumes:
      - $CONFIG_DIR:/etc/fortresswaf
      - $DATA_DIR:/var/lib/fortresswaf
      - ${CERTS_DIR:-$CONFIG_DIR/certs}:/etc/fortresswaf/certs
    environment:
      - TZ=UTC
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
YAML

  info "Starting FortressWAF..."
  (cd "$INSTALL_DIR" && Sudo docker compose up -d)

  echo ""
  info "FortressWAF running!"
  echo -e "  ${CYAN}http://localhost:${PORT_HTTP:-80}${NC}"
  echo -e "  ${CYAN}https://localhost:${PORT_HTTPS:-443}${NC}"
}

install_binary() {
  head "Installing as Binary"

  if [ "$HAS_RUST" = false ]; then
    error "Rust (cargo) required for binary installation. Use --docker instead."
    exit 1
  fi

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT

  info "Cloning repository..."
  git clone --depth 1 "https://github.com/$REPO.git" "$TMP_DIR/fortresswaf"

  info "Building (cargo)..."
  (cd "$TMP_DIR/fortresswaf/rust" && cargo build --release --locked)

  Sudo mv "$TMP_DIR/fortresswaf/rust/target/release/fortresswaf" "/usr/local/bin/fortresswafd"
  info "Binary: /usr/local/bin/fortresswafd"

  Sudo tee /etc/systemd/system/fortresswaf.service > /dev/null <<SYSTEMD
[Unit]
Description=FortressWAF
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fortresswafd --config $CONFIG_DIR/config.yml
Restart=always
RestartSec=5
User=root
Group=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SYSTEMD

  Sudo systemctl daemon-reload
  Sudo systemctl enable fortresswaf
  Sudo systemctl start fortresswaf

  info "Service started: fortresswaf"
}

show_summary() {
  head "Installation Complete"

  echo -e "  ${GREEN}FortressWAF${NC} is now installed and running."
  echo ""
  echo -e "  Config:  ${CYAN}$CONFIG_DIR/config.yml${NC}"
  echo -e "  Data:    ${CYAN}$DATA_DIR${NC}"
  echo ""
  echo -e "  ${YELLOW}Next steps:${NC}"
  echo -e "  1. Edit config:    ${CYAN}sudo nano $CONFIG_DIR/config.yml${NC}"
  echo -e "  2. Restart:        ${CYAN}sudo systemctl restart fortresswaf${NC}"
  echo -e "     (or Docker):    ${CYAN}cd $INSTALL_DIR && sudo docker compose restart${NC}"
  echo -e "  3. Check logs:     ${CYAN}sudo journalctl -u fortresswaf -f${NC}"
  echo -e "     (or Docker):    ${CYAN}sudo docker compose logs -f${NC}"
  echo -e "  4. Dashboard:      ${CYAN}http://localhost:${PORT_HTTP:-80}${NC}"
  echo ""
  echo -e "  ${GREEN}Thank you for using FortressWAF!${NC}"
}

main() {
  printf "\n"
  printf "${CYAN}  ______                   _                                        __        _  __${NC}\n"
  printf "${CYAN} |  ____|                 | |                                      / _|      | |/ _|${NC}\n"
  printf "${CYAN} | |__ ___  ___ _ __ ___ | |_ ___ _ __  ___    ___ _ __ __ _  ___| |_ ______| | |_ ${NC}\n"
  printf "${CYAN} |  __/ _ \\/ __| '_ \\\` _ \\| __/ _ \\ '_ \\/ __|  / __| '__/ _\\\` |/ _ \\  _|______| |  _|${NC}\n"
  printf "${CYAN} | | |  __/\\__ \\ | | | | | ||  __/ | | \\__ \\ | (__| | | (_| |  __/ |        | | |${NC}\n"
  printf "${CYAN} |_|  \\___||___/_| |_| |_|\\__\\___|_| |_|___/  \\___|_|  \\__, |\\___|_|        |_|_|${NC}\n"
  printf "${CYAN}                                                         __/ |${NC}\n"
  printf "${CYAN}                                                        |___/ ${NC}\n"
  printf "\n"
  printf "  ${GREEN}Enterprise Web Application Firewall${NC}\n"
  printf "  Version: ${YELLOW}v1.1.0${NC}\n"
  printf "\n"

  for arg in "$@"; do
    case "$arg" in
      --help) usage;;
      --docker) INSTALL_METHOD=docker;;
      --binary) INSTALL_METHOD=binary;;
      --port=*) PORT_HTTP="${arg#*=}"; PORT_HTTPS="$PORT_HTTP";;
      --domain=*) DOMAIN="${arg#*=}";;
      --upstream=*) UPSTREAM="${arg#*=}";;
      --dir=*) INSTALL_DIR="${arg#*=}";;
    esac
  done

  detect_os
  install_deps

  setup_dirs

  if [ -f "$CONFIG_DIR/config.yml" ]; then
    warn "Config already exists: $CONFIG_DIR/config.yml"
    if [ -t 0 ]; then
      read -rp "Overwrite? [y/N] " yn
      case "$yn" in
        [Yy]*) gen_config;;
        *)     info "Using existing config";;
      esac
    else
      info "Skipping config overwrite (non-interactive). Delete $CONFIG_DIR/config.yml to regenerate."
    fi
  else
    gen_config
  fi

  if [ -z "${INSTALL_METHOD:-}" ]; then
    if [ "$HAS_DOCKER" = true ]; then
      INSTALL_METHOD=docker
    elif [ "$HAS_RUST" = true ]; then
      INSTALL_METHOD=binary
    else
      INSTALL_METHOD=docker
      warn "Neither Docker nor Rust found. Will install Docker first."
    fi
  fi

  if [ "$INSTALL_METHOD" = docker ]; then
    install_docker
  else
    install_binary
  fi

  show_summary
}

main "$@"
