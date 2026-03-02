#!/usr/bin/env sh
set -eu

REPO="botnetdotpub/botnet.pub"
APP="botnet"
VERSION="${BOTNET_VERSION:-latest}"

# --- colors (disabled when not a tty) ---

if [ -t 1 ]; then
  BOLD="\033[1m"
  DIM="\033[2m"
  GREEN="\033[32m"
  RED="\033[31m"
  CYAN="\033[36m"
  RESET="\033[0m"
else
  BOLD="" DIM="" GREEN="" RED="" CYAN="" RESET=""
fi

# --- message helpers ---

info()    { printf "${DIM}  %s${RESET}\n" "$1"; }
success() { printf "${GREEN}  %s${RESET}\n" "$1"; }
error()   { printf "${RED}  error: %s${RESET}\n" "$1" >&2; exit 1; }

# --- dependency check ---

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || error "missing required command '$1'"
}

need_cmd uname
need_cmd mktemp
need_cmd tar
need_cmd curl

# --- platform detection ---

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *) error "unsupported architecture '$ARCH'" ;;
esac

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
      *) error "linux $ARCH is not published yet — open an issue at https://github.com/${REPO}/issues" ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-apple-darwin" ;;
      aarch64) TARGET="aarch64-apple-darwin" ;;
      *) error "macOS $ARCH is not published yet — open an issue at https://github.com/${REPO}/issues" ;;
    esac
    ;;
  *) error "unsupported OS '$OS' — open an issue at https://github.com/${REPO}/issues" ;;
esac

# --- resolve version ---

if [ "$VERSION" = "latest" ]; then
  TAG="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  [ -z "$TAG" ] && error "unable to resolve latest release — check https://github.com/${REPO}/releases"
else
  TAG="$VERSION"
fi

# --- download & extract ---

ASSET="${APP}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

printf "\n"
info "downloading ${BOLD}${APP}${RESET}${DIM} ${TAG} (${TARGET})"
curl -fL --progress-bar "$URL" -o "$TMP_DIR/$ASSET"
tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"

# --- install binary ---

if [ -w /usr/local/bin ]; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="${HOME}/.local/bin"
  mkdir -p "$BIN_DIR"
fi

install -m 0755 "$TMP_DIR/$APP" "$BIN_DIR/$APP"

# tildify for display
DISPLAY_PATH="$BIN_DIR/$APP"
case "$DISPLAY_PATH" in
  "$HOME"/*) DISPLAY_PATH="~${DISPLAY_PATH#"$HOME"}" ;;
esac

# --- done ---

printf "\n"
success "${BOLD}${APP}${RESET}${GREEN} ${TAG} installed to ${BOLD}${DISPLAY_PATH}${RESET}"
printf "\n"

if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
  info "${BIN_DIR} is not in your PATH. Add it with:"
  printf "\n"
  printf "  ${BOLD}export PATH=\"%s:\$PATH\"${RESET}\n" "$BIN_DIR"
  printf "\n"
fi

info "get started:"
printf "\n"
printf "  ${BOLD}${APP} --help${RESET}\n"
printf "\n"
