#!/usr/bin/env sh
set -eu

REPO="botnetdotpub/botnet.pub"
APP="botctl"
VERSION="${BOTCTL_VERSION:-latest}"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command '$1'" >&2
    exit 1
  fi
}

need_cmd uname
need_cmd mktemp
need_cmd tar
need_cmd curl

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="aarch64" ;;
  *)
    echo "error: unsupported architecture '$ARCH'" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
      *)
        echo "error: linux '$ARCH' is not published yet" >&2
        exit 1
        ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64) TARGET="x86_64-apple-darwin" ;;
      aarch64) TARGET="aarch64-apple-darwin" ;;
      *)
        echo "error: macOS '$ARCH' is not published yet" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "error: unsupported OS '$OS'" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  TAG="$(
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  )"
  if [ -z "$TAG" ]; then
    echo "error: unable to resolve latest release tag" >&2
    exit 1
  fi
else
  TAG="$VERSION"
fi

ASSET="${APP}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

echo "Downloading ${ASSET} (${TAG})..."
curl -fL "$URL" -o "$TMP_DIR/$ASSET"
tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"

if [ -w /usr/local/bin ]; then
  BIN_DIR="/usr/local/bin"
else
  BIN_DIR="${HOME}/.local/bin"
  mkdir -p "$BIN_DIR"
fi

install -m 0755 "$TMP_DIR/$APP" "$BIN_DIR/$APP"

echo "Installed ${APP} to ${BIN_DIR}/${APP}"
if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
  echo "Add ${BIN_DIR} to your PATH to run '${APP}' from any shell."
fi

echo "Run: ${APP} --help"
