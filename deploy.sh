#!/bin/bash
# One-command deploy: ./deploy.sh user@host [-p port] [--vmess "vmess://..."]
#
# Examples:
#   ./deploy.sh root@1.2.3.4
#   ./deploy.sh root@1.2.3.4 -p 8080
#   ./deploy.sh root@1.2.3.4 --vmess "vmess://eyJ..."

set -e

if [ -z "$1" ] || [[ "$1" == -* ]]; then
  echo "Usage: ./deploy.sh user@host [-p proxy_port] [--vmess \"vmess://...\"]"
  exit 1
fi

SERVER="$1"; shift

# Parse optional args
PROXY_PORT=3080
VMESS_URI=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) PROXY_PORT="$2"; shift 2 ;;
    --vmess) VMESS_URI="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="socks5-proxy-linux"

# Build if needed
if [ ! -f "$SCRIPT_DIR/$BINARY" ]; then
  echo "Compiling for Linux..."
  cd "$SCRIPT_DIR" && bun build --compile --target=bun-linux-x64 index.ts --outfile "$BINARY"
fi

# Generate remote install script
SETUP_SCRIPT=$(mktemp)
cat > "$SETUP_SCRIPT" << EOF
#!/bin/bash
set -e

sudo mv /tmp/socks5-proxy /usr/local/bin/socks5-proxy
sudo chmod +x /usr/local/bin/socks5-proxy

sudo tee /etc/socks5-proxy.env > /dev/null << 'CONF'
PORT=$PROXY_PORT
HOST=0.0.0.0
VMESS=$VMESS_URI
CONF

sudo tee /usr/local/bin/socks5-proxy-start > /dev/null << 'WRAPPER'
#!/bin/bash
source /etc/socks5-proxy.env 2>/dev/null || true
ARGS="-p \${PORT:-3080} -h \${HOST:-0.0.0.0}"
[ -n "\$VMESS" ] && ARGS="\$ARGS --vmess \$VMESS"
exec /usr/local/bin/socks5-proxy \$ARGS
WRAPPER
sudo chmod +x /usr/local/bin/socks5-proxy-start

sudo tee /etc/systemd/system/socks5-proxy.service > /dev/null << 'SVC'
[Unit]
Description=SOCKS5/HTTP Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/socks5-proxy-start
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SVC

sudo systemctl daemon-reload
sudo systemctl enable socks5-proxy
sudo systemctl restart socks5-proxy
sleep 1

echo ""
echo "========================================="
sudo systemctl is-active socks5-proxy > /dev/null && echo "  ✅ Proxy running on :$PROXY_PORT" || echo "  ❌ Failed to start"
echo "  Config: /etc/socks5-proxy.env"
echo "  Logs:   journalctl -u socks5-proxy -f"
echo "========================================="
EOF

echo "Deploying to $SERVER ..."

# Upload binary + script
scp "$SCRIPT_DIR/$BINARY" "$SERVER:/tmp/socks5-proxy"
scp "$SETUP_SCRIPT" "$SERVER:/tmp/socks5-proxy-setup.sh"
rm "$SETUP_SCRIPT"

# Run setup with interactive SSH (supports sudo password prompt)
ssh -t "$SERVER" "bash /tmp/socks5-proxy-setup.sh && rm /tmp/socks5-proxy-setup.sh"

echo ""
echo "Done! Test it:"
echo "  curl -x socks5://$SERVER:$PROXY_PORT https://httpbin.org/get"
