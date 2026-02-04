# HVYM Tunnler Deployment Guide

Quick deployment guide using the automated startup script.

## Prerequisites

- Ubuntu 22.04 VPS with root access
- Domain with wildcard DNS support
- Ports 22, 80, 443 accessible

## Step 1: Configure the Startup Script

Before deploying, edit `scripts/vps_startup.sh` to set your configuration:

```bash
#=============================================================================
# CONFIGURATION - Modify these variables for your deployment
#=============================================================================

# Domain for tunnel endpoints (e.g., tunnel.yourdomain.com)
DOMAIN="tunnel.hvym.link"

# Git repository URL
REPO_URL="https://github.com/inviti8/hvym_tunnler.git"

# Git branch to deploy
REPO_BRANCH="master"

# Linux user to run the service
HVYM_USER="hvym"

# Allowed tunnel services (comma-separated)
ALLOWED_SERVICES="pintheon,ipfs"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"
```

| Variable | Description |
|----------|-------------|
| `DOMAIN` | Your tunnel domain. Clients connect via `wss://DOMAIN/connect` and get endpoints like `https://GADDR.DOMAIN` |
| `REPO_URL` | Git repository to clone. Change if using a fork |
| `REPO_BRANCH` | Branch to deploy (typically `master` or `main`) |
| `HVYM_USER` | Linux user that will own and run the service |
| `ALLOWED_SERVICES` | Service names clients can request (for access control) |
| `LOG_LEVEL` | Verbosity of logs. Use `DEBUG` for troubleshooting |

## Step 2: Configure DNS

Add these A records to your domain (replace `YOUR_VPS_IP`):

| Name | Type | Value |
|------|------|-------|
| `tunnel.yourdomain.com` | A | `YOUR_VPS_IP` |
| `*.tunnel.yourdomain.com` | A | `YOUR_VPS_IP` |

Wait 1-5 minutes for DNS propagation, then verify:

```bash
dig +short tunnel.yourdomain.com
```

## Step 3: Deploy to VPS

SSH into your VPS and run:

```bash
# Download the startup script
curl -O https://raw.githubusercontent.com/inviti8/hvym_tunnler/master/scripts/vps_startup.sh

# Make executable
chmod +x vps_startup.sh

# Run as root
sudo ./vps_startup.sh
```

The script will:
1. Install all dependencies (Python, nginx, Redis, certbot)
2. Create the hvym user
3. Clone and configure the repository
4. Generate a Stellar keypair for server identity
5. Set up systemd services
6. Configure nginx

## Step 4: Install SSL Certificate

After the script completes, it will display instructions. Follow these steps:

```bash
# Set PATH (required on some container VPS)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Request certificate with DNS challenge (required for wildcard)
certbot certonly --manual --preferred-challenges dns \
  -d tunnel.yourdomain.com -d "*.tunnel.yourdomain.com"
```

When prompted:
1. Add the TXT record to your DNS:
   - Name: `_acme-challenge.tunnel.yourdomain.com`
   - Type: `TXT`
   - Value: (certbot will provide this)
2. Wait 1-2 minutes for DNS propagation
3. Verify with: `dig +short TXT _acme-challenge.tunnel.yourdomain.com`
4. Press Enter in certbot

Then configure nginx to use the certificate:

```bash
certbot install --nginx -d tunnel.yourdomain.com -d "*.tunnel.yourdomain.com"
```

## Step 5: Verify Deployment

```bash
# Check services are running
systemctl status hvym-tunnler
systemctl status nginx

# Test health endpoint
curl https://tunnel.yourdomain.com/health

# View server identity QR code
# Visit: https://tunnel.yourdomain.com/server-identity/qr
```

## Troubleshooting

### PATH Not Found / Command Not Found

Container-based VPS (OpenVZ, LXC) often have minimal PATH. Fix:

```bash
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
```

To make permanent:

```bash
echo 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"' >> ~/.bashrc
```

### Certbot Errors

**"KeyError: 'PATH'"**
Set PATH before running certbot (see above).

**"Challenge failed"**
- Verify DNS TXT record was added correctly
- Wait longer for DNS propagation (try 2-3 minutes)
- Check with: `dig +short TXT _acme-challenge.tunnel.yourdomain.com`

**Certificate exists but nginx not using it**
Run the install step:
```bash
certbot install --nginx -d tunnel.yourdomain.com -d "*.tunnel.yourdomain.com"
```

### Port 443 Not Listening

After certbot, verify SSL is configured:

```bash
ss -tlnp | grep 443
```

If empty, reload nginx:

```bash
nginx -t && systemctl reload nginx
```

### Connection Refused from Outside

1. Check firewall:
```bash
ufw status
# Should show 80 and 443 ALLOW
```

2. Check VPS provider firewall (AWS Security Groups, etc.) - may need to open ports in their dashboard.

3. Test locally:
```bash
curl http://localhost/health
```

### Tunnel Subdomain Returns "Missing X-Stellar-Address"

The nginx map directive may not be extracting the address. Check the regex is case-insensitive:

```nginx
map $host $stellar_address {
    ~*^(?<addr>[A-Za-z0-9]+)\.tunnel\.yourdomain\.com$ $addr;
    default "";
}
```

Note: `~*` for case-insensitive, and `[A-Za-z0-9]+` to match both cases.

### View Logs

```bash
# Tunnler service logs
journalctl -u hvym-tunnler -f

# Nginx logs
tail -f /var/log/nginx/error.log

# Startup script log
cat /var/log/hvym-startup.log
```

## Updating

```bash
cd /home/hvym/hvym_tunnler
git pull
systemctl restart hvym-tunnler
```

## Testing the Tunnel

From a client machine with Python:

```bash
cd hvym_tunnler
pip install websockets aiohttp stellar-sdk hvym-stellar
python scripts/test_tunnel_client.py --server wss://tunnel.yourdomain.com/connect
```

This starts a local test server and connects through the tunnel. Visit the displayed URL to verify.
