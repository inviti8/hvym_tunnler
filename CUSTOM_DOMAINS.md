# Custom Domain Support for HVYM Tunnler

## Problem Statement

Currently, every tunnel endpoint is assigned a subdomain based on the client's Stellar address:

```
https://GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12345678.tunnel.hvym.link
```

This is deterministic, collision-free, and requires no registration -- but it's not human-friendly. Some users (artists, galleries, DAOs, project teams) will want to serve their Pintheon gateway on a domain they own, e.g.:

```
https://gallery.example.com  -->  tunnels to their local Pintheon
```

This document scopes and plans adding custom domain support to hvym_tunnler.

---

## Current Architecture (Summary)

| Component | How it works today |
|---|---|
| **DNS** | Wildcard `*.tunnel.hvym.link` A record -> VPS IP |
| **SSL** | Wildcard cert via certbot DNS-01 challenge |
| **Nginx** | Regex extracts Stellar address from subdomain, sets `X-Stellar-Address` header |
| **FastAPI** | `/proxy/{path}` reads `X-Stellar-Address`, forwards to active WebSocket tunnel |
| **Registry** | Redis maps Stellar address -> active tunnel session |
| **Client auth** | Stellar JWT challenge-response; Stellar address = identity |

**Key constraint**: The Stellar address IS the routing key throughout the entire pipeline. Custom domains need to resolve to a Stellar address before they can enter the existing forwarding path.

---

## Design Goals

1. **User owns the domain** -- We never manage DNS for the user. They CNAME to us; we serve their traffic.
2. **Automatic TLS** -- Custom domains get valid HTTPS certificates without manual intervention.
3. **Minimal server changes** -- Reuse the existing forwarding path. Custom domains are an alias layer on top of Stellar address routing.
4. **Secure verification** -- Prove domain ownership before accepting traffic.
5. **Soroban-ready** -- The domain registry should be designed so it can migrate to on-chain storage later (already referenced in `SEAMLESS_TUNNELING.md`).
6. **Metavinci integration** -- Expose domain management in the tray app UI.

---

## Competitive Analysis

How other tunneling services handle custom domains, and what we can learn from each.

### ngrok

ngrok is the industry standard and has the most mature custom domain implementation.

**How it works**:
- Users reserve a domain via the dashboard or REST API (`POST /reserved_domains`).
- ngrok generates a unique per-domain CNAME target: `<random>.<random>.ngrok-cname.com`. The user adds this CNAME at their DNS provider.
- SSL is automatic via Let's Encrypt. Standard domains use HTTP-01 challenges; wildcard domains use DNS-01 (requiring a second CNAME for `_acme-challenge`).
- Alternatively, users can upload their own certificates (EV certs, internal CA, etc.).
- Full CRUD API with SDK libraries for Python, TypeScript, Ruby, plus Terraform and Pulumi providers.

**Key details**:
- No apex/root domain support (e.g. bare `example.com`) -- CNAME-only, which is a hard DNS limitation.
- Wildcard domains supported (`*.app.example.com`) on paid plans.
- Cert provisioning is async, can take up to 10 minutes.
- DNS verification is implicit -- the CNAME itself proves control. No separate TXT challenge for standard domains.
- Enterprise tier adds explicit TXT-based domain ownership verification for organizational governance.

**Pricing**: Custom domains require Pay-as-you-go plan ($20/mo base). Each domain costs ~$7.44/mo at 24/7 usage. Free tier gets only an auto-assigned `*.ngrok-free.dev` subdomain.

**Takeaways for us**:
- The per-domain unique CNAME target pattern (`*.ngrok-cname.com`) is elegant -- it allows ngrok to route traffic without exposing server IPs. We could do something similar with per-address CNAME targets if we wanted to hide our VPS IP, but it's not necessary at our scale.
- CNAME-as-verification (no separate TXT step) is simpler for users and is sufficient when combined with authenticated registration. ngrok's logic: if you can set the CNAME and you hold the API key, you own the domain.
- API-first domain management is important. ngrok's full REST API means every operation is automatable. Our planned `/api/domains` CRUD follows this same pattern.
- The "no apex domain" limitation is universal for CNAME-based approaches. We should document this limitation clearly.

---

### Pinggy

Pinggy is the service we're replacing in Metavinci, so understanding their approach is especially relevant.

**How it works**:
- Custom domains are configured through the Pinggy web dashboard only (no API or CLI).
- For subdomains: User adds a CNAME pointing to a Pinggy-provided target (e.g. `ahsu9ol.a.pinggy.link`).
- For apex/root domains: Pinggy provides a **relay architecture** -- the user adds a TXT record for ownership verification, then A + AAAA records pointing to a Pinggy relay server in a chosen region.
- SSL is automatic via Let's Encrypt, but the user must click "Issue Certificate" in the dashboard.
- Active tunnels must be **stopped** before certificate issuance. Certs take up to 60 seconds to issue and up to 7 minutes to propagate across Pinggy's infrastructure.

**Key details**:
- Dashboard-only domain management. No programmatic API for domain CRUD.
- Cloudflare proxy must be disabled (DNS-only mode) if user's DNS goes through Cloudflare.
- Relay architecture for apex domains is a unique approach -- most competitors simply don't support apex domains at all.
- Pro plan includes only 1 custom domain. Enterprise required for more.

**Pricing**: Custom domains require Pro plan (~$2.50-3/mo). Free tier is random subdomains with 60-minute tunnel timeout.

**Takeaways for us**:
- Pinggy's lack of API-based domain management is a clear weakness. Users manage domains through a web UI with no automation path. Our API-first approach is already better.
- The "must stop tunnels to issue certs" limitation is a poor UX. Our certbot HTTP-01 approach avoids this since we control the webroot directly -- no need to disrupt active tunnels.
- Pinggy's relay architecture for apex domains is interesting but complex. We should note that apex domain support is possible but not a v1 priority.
- The 7-minute cert propagation delay is worth noting as something to avoid. With our single-server Nginx setup, cert activation is near-instant after a reload.

---

### Cloudflare Tunnel

Cloudflare Tunnel is architecturally different (it's not a traditional tunnel service) but has relevant patterns.

**How it works**:
- The domain must be an active zone in the user's Cloudflare account (Cloudflare manages DNS).
- A CNAME record points the hostname to `<tunnel-uuid>.cfargotunnel.com`.
- DNS records can be created automatically via CLI: `cloudflared tunnel route dns <tunnel> <hostname>`.
- Multiple hostnames can map to one tunnel using ingress rules (hostname -> backend service routing).
- SSL is fully managed -- Cloudflare provisions Universal SSL at their edge. No user-side cert management at all.
- Full REST API + CLI for tunnel and DNS management.

**Key details**:
- `cfargotunnel.com` CNAMEs are **not publicly routable** -- they only proxy traffic for DNS records within the same Cloudflare account. This prevents UUID hijacking.
- Wildcard domains supported on all plans.
- No separate domain verification step. Security relies on the domain being in your Cloudflare account (you proved ownership when adding the zone).
- Two-tier credential model: `cert.pem` (account-wide, for management) vs. `<uuid>.json` (tunnel-specific, for running). Principle of least privilege.
- QUIC (TLS 1.3) as the default tunnel protocol with HTTP/2 fallback. 4 parallel HA connections per tunnel.

**Pricing**: Completely free for all plans. No bandwidth caps. No per-domain charges.

**Takeaways for us**:
- Cloudflare's model is fundamentally different -- they own the DNS layer, which eliminates the verification problem entirely. We can't replicate this since we don't manage user DNS, but it's worth noting that the verification step is a cost of our independence.
- The ingress rules pattern (one tunnel, many hostnames, different backends) is powerful. Our 1:1 mapping (one tunnel = one Stellar address = one Pintheon) is simpler but could evolve toward multi-service routing later.
- The non-routable CNAME target (`cfargotunnel.com`) is a clever security pattern. Our equivalent is that the Stellar address subdomain is meaningless without an active authenticated tunnel behind it.
- Their free pricing puts pressure on all competitors. Custom domains being free is a strong user expectation now.

---

### Tailscale Funnel

**How it works**: Tailscale Funnel **does not support custom domains**. Endpoints are always `*.ts.net`. This is a well-known feature request (GitHub issue #11563, still open). CNAMEing a custom domain to a `*.ts.net` address does not work because Tailscale's relay uses SNI to route connections and won't recognize the custom hostname.

**Takeaway**: Even major players haven't solved this yet. Custom domain support is a genuine differentiator.

---

### Expose (beyondco/expose)

Expose is an open-source PHP-based tunnel with the most complete custom domain support among OSS alternatives.

**How it works**:
- Self-hosted server with wildcard DNS (`*.expose.mydomain.dev` A records).
- Custom subdomains via `--subdomain` flag.
- Full custom domains supported through an admin web dashboard + SQLite database.
- SSL delegated to reverse proxy (Nginx + certbot wildcard cert).
- Token-based user authentication with an admin management interface.

**Key details**:
- ReactPHP-based (event-driven, non-blocking).
- Includes a localhost:4040 web inspector for debugging (like ngrok).
- Open-source core, paid "Pro" platform for team management and subdomain reservation.
- Custom domain management lives in the admin dashboard, not the client.

**Takeaway**: Expose validates our architecture -- wildcard DNS + reverse proxy + subdomain routing + domain registry is the proven OSS pattern for custom domains. Their admin dashboard approach maps well to our Metavinci tray UI.

---

### Localtunnel / Bore

Neither supports custom domains. Localtunnel supports custom *subdomains* (`--subdomain` flag, first-come-first-served, no persistence). Bore is pure TCP port forwarding with no domain concepts at all.

**Takeaway**: Custom domain support separates serious tunnel services from simple dev tools.

---

### Comparative Summary

| Feature | ngrok | Pinggy | Cloudflare Tunnel | Tailscale Funnel | Expose | **HVYM (planned)** |
|---|---|---|---|---|---|---|
| Custom domains | Yes (paid) | Yes (paid) | Yes (free) | No | Yes (self-hosted) | **Yes** |
| Apex domains | No | Yes (relay) | Yes (owns DNS) | No | No | **No (v1)** |
| Wildcard domains | Yes (paid) | Yes | Yes | No | No | **No (v1)** |
| Domain verification | CNAME implicit | CNAME / TXT+relay | Zone ownership | N/A | Admin dashboard | **CNAME + TXT** |
| SSL provisioning | Auto (LE) | Semi-auto (dashboard) | Auto (Cloudflare edge) | Auto (LE DNS-01) | Manual (reverse proxy) | **Auto (certbot)** |
| Domain API | Full REST CRUD | None (dashboard only) | Full REST + CLI | N/A | Admin dashboard | **Full REST CRUD** |
| Bring your own cert | Yes | No | Yes (origin certs) | No | Manual | **No (v1)** |
| Must stop tunnel for cert | No | Yes | No | No | No | **No** |
| Identity model | API key | Token | Cloudflare account | Tailnet membership | Auth token | **Stellar address** |
| Pricing for custom domains | $20/mo + $7.44/domain/mo | ~$3/mo (1 domain) | Free | N/A | Free (self-hosted) | **Free** |

### Key Learnings Applied to Our Design

1. **CNAME-as-verification is the industry standard.** ngrok, Pinggy, and Cloudflare all use DNS pointing as implicit ownership proof. Our plan to support both CNAME and TXT verification is more flexible than most competitors. However, CNAME should be the default/recommended path since users need the CNAME for routing anyway.

2. **API-first domain management is table stakes.** ngrok's full REST API vs. Pinggy's dashboard-only approach is a clear quality gap. Our planned `/api/domains` CRUD puts us on par with ngrok from day one.

3. **Automated SSL without tunnel disruption is critical.** Pinggy's "stop your tunnel to issue a cert" flow is a bad UX that we should avoid. Our certbot HTTP-01 webroot approach handles this cleanly -- the ACME challenge is served on port 80 while active tunnels continue on port 443.

4. **Apex domain support is a "nice to have", not a blocker.** ngrok doesn't support it. Tailscale doesn't support it. Pinggy's relay approach is complex. We can safely defer apex domains and document the limitation.

5. **Wildcard custom domains add significant complexity.** Only ngrok and Cloudflare support them, both with additional DNS-01 ACME requirements. Defer to v2 at the earliest.

6. **Free custom domains are a competitive advantage.** Cloudflare offers this for free. ngrok charges $20+/mo. Pinggy charges $3/mo. Offering custom domains for free on our self-hosted service (no per-domain cost beyond the cert) is a strong differentiator for our community.

7. **Stellar identity is unique.** Every other service uses opaque tokens, API keys, or account credentials. Our Stellar address as both identity and default subdomain is architecturally cleaner and maps naturally to on-chain domain registration (Phase 6).

---

## Architecture Overview

```
                    Custom Domain Flow
                    ==================

User's DNS:  gallery.example.com  CNAME  tunnel.hvym.link

                         |
                         v

  ┌──────────────────────────────────────────────────┐
  │  Nginx (port 443)                                │
  │                                                  │
  │  1. TLS termination                              │
  │     - Wildcard cert for *.tunnel.hvym.link       │
  │     - Per-domain cert via certbot HTTP-01        │
  │                                                  │
  │  2. Routing decision                             │
  │     if host matches *.tunnel.hvym.link:          │
  │       extract Stellar address from subdomain     │
  │     else:                                        │
  │       query domain registry for Stellar address  │
  │                                                  │
  │  3. Set X-Stellar-Address header                 │
  │  4. proxy_pass -> FastAPI :8000                  │
  └──────────────────────────┬───────────────────────┘
                             │
                             v
  ┌──────────────────────────────────────────────────┐
  │  FastAPI                                         │
  │                                                  │
  │  /proxy/{path}  -- unchanged, reads              │
  │                    X-Stellar-Address header       │
  │                                                  │
  │  /api/domains/* -- NEW: domain CRUD + verify     │
  │                                                  │
  │  /acme/*        -- NEW: ACME HTTP-01 challenges  │
  └──────────────────────────────────────────────────┘
                             │
                             v
  ┌──────────────────────────────────────────────────┐
  │  Domain Registry (Redis + optional Soroban)      │
  │                                                  │
  │  gallery.example.com -> GABCDEF...  (verified)   │
  │  art.dao.xyz         -> GXYZ123...  (pending)    │
  └──────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. Domain Registry

A new registry that maps custom domains to Stellar addresses.

**Data Model** (per domain entry):

```python
@dataclass
class CustomDomain:
    domain: str                    # "gallery.example.com"
    stellar_address: str           # "GABCDEF..."
    status: str                    # "pending_verification" | "verified" | "suspended"
    verification_method: str       # "cname" | "txt"
    verification_token: str        # random token for TXT verification
    created_at: datetime
    verified_at: Optional[datetime]
    last_checked_at: Optional[datetime]
    ssl_provisioned: bool          # True once cert is issued
    ssl_expires_at: Optional[datetime]
```

**Storage**: Redis (same instance as tunnel registry), key pattern: `domain:{domain}`.

**Future**: Mirror to Soroban contract for on-chain proof of domain<->address binding.

**Constraints**:
- One Stellar address can have multiple custom domains.
- Each domain maps to exactly one Stellar address.
- Domain must be verified before traffic is routed.

---

### 2. Domain Verification

The primary verification method is CNAME -- the user must point their domain to the tunnel server for routing to work anyway, so the CNAME record doubles as proof of DNS control. Combined with Stellar JWT authentication at registration time, an attacker would need both the Stellar key AND DNS control to hijack a domain.

#### CNAME Verification (Default)

The user creates a CNAME record pointing their domain to the tunnel server:

```
gallery.example.com  CNAME  tunnel.hvym.link
```

**Server checks**: DNS lookup of `gallery.example.com` resolves (directly or via CNAME chain) to the tunnel server's IP. This is the same approach used by ngrok and Pinggy, and is the industry standard.

#### TXT Record Verification (Fallback)

For cases where the user wants to verify ownership before configuring routing (e.g. pre-registering a domain), they can add a DNS TXT record instead:

```
_hvym-verify.gallery.example.com  TXT  "hvym-verify=GABCDEF...:<token>"
```

Where `<token>` is a server-generated random value tied to the Stellar address. The CNAME must still be added before traffic will route.

#### Verification Flow

```
1. Client sends: POST /api/domains { domain, method }
   (Authenticated via Stellar JWT)

2. Server generates verification token, stores pending domain entry.
   Returns instructions: "Add this CNAME/TXT record"

3. Client (or background job) sends: POST /api/domains/{domain}/verify

4. Server performs DNS lookup:
   - CNAME: Resolve domain, check it points to tunnel server
   - TXT: Query _hvym-verify.{domain}, check token matches

5. If verified:
   - Mark domain as "verified"
   - Trigger SSL certificate provisioning
   - Add to Nginx routing

6. If not verified:
   - Return "pending", user can retry
   - Expire after 72 hours if never verified
```

---

### 3. SSL Certificate Provisioning

Custom domains can't use the wildcard `*.tunnel.hvym.link` cert. Each custom domain needs its own certificate.

We use **certbot with HTTP-01 challenges**. HTTP-01 is fully automated -- no DNS API integration needed per registrar. Since the CNAME already points traffic to our server, we control the HTTP path. Unlike Pinggy, which requires stopping active tunnels to issue certs, our webroot approach runs alongside active tunnels with zero disruption.

**Flow**:
1. Domain passes verification.
2. Server triggers certbot: `certbot certonly --webroot -w /var/www/acme -d gallery.example.com`
3. Certbot places challenge file at `/.well-known/acme-challenge/<token>`.
4. Let's Encrypt validates via HTTP on port 80.
5. Certificate issued, stored in `/etc/letsencrypt/live/{domain}/`.
6. Nginx serves the cert automatically via dynamic `$ssl_server_name` path (see Nginx Routing below) -- no reload or per-domain config needed.

**Nginx config for ACME**:
```nginx
# Catch-all for port 80 -- serve ACME challenges, redirect everything else
server {
    listen 80;
    server_name _;

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
```

**Certificate Renewal**: Certbot's built-in renewal cron handles this. Certs renew automatically before expiry.

**Rate Limits**: Let's Encrypt allows 50 certs per registered domain per week. Since each custom domain is unique, this is unlikely to be an issue unless the service scales massively (at which point we'd use a wildcard or switch to a paid CA).

---

### 4. Nginx Routing Changes

Currently Nginx has two server blocks:
- `server_name tunnel.hvym.link` -- API/WebSocket
- `server_name *.tunnel.hvym.link` -- Stellar address subdomain routing

We add a catch-all server block for custom domains. This block handles two things: **dynamic TLS certificate selection** and **domain-to-tunnel routing**.

#### Dynamic TLS via `$ssl_server_name`

Nginx 1.15.9+ supports variables in `ssl_certificate` directives, resolved at TLS handshake time using the SNI hostname. This lets a single catch-all server block serve the correct per-domain certificate without any per-domain Nginx config or reloads:

```nginx
# Catch-all for custom domains
server {
    listen 443 ssl;
    server_name _;

    # Dynamic cert selection -- Nginx resolves $ssl_server_name from SNI at handshake
    # Certbot stores certs at /etc/letsencrypt/live/{domain}/
    ssl_certificate     /etc/letsencrypt/live/$ssl_server_name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$ssl_server_name/privkey.pem;

    location / {
        proxy_set_header X-Custom-Domain $host;
        proxy_pass http://127.0.0.1:8000/proxy$request_uri;
    }
}
```

If a cert doesn't exist for the hostname (e.g. unverified domain, or cert not yet issued), the TLS handshake fails before reaching FastAPI. This is correct behavior -- unverified domains should not serve traffic.

#### FastAPI Domain Lookup

Nginx passes the custom hostname via `X-Custom-Domain`. FastAPI's `/proxy` route gains a fallback to resolve it to a Stellar address:

```python
stellar_address = request.headers.get("X-Stellar-Address")
if not stellar_address:
    custom_domain = request.headers.get("X-Custom-Domain")
    if custom_domain:
        domain_entry = await domain_registry.lookup(custom_domain)
        if domain_entry and domain_entry.status == "verified":
            stellar_address = domain_entry.stellar_address
```

The domain registry lookup is cached in-process (TTL-based) so repeated requests for the same custom domain don't hit Redis on every request. All routing logic stays in Python -- no OpenResty, no Lua modules.

---

### 5. API Endpoints

New endpoints under `/api/domains/`, all requiring Stellar JWT authentication:

```
POST   /api/domains
       Body: { "domain": "gallery.example.com", "method": "cname" }
       Creates a pending domain entry.
       Returns: { "domain", "status": "pending_verification", "instructions" }

GET    /api/domains
       Lists all domains for the authenticated Stellar address.
       Returns: [{ "domain", "status", "verified_at", "ssl_provisioned" }]

GET    /api/domains/{domain}
       Get details for a specific domain.
       Returns: { "domain", "status", "verification_method", ... }

POST   /api/domains/{domain}/verify
       Triggers server-side DNS verification.
       Returns: { "domain", "status", "message" }

DELETE /api/domains/{domain}
       Removes the domain mapping. Revokes SSL cert.
       Returns: { "deleted": true }
```

**Authentication**: These endpoints use the same Stellar JWT auth as the WebSocket tunnel. The JWT's `sub` claim (Stellar address) determines which address the domain binds to.

**Authorization**: A user can only manage domains bound to their own Stellar address.

---

### 6. Client Changes (tunnel_client.py)

Add domain management methods to `HVYMTunnelClient`:

```python
async def register_domain(self, domain: str, method: str = "cname") -> dict:
    """Register a custom domain for this tunnel."""

async def verify_domain(self, domain: str) -> dict:
    """Trigger server-side verification of a registered domain."""

async def list_domains(self) -> list:
    """List all custom domains for this address."""

async def remove_domain(self, domain: str) -> dict:
    """Remove a custom domain mapping."""
```

These call the REST API endpoints above using the client's existing JWT.

---

### 7. Metavinci UI Integration

Add domain management to the tunnel submenu in `metavinci.py`:

```
Open Tunnel
├── Status: Connected (Native)
├── Endpoint: https://GADDR...tunnel.hvym.link
├── Custom Domains                        <-- NEW
│   ├── gallery.example.com  (verified)
│   ├── art.mysite.org       (pending)
│   ├── ─────────
│   ├── Add Domain...                     <-- opens dialog
│   └── Manage Domains...                 <-- opens full management dialog
├── ─────────
├── Native (HVYM)
│   ├── Connect / Disconnect
│   └── ...
```

**Add Domain Dialog**:
1. Text input for domain name.
2. Dropdown: CNAME or TXT verification.
3. Shows instructions after submission ("Add this DNS record, then click Verify").
4. "Verify" button to trigger server check.
5. Status indicator: pending -> verified -> SSL ready.

---

## Implementation Phases

### Phase 1: Domain Registry & API

**Scope**: Server-side domain storage and CRUD API.

- [ ] Add `CustomDomain` dataclass to `app/registry/` or new `app/domains/` module.
- [ ] Add Redis storage for domain entries (key pattern: `domain:{domain}`, reverse index: `domains:{stellar_address}`).
- [ ] Add `/api/domains` CRUD endpoints to `app/api/routes.py` (or new `app/api/domains.py`).
- [ ] Add JWT authentication middleware for domain endpoints.
- [ ] Add unit tests for domain registry.

**Estimated effort**: Small-medium. Mostly new code, no changes to existing tunnel flow.

---

### Phase 2: Domain Verification

**Scope**: DNS verification logic.

- [ ] Add DNS resolution helpers (CNAME check, TXT record check) using `dnspython`.
- [ ] Add `POST /api/domains/{domain}/verify` logic.
- [ ] Add background task to expire unverified domains after 72 hours.
- [ ] Add periodic re-verification (optional, to catch domains that stop pointing to us).
- [ ] Add unit tests for verification logic.

**Estimated effort**: Small. Straightforward DNS queries.

---

### Phase 3: SSL Provisioning

**Scope**: Automatic certificate generation for verified custom domains.

- [ ] Add certbot integration (subprocess call or ACME client library).
- [ ] Add Nginx ACME challenge location block (port 80 webroot).
- [ ] Add cert-issued callback to update domain entry (`ssl_provisioned = True`).
- [ ] Add cert cleanup on domain removal (`certbot delete --cert-name {domain}`).
- [ ] Test end-to-end: register domain -> verify -> cert issued -> HTTPS works.

**Estimated effort**: Medium. Certbot subprocess integration needs care. No Nginx reloads needed -- dynamic `$ssl_server_name` picks up new certs automatically.

---

### Phase 4: Nginx Routing

**Scope**: Route custom domain traffic to the correct tunnel.

- [ ] Add catch-all server block with dynamic `$ssl_server_name` cert paths.
- [ ] Add domain lookup fallback in `/proxy` route via `X-Custom-Domain` header.
- [ ] Add in-process TTL cache for domain->address lookups.
- [ ] Update `config/nginx-hvym-tunnler.conf` template.
- [ ] Update `scripts/vps_startup.sh` to install new Nginx config.
- [ ] Test end-to-end: custom domain request -> Nginx -> FastAPI -> tunnel -> local service.

**Estimated effort**: Medium. Nginx config for dynamic SSL + catch-all routing needs careful testing.

---

### Phase 5: Client & Metavinci Integration

**Scope**: Client-side domain management.

- [ ] Add domain management methods to `tunnel_client.py`.
- [ ] Add domain management to `tunnel_config.py` (persist registered domains locally).
- [ ] Add domain submenu to Metavinci tray UI.
- [ ] Add "Add Domain" dialog with verification flow.
- [ ] Add domain status indicators in UI.
- [ ] Test end-to-end from Metavinci: add domain -> verify -> use.

**Estimated effort**: Medium. UI work in PyQt5 plus client API calls.

---

### Phase 6: Soroban On-Chain Registry (Future)

**Scope**: Migrate domain registry to Soroban smart contract.

- [ ] Design Soroban contract for domain<->address mapping.
- [ ] Implement contract with ownership transfer support.
- [ ] Add server-side Soroban read integration (use contract as source of truth).
- [ ] Keep Redis as a cache layer in front of Soroban.
- [ ] Support namespace resolution (human-readable names like `mynode.tunnel.hvym.link`).

**Estimated effort**: Large. Depends on Soroban tooling maturity.

---

## Server Overhead

Custom domain support adds minimal resource overhead. The feature is an alias layer -- it resolves a hostname to a Stellar address, then the existing tunnel infrastructure handles the rest.

| Resource | Per-domain cost | At 100 domains | At 1,000 domains | Notes |
|---|---|---|---|---|
| **Redis** | ~500 bytes | ~50 KB | ~500 KB | Domain entry + reverse index. Negligible vs. tunnel session data already in Redis. |
| **Disk (certs)** | ~15-20 KB | ~2 MB | ~20 MB | Let's Encrypt cert files (fullchain, privkey, chain) + certbot renewal metadata. |
| **Disk (Nginx)** | 0 | 0 | 0 | Dynamic `$ssl_server_name` means no per-domain config files or server blocks. |
| **Memory** | ~200 bytes | ~20 KB | ~200 KB | In-process TTL cache for domain->address lookups in FastAPI. |
| **CPU (one-time)** | ~2-5 sec | -- | -- | Certbot run per domain registration + DNS lookup for verification. |
| **CPU (ongoing)** | ~0 | ~0 | ~0 | Certbot renewal cron runs every 12 hours system-wide (not per-domain). |
| **CPU (per-request)** | 1 Redis GET | -- | -- | Cached in-process with TTL; only cold lookups hit Redis. |

**What does NOT scale linearly**:
- Nginx config: stays the same size regardless of how many custom domains exist (single catch-all block).
- Nginx reloads: none needed. Certs are resolved dynamically from disk at TLS handshake time.
- FastAPI code: one fallback branch in `/proxy`, same for 1 or 10,000 domains.

**What to watch at scale**:
- **Let's Encrypt rate limits**: 50 certificates per registered domain per week. Each custom domain is its own registered domain, so this only matters if 50+ domains are registered in a single week.
- **Certbot renewal load**: All certs renew within a 30-day window before expiry. If 1,000 domains were added in the same week, they'd all renew in the same week ~60 days later. Certbot handles this serially but it could take time. Unlikely to be an issue at our expected scale.
- **Redis memory**: Only relevant if domain count reaches tens of thousands, at which point Redis is still fine (it routinely handles millions of keys).

**Bottom line**: This feature adds near-zero ongoing resource cost. The infrastructure overhead is dominated by the SSL certs on disk, which are tiny. The biggest cost is operational complexity (certbot subprocess management, DNS verification logic), not server resources.

---

## Open Questions

1. **Rate limits on domain registration?** Should there be a cap on how many custom domains one Stellar address can register? (Suggestion: Start with 5, increase later.)

2. **Domain transfer?** If a user wants to transfer a domain to another Stellar address, do we require re-verification? (Suggestion: Yes, always re-verify on transfer.)

3. **Subdomain depth?** Do we support `deep.sub.example.com` or only single-level like `gallery.example.com`? (Suggestion: Support any valid hostname, no depth restriction.)

4. **Paid tier?** Custom domains could be a premium feature. Does this need billing integration? (Suggestion: Free initially, consider gating later if server costs grow. Cloudflare offers custom domains for free; ngrok charges $20+/mo. Free is a competitive advantage for us.)

---

## Security Considerations

- **Domain hijacking**: A malicious user could register someone else's domain before them. Mitigated by requiring DNS verification -- only the domain's DNS controller can verify.
- **Dangling CNAME**: If a user removes their CNAME but doesn't delete the domain entry, the cert stays valid. Add periodic re-verification (weekly) to catch stale entries.
- **SSL cert limits**: Let's Encrypt has rate limits (50 certs/week per registered domain). Monitor usage if adoption grows.
- **JWT scope**: Domain management endpoints should verify the JWT's `sub` matches the domain's `stellar_address`. Never allow cross-address domain management.

---

## Dependencies

| Dependency | Purpose | Phase |
|---|---|---|
| `dnspython` | DNS resolution for verification | 2 |
| `certbot` (system) | SSL certificate provisioning | 3 |
| Soroban SDK | On-chain domain registry | 6 |

---

## Summary

Custom domain support is an **alias layer** on top of the existing Stellar address routing. The core tunnel infrastructure stays unchanged. The work breaks down into:

1. **Registry + API** -- Store domain->address mappings, expose CRUD.
2. **Verification** -- Prove DNS ownership via CNAME or TXT.
3. **SSL** -- Auto-provision certs for verified domains.
4. **Routing** -- Resolve custom domains to Stellar addresses in the request path.
5. **UI** -- Let Metavinci users manage domains from the tray.
6. **On-chain** -- Soroban migration for decentralized registry (future).

Phases 1-4 are the server-side foundation. Phase 5 wires it into the user experience. Phase 6 is the long-term decentralization play.
