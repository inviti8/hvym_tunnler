# HVYM Tunnler

Stellar-authenticated tunneling service for the Heavymeta network.

## Overview

HVYM Tunnler provides secure WebSocket-based tunneling with Stellar JWT authentication, replacing third-party dependencies like Pinggy with a self-hosted solution.

### Key Features

- **Stellar JWT Authentication**: Ed25519-signed JWTs tied to Stellar wallet addresses
- **WebSocket Transport**: Firewall-friendly connections over wss://
- **Zero External Dependencies**: No third-party tunnel providers required
- **Redis-backed Registry**: Scalable tunnel tracking with Redis

## Quick Start

### Development

1. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```

2. Generate server keypair and update `.env`:
   ```bash
   python -c "from stellar_sdk import Keypair; k=Keypair.random(); print(f'TUNNLER_SERVER_ADDRESS={k.public_key}\nTUNNLER_SERVER_SECRET={k.secret}')"
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Docker Deployment

```bash
docker-compose up -d
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | Server info for clients |
| `/connect` | WebSocket | Tunnel connection endpoint |
| `/api/tunnels` | GET | List active tunnels |
| `/api/tunnel/{address}` | GET | Get tunnel details |
| `/api/stats` | GET | Server statistics |

## Documentation

- [TUNNEL_SERVICE.md](./TUNNEL_SERVICE.md) - Server implementation details
- [docs/SEAMLESS_TUNNELING.md](./docs/SEAMLESS_TUNNELING.md) - Architecture overview
- [docs/HVYM_STELLAR_JWT.md](./docs/HVYM_STELLAR_JWT.md) - JWT specification
- [docs/METAVINCI_TUNNELER.md](./docs/METAVINCI_TUNNELER.md) - Client implementation

## License

MIT
