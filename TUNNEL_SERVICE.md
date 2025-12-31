# OpenZiti Tunneling Service

This document provides a comprehensive guide to setting up your own secure tunneling service using OpenZiti, similar to Ngrok or Pinggy. This service will allow you to expose applications running on localhost to the internet with built-in security and access control.

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Setting Up the Tunneling Service](#setting-up-the-tunneling-service)
7. [Client Setup](#client-setup)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)
10. [Scaling](#scaling)

## Overview

OpenZiti provides a zero-trust networking solution that can be used to create secure tunnels between clients and services. Unlike traditional VPNs, OpenZiti uses a "dark" architecture where services don't need to expose any incoming ports to the internet.

## Architecture

Our tunneling service will consist of the following components:

1. **Controller**: Manages the network and policies
2. **Edge Router**: Handles client connections and routes traffic
3. **Tunnelers**: Client components that create secure tunnels
4. **Management Console**: Web interface for administration

## Prerequisites

- Linux server (Ubuntu 20.04/22.04 recommended)
- Public IP address with ports 80, 443, and 8443 open
- Domain name with DNS access
- Docker and Docker Compose installed
- Basic understanding of networking concepts

## Installation

### 1. Install Docker and Docker Compose

```bash
# Update package index
sudo apt-get update

# Install required packages
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Add Docker repository
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.15.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2. Create Project Directory

```bash
mkdir -p ~/ziti-tunnel
cd ~/ziti-tunnel
```

## Configuration

### 1. Create Docker Compose File

Create a `docker-compose.yml` file with the following content:

```yaml
version: '3.3'

services:
  ziti-controller:
    image: openziti/quickstart:latest
    container_name: ziti-controller
    ports:
      - "1280:1280"
      - "6262:6262"
      - "6263:6263"
    environment:
      - ZITI_CTRL_EDGE_ADVERTISED_ADDRESS=your-domain.com
      - ZITI_CTRL_EDGE_ADVERTISED_PORT=1280
      - ZITI_CTRL_EDGE_ADVERTISED_HOST=ziti-edge-controller
    volumes:
      - ./controller.yaml:/openziti/ziti-controller.yaml
    command: run
    restart: unless-stopped

  ziti-router:
    image: openziti/quickstart:latest
    container_name: ziti-router
    depends_on:
      - ziti-controller
    ports:
      - "3022:3022"
      - "10080:10080"
    environment:
      - ZITI_ROUTER_NAME=ziti-router
      - ZITI_ROUTER_ADVERTISED_HOST=your-domain.com
      - ZITI_CTRL_ENDPOINT=ziti-controller:6262
    volumes:
      - ./router.yaml:/openziti/ziti-router.yaml
    command: router
    restart: unless-stopped

  ziti-console:
    image: openziti/console
    container_name: ziti-console
    ports:
      - "1408:1408"
    environment:
      - ZITI_CTRL_ENDPOINT=ziti-controller:6262
      - ZITI_CTRL_USERNAME=admin
      - ZITI_CTRL_PASSWORD=admin
    depends_on:
      - ziti-controller
    restart: unless-stopped
```

### 2. Create Configuration Files

Create a `controller.yaml` file:

```yaml
v: 3

db: ziti.db

web:
  - name: edge-client
    bindPoints:
      - interface: edge-client
        address: 0.0.0.0:1280
        protocol: tcp
    options:
      _trace: true
      idleTimeout: 5000
      readTimeout: 20000
      writeTimeout: 10000

  - name: edge-management
    bindPoints:
      - interface: edge-management
        address: 0.0.0.0:1281
        protocol: tcp
    options:
      _trace: true
      idleTimeout: 5000
      readTimeout: 20000
      writeTimeout: 10000

edge:
  api:
    sessionTimeout: 30m
    address: 0.0.0.0:1282
    port: 1282
  enrollment:
    signingCert:
      cert: /openziti/pki/ca.pem
      key: /openziti/pki/ca.key
    edgeIdentity:
      duration: 5m
    edgeRouter:
      duration: 5m
```

Create a `router.yaml` file:

```yaml
v: 3

name: ziti-router
listeners:
  - binding: edge
    address: tcp:0.0.0.0:3022
    options:
      advertise: your-domain.com:3022
  - binding: link
    address: tls:0.0.0.0:10080
    options:
      advertise: your-domain.com:10080
```

## Setting Up the Tunneling Service

### 1. Start the Services

```bash
docker-compose up -d
```

### 2. Initialize the Controller

```bash
docker exec -it ziti-controller /openziti/ziti-controller edge init /openziti/ziti-controller.yaml -u admin -p admin
```

### 3. Create a Service and Policies

1. Log in to the Ziti Console at `http://your-domain.com:1408`
2. Navigate to "Services" and create a new service (e.g., "tunnel-service")
3. Create an intercept configuration for the service
4. Set up appropriate service and edge router policies

## Client Setup

### 1. Install Ziti Edge Tunneler

For Linux:

```bash
curl -s https://get.openziti.io/quickstart.sh | bash
```

### 2. Enroll the Client

```bash
ziti edge login your-domain.com:1280 -u admin -p admin
ziti edge create identity device tunnel-client -o tunnel-client.jwt -a "#tunnel-clients"
ziti edge enroll tunnel-client.jwt
```

### 3. Create a Tunnel Configuration

Create a `tunnel-config.json` file:

```json
{
  "ztAPI": "https://your-domain.com:1280",
  "identity": "/path/to/tunnel-client.json",
  "tunnels": [
    {
      "name": "webapp",
      "address": "localhost:3000",
      "protocol": "tcp",
      "service": "tunnel-service"
    }
  ]
}
```

### 4. Start the Tunnel

```bash
ziti-tunnel run -c tunnel-config.json
```

## Security Considerations

1. **TLS Certificates**: Set up proper TLS certificates for your domain
2. **Authentication**: Use strong authentication methods
3. **Authorization**: Implement least-privilege access control
4. **Monitoring**: Set up monitoring and logging
5. **Updates**: Keep all components updated

## Troubleshooting

1. **Connection Issues**:
   - Verify ports are open and accessible
   - Check firewall settings
   - Verify DNS resolution

2. **Authentication Problems**:
   - Check JWT token validity
   - Verify identity and service policies

3. **Performance Issues**:
   - Monitor resource usage
   - Consider scaling edge routers

## Scaling

As your user base grows, consider:

1. Adding more edge routers in different regions
2. Implementing load balancing
3. Setting up high availability for the controller
4. Monitoring and alerting

## Next Steps

1. Set up automated backups
2. Implement monitoring and alerting
3. Create custom branding for the management console
4. Develop custom integrations using the OpenZiti SDK

## Resources

- [OpenZiti Documentation](https://openziti.io/docs/)
- [OpenZiti GitHub](https://github.com/openziti/ziti)
- [OpenZiti Community](https://openziti.discourse.group/)

---

This document provides a starting point for setting up your OpenZiti tunneling service. For production deployments, consult the official OpenZiti documentation and consider engaging with the OpenZiti community for additional support.
