[![Build and Release](https://github.com/Mahyardana/SimpleTLSTunnel/actions/workflows/dotnet-desktop.yml/badge.svg?branch=master)](https://github.com/Mahyardana/SimpleTLSTunnel/actions/workflows/dotnet-desktop.yml)

# SimpleTLSTunnel

A lightweight SOCKS5-over-TLS tunnel. Traffic from a local SOCKS5 proxy is encrypted with TLS and forwarded through one or more relay servers before reaching the internet. Supports single-hop, multi-hop, and reverse (BackConnect) topologies.

---

## Requirements

- A VPS or remote server to run the server component (two servers for multi-hop)
- [.NET 6 Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) on both client and server machines, **or** use a self-contained build from the [Releases](../../releases) page (no runtime needed)
- A self-signed X.509 certificate pair (`cert.pfx` for the server, `cert.crt` for the client)

---

## Getting a Certificate

You need a self-signed certificate. A mismatch between the server's `cert.pfx` and the client's `cert.crt` will cause the TLS handshake to fail.

**Option 1 — OpenSSL (recommended):**
```bash
# Generate a private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.crt -days 3650 -nodes -subj "/CN=tunnel"

# Bundle into a PFX (server needs this)
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.crt -passout pass:
```

**Option 2 — Online tool:** Use [certificatetools.com](https://certificatetools.com) to generate and export both files.

Place `cert.pfx` in the server's working directory and `cert.crt` in the client's working directory.

---

## Installation

### Download a pre-built binary

Go to the [Releases](../../releases) page and download the archive for your platform and architecture:

| Archive name | Platform | Architecture |
|---|---|---|
| `SimpleTLSTunnelClient-win-x64.zip` | Windows | x64 |
| `SimpleTLSTunnelClient-win-arm64.zip` | Windows | ARM64 |
| `SimpleTLSTunnelClient-linux-x64.zip` | Linux | x64 |
| `SimpleTLSTunnelClient-linux-arm64.zip` | Linux | ARM64 |
| `SimpleTLSTunnelClient-osx-x64.zip` | macOS | x64 (Intel) |
| `SimpleTLSTunnelClient-osx-arm64.zip` | macOS | ARM64 (Apple Silicon) |

Server archives follow the same naming pattern (`SimpleTLSTunnelServer-*`).

Self-contained builds include the .NET runtime — no separate installation is required.

### Build from source

```bash
git clone https://github.com/Mahyardana/SimpleTLSTunnel.git
cd SimpleTLSTunnel

# Build for your current platform
dotnet publish SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj -c Release --self-contained true
dotnet publish SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj -c Release --self-contained true

# Cross-compile for a specific RID (e.g. linux-arm64)
dotnet publish SimpleTLSTunnelClient/SimpleTLSTunnelClient.csproj -c Release -r linux-arm64 --self-contained true
dotnet publish SimpleTLSTunnelServer/SimpleTLSTunnelServer.csproj -c Release -r linux-arm64 --self-contained true
```

---

## Quick Start

1. Deploy the server binary on your VPS and place `cert.pfx` in the same directory.
2. Deploy the client binary on your local machine and place `cert.crt` in the same directory.
3. Create a `config.json` file in the same directory as each binary (see [Configuration Reference](#configuration-reference) below).
4. Start the server: `./SimpleTLSTunnelServer` (or `SimpleTLSTunnelServer.exe` on Windows).
5. Start the client: `./SimpleTLSTunnelClient`.
6. Point your application's SOCKS5 proxy to `127.0.0.1:1080` (or your configured `proxy_listening_port`).
7. Open the server's `ListeningPort` in your VPS firewall/security group.

---

## Configuration Reference

Both programs read `config.json` from their working directory on startup. If the file is absent, defaults are used.

### Client — `config.json`

```json
{
  "stable_tunnels": 8,
  "server_address": "YOUR_SERVER_IP",
  "server_port": 443,
  "proxy_listening_port": 1080
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `stable_tunnels` | integer | `32` | Number of persistent TLS connections to keep open to the server. Higher values allow more concurrent SOCKS5 connections but use more resources. Recommended range: `4`–`32`. |
| `server_address` | string | `"127.0.0.1"` | IP address or hostname of the tunnel server (or the first edge server in a multi-hop setup). |
| `server_port` | integer | `443` | TCP port the server is listening on. Must match the server's `ListeningPort`. |
| `proxy_listening_port` | integer | `1080` | Local TCP port that accepts SOCKS5 connections. Configure your browser or application to use `127.0.0.1:<this port>` as a SOCKS5 proxy. |

---

### Server — `config.json`

```json
{
  "stable_tunnels": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `stable_tunnels` | integer | `32` | Number of stable tunnel slots to keep ready. Should be at least as large as the client's `stable_tunnels` value. |
| `nextHop_address` | string | `"127.0.0.1"` | Address of the next server in the chain. Set to `"127.0.0.1"` on the **last (destination) server** — this signals that this server is the final hop and traffic exits here. Set to the next server's IP on intermediate (edge) servers. |
| `nextHop_port` | integer | `8080` | Port of the next server. Ignored when `nextHop_address` is `"127.0.0.1"` (last hop). |
| `ListeningPort` | integer | `443` | Public TCP port this server listens on for incoming tunnel connections. Open this port in your firewall. |
| `BackConnectCapability` | boolean | `false` | Enable reverse-connection mode. When `true`, this server will initiate a connection back to the edge server instead of waiting for it. Useful when the destination server cannot accept inbound connections from the edge (e.g., strict firewall). See [BackConnect](#backconnect-mode). |
| `BackConnect_address` | string | `"127.0.0.1"` | The edge server's IP address that this server will dial back to. Only used when `BackConnectCapability` is `true`. |
| `BackConnectManager_port` | integer | `444` | Management port on the edge server used to coordinate BackConnect. Must match the edge server's own `BackConnectManager_port`. |
| `BackConnect_port` | integer | `443` | The port on the edge server this server dials back to. |

---

## Deployment Scenarios

### Single Hop

The simplest setup: one client, one server. All traffic exits through the single server.

```
[Client] ──TLS──> [Server] ──> Internet
```

**Client `config.json`:**
```json
{
  "stable_tunnels": 8,
  "server_address": "SERVER_IP",
  "server_port": 443,
  "proxy_listening_port": 1080
}
```

**Server `config.json`:**
```json
{
  "stable_tunnels": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

`nextHop_address` set to `127.0.0.1` marks this as the final hop; `nextHop_port` is ignored.

---

### Multi-Hop (without BackConnect)

Traffic passes through one or more edge servers before reaching the destination. This adds an extra layer of indirection.

```
[Client] ──TLS──> [Edge Server] ──TLS──> [Destination Server] ──> Internet
```

For this example:
- Edge server: `10.10.10.1:443`
- Destination server: `10.10.10.2:443`

**Client `config.json`** — connect to the **edge** server:
```json
{
  "stable_tunnels": 8,
  "server_address": "10.10.10.1",
  "server_port": 443,
  "proxy_listening_port": 1080
}
```

**Edge Server (`10.10.10.1`) `config.json`** — forward to destination:
```json
{
  "stable_tunnels": 16,
  "nextHop_address": "10.10.10.2",
  "nextHop_port": 443,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

**Destination Server (`10.10.10.2`) `config.json`** — final hop, traffic exits here:
```json
{
  "stable_tunnels": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": false,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

---

### BackConnect Mode

Use BackConnect when the destination server sits behind a firewall that blocks inbound connections from the edge server. Instead of the edge reaching out to the destination, the **destination dials back** to the edge.

```
[Client] ──TLS──> [Edge Server] <──BackConnect── [Destination Server] ──> Internet
```

Same topology as above (`10.10.10.1` = edge, `10.10.10.2` = destination), with `BackConnectCapability` enabled on both servers.

**Edge Server (`10.10.10.1`) `config.json`:**
```json
{
  "stable_tunnels": 16,
  "nextHop_address": "10.10.10.2",
  "nextHop_port": 443,
  "ListeningPort": 443,
  "BackConnectCapability": true,
  "BackConnect_address": "127.0.0.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

**Destination Server (`10.10.10.2`) `config.json`:**
```json
{
  "stable_tunnels": 16,
  "nextHop_address": "127.0.0.1",
  "nextHop_port": 8080,
  "ListeningPort": 443,
  "BackConnectCapability": true,
  "BackConnect_address": "10.10.10.1",
  "BackConnectManager_port": 444,
  "BackConnect_port": 443
}
```

- Set `BackConnect_address` on the destination to the **edge server's public IP**.
- `BackConnectManager_port` (default `444`) must be open on the edge server.
- The destination server will initiate a connection back to the edge, bypassing its own inbound firewall restrictions.

---

## Firewall Checklist

| Machine | Port | Direction | Notes |
|---|---|---|---|
| Server | `ListeningPort` (e.g. `443`) | Inbound | Clients and edge servers connect here |
| Edge server | `BackConnectManager_port` (e.g. `444`) | Inbound | Only required when `BackConnectCapability` is `true` |
| Client | `proxy_listening_port` (e.g. `1080`) | Localhost only | Bind to `127.0.0.1` to prevent exposure |

---

## Bug Reports

If you encounter a crash or unexpected behavior, open an issue and describe the steps to reproduce it including your topology (single-hop, multi-hop, etc.) and any error output.

---

## License

See [LICENSE](LICENSE) for details.
