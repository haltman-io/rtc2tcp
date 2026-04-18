# Running the broker behind a reverse proxy

`rtc2tcp-broker` is a plain HTTP/WebSocket server; it does not terminate
TLS on its own. A reverse proxy (Caddy, nginx, Cloudflare Tunnel,
Traefik, etc.) is the recommended way to expose it on the public
internet.

This page covers:

- [Traffic shape](#traffic-shape)
- [Trusted-proxy configuration](#trusted-proxy-configuration) — needed so
  the per-IP rate limiter keys on the real client, not on the proxy.
- [Caddy example](#caddy)
- [nginx example](#nginx)
- [Cloudflare Tunnel example](#cloudflare-tunnel)
- [Validating the setup](#validating-the-setup)

---

## Traffic shape

The broker listens on a single HTTP port and exposes two routes:

| Path       | Purpose                                          |
| ---------- | ------------------------------------------------ |
| `/ws`      | WebSocket upgrade used by `rtc2tcp-peer`         |
| `/healthz` | Liveness endpoint (`200 OK`, body `ok`)          |

Peer clients always connect to `/ws`; a value like `--broker
https://rtc.example.com` is rewritten to `wss://rtc.example.com/ws`
automatically.

Requirements for the reverse proxy:

- Must forward the `Upgrade` / `Connection` headers (WebSocket).
- Must preserve the original `Host` header; the broker's origin check
  compares the `Origin` of the WebSocket handshake against the request
  `Host`.
- Should terminate TLS with a publicly trusted certificate — peers
  refuse plain `ws://` to non-loopback hosts.
- Should set **long** read/write timeouts on the WebSocket location
  (sessions can sit idle for minutes between signalling messages).

---

## Trusted-proxy configuration

Without any proxy configuration, the broker keys its per-IP upgrade
rate limiter on `r.RemoteAddr`. Behind a reverse proxy that address is
always the proxy's IP, so a single abusive peer would consume the
entire budget for everyone — or, conversely, a misbehaving proxy would
trip the limit for legitimate traffic.

Fix it by pointing the broker at the upstreams it should trust:

```bash
rtc2tcp-broker \
  --listen :8080 \
  --trusted-proxies "127.0.0.1,::1" \
  --trusted-proxy-header "X-Forwarded-For"
```

Behaviour:

- `--trusted-proxies` accepts a comma- or whitespace-separated list of
  IPs and CIDR blocks (both IPv4 and IPv6). Typical values:
  - `127.0.0.1,::1` — Caddy/nginx/Cloudflare Tunnel on the same host.
  - `10.0.0.0/8` — upstream load balancer in a private VPC.
- `--trusted-proxy-header` names the header consulted when the
  immediate peer matches the trusted list:
  - `X-Forwarded-For` (default) — multi-hop, list-aware. The broker
    walks the list right-to-left, skipping each entry that is itself a
    trusted proxy, and returns the first untrusted IP (the real
    client).
  - `X-Real-IP` — single-value, set by nginx (`proxy_set_header
    X-Real-IP $remote_addr`).
  - `CF-Connecting-IP` — set by Cloudflare when the broker is fronted
    by Cloudflare Tunnel or the orange-cloud proxy.
- When the immediate peer is **not** a trusted proxy, the header is
  ignored entirely — this is what prevents a direct internet client
  from spoofing its source IP by injecting `X-Forwarded-For: 1.2.3.4`.
- Leaving `--trusted-proxies` empty disables forwarded-for parsing
  entirely (the safe default for direct internet exposure).

### Rate-limit knobs

Two related flags let you tune the per-client budget once real client
IPs are visible:

- `--rate-limit-per-minute` (default `30`) — steady-state requests per
  minute per IP.
- `--rate-limit-burst` (default `10`) — short-spike budget before the
  steady-state rate kicks in.

These operate on whatever IP the broker decides is the source, so they
work correctly both with and without a reverse proxy once trusted
proxies are configured.

---

## Caddy

Caddy 2 handles TLS provisioning, HTTP/2, and WebSockets out of the box.

```caddy
# /etc/caddy/Caddyfile
rtc.example.com {
    encode zstd gzip

    reverse_proxy 127.0.0.1:8080 {
        # Preserve the client's original IP so the broker's trusted-proxy
        # logic can see it. Caddy sets X-Forwarded-For by default; this
        # makes the behaviour explicit.
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}

        # WebSocket sessions can sit idle between signalling messages;
        # don't let Caddy cut them short.
        transport http {
            read_timeout  1h
            write_timeout 1h
        }
    }
}
```

Matching broker command (run as a service — see
[`contrib/systemd`](../contrib/systemd/)):

```bash
rtc2tcp-broker \
  --listen 127.0.0.1:8080 \
  --trusted-proxies 127.0.0.1 \
  --trusted-proxy-header X-Forwarded-For
```

---

## nginx

nginx requires explicit WebSocket upgrade handling:

```nginx
# /etc/nginx/conf.d/rtc2tcp.conf
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name rtc.example.com;

    ssl_certificate     /etc/letsencrypt/live/rtc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/rtc.example.com/privkey.pem;

    # Health probe — useful for external monitors.
    location = /healthz {
        proxy_pass http://127.0.0.1:8080/healthz;
        access_log off;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8080/ws;

        proxy_http_version 1.1;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        $connection_upgrade;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket sessions are long-lived.
        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
    }
}
```

Matching broker command:

```bash
rtc2tcp-broker \
  --listen 127.0.0.1:8080 \
  --trusted-proxies 127.0.0.1 \
  --trusted-proxy-header X-Forwarded-For
```

### nginx behind another layer

If nginx itself sits behind a load balancer, add the LB's CIDR to
`--trusted-proxies` too; the broker will walk the full XFF chain and
strip every trusted hop:

```bash
--trusted-proxies "127.0.0.1,10.0.0.0/8"
```

---

## Cloudflare Tunnel

Cloudflare Tunnel (formerly Argo Tunnel) exposes the broker without
opening any inbound ports. The egress connection terminates on
`cloudflared` running on the broker host.

### 1. Create the tunnel

```bash
cloudflared tunnel login
cloudflared tunnel create rtc2tcp
```

### 2. Tunnel config

```yaml
# /etc/cloudflared/config.yml
tunnel: <tunnel-uuid>
credentials-file: /etc/cloudflared/<tunnel-uuid>.json

ingress:
  - hostname: rtc.example.com
    service: http://127.0.0.1:8080
    originRequest:
      # Don't time out long-lived WebSocket sessions.
      noTLSVerify: false
      connectTimeout: 30s
      tlsTimeout: 10s
      keepAliveTimeout: 90s
      httpHostHeader: rtc.example.com
  - service: http_status:404
```

### 3. DNS + run

```bash
cloudflared tunnel route dns rtc2tcp rtc.example.com
cloudflared tunnel run rtc2tcp
```

### 4. Broker flags

Cloudflare injects `CF-Connecting-IP` with the original client IP. Since
`cloudflared` connects to the broker over loopback, trust only
loopback:

```bash
rtc2tcp-broker \
  --listen 127.0.0.1:8080 \
  --trusted-proxies "127.0.0.1,::1" \
  --trusted-proxy-header CF-Connecting-IP
```

> Using `CF-Connecting-IP` rather than `X-Forwarded-For` is important
> here: Cloudflare documents `CF-Connecting-IP` as authoritative for
> the original client, whereas `X-Forwarded-For` may include values
> injected by the client before reaching Cloudflare's edge.

---

## Validating the setup

Three quick checks after a deploy:

1. **Health probe:**

   ```bash
   curl -fsS https://rtc.example.com/healthz
   # -> ok
   ```

2. **WebSocket handshake:**

   ```bash
   curl -vk \
     -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
     https://rtc.example.com/ws
   # -> 101 Switching Protocols
   ```

3. **Rate-limit visibility.** Flood `/ws` from a single client. In the
   broker log you should see the real client IP, not the proxy's:

   ```
   broker: event=rate_limited source_ip=198.51.100.42
   ```

   If `source_ip` shows `127.0.0.1` (or your proxy's IP), either
   `--trusted-proxies` is missing or the proxy is not forwarding the
   chosen header. Recheck the proxy config against the examples above.
