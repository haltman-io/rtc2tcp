# TURN

WebRTC prefers a direct peer-to-peer path, falls back to a TURN relay when both ends sit behind symmetric NATs, firewalls, or corporate egress policies that block UDP. TURN is transport-only; it never sees plaintext (payload is DTLS-SRTP end-to-end between the peers).

rtc2tcp is deliberately unopinionated about TURN providers — bring your own.

## Pass your own TURN

Same flags on both peers:

```bash
rtc2tcp-peer expose  \
  --target 127.0.0.1:22 \
  --turn turn:turn.example.net:3478?transport=udp \
  --turn-username demo \
  --turn-password demo-secret

rtc2tcp-peer connect <url> \
  --listen 127.0.0.1:2222 \
  --turn turn:turn.example.net:3478?transport=udp \
  --turn-username demo \
  --turn-password demo-secret
```

## Provider shape

Any TURN server that speaks the standard protocol works. Popular options:

- [coturn](https://github.com/coturn/coturn) — self-hosted, battle-tested.
- Cloudflare TURN.
- Twilio Network Traversal Service.
- Xirsys.

## Not in scope

rtc2tcp does not mint short-lived TURN credentials or ship a credentials backend. Static username/password (or your provider's pre-auth URL scheme) is what the flags expect.

Cloudflare-specific provider integrations are intentionally deferred — handling one vendor's auth flow in-tree would make the peer binary larger and less portable than the current design.
