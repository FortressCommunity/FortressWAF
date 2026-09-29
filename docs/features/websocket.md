# WebSocket Inspection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides real-time inspection of WebSocket connections and messages, protecting against injection attacks, rate abuse, and protocol violations.

## Configuration

```yaml
websocket:
  enabled: true
  max_frame_size: 65536        # Maximum frame payload (bytes)
  max_message_size: 131072     # Maximum message size (bytes)
  max_depth: 10                # Maximum JSON nesting depth
  max_frames_per_min: 1000     # Frame rate limit per IP
  max_bytes_per_min: 10485760  # 10 MB/min bandwidth limit
  block_on_limit: true         # Block or just monitor when limit exceeded
  allowed_types:               # Allowed frame types
    - 1                        # TextMessage
    - 2                        # BinaryMessage
  strict_mode: true            # Enable injection detection
  enable_ping: true            # Allow PING frames
  enable_pong: true            # Allow PONG frames
  enable_close: true           # Allow CLOSE frames
```

## Connection-Level Inspection

### Upgrade Handshake Validation

Detects WebSocket upgrade requests by checking headers:

| Header | Expected Value |
|--------|---------------|
| `Upgrade` | `websocket` |
| `Connection` | `upgrade` |
| `Sec-WebSocket-Key` | Present |
| `Sec-WebSocket-Version` | `13` |

### Frame Rate Limiting

Monitors frames per minute per IP address. Configurable action when limits are exceeded (block or monitor).

## Message-Level Inspection

### Frame Type Control

Restrict which WebSocket frame types are allowed:

| Type | Code | Description |
|------|------|-------------|
| TextMessage | 1 | UTF-8 text data |
| BinaryMessage | 2 | Binary data |
| CloseMessage | 8 | Connection close |
| PingMessage | 9 | Keep-alive ping |
| PongMessage | 10 | Keep-alive pong |

### Injection Detection

In strict mode, text messages are scanned for injection patterns:

```
<script, javascript:, onerror=, onload=, onclick=,
onmouseover=, eval(, document., window., expression(, url(, href=
```

### JSON Depth Validation

When `max_depth` is set, nested JSON structures are checked. Excessively deep nesting is blocked:

```json
{
  "a": {
    "b": {
      "c": {           # depth 3
        "d": {         # depth 4
          "e": {}      # depth 5 - blocked if max_depth < 5
        }
      }
    }
  }
}
```

## Frame Parsing

FortressWAF includes a built-in WebSocket frame parser for raw frame inspection:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |                               |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - -+
|     Extended payload length continued, if payload len == 126  |
+ - - - - - - - - - - - - - - -+-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - -+
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
|                     Payload Data (continued)                  |
+---------------------------------------------------------------+
```

## Example: Production Configuration

```yaml
websocket:
  enabled: true
  max_frame_size: 16384
  max_depth: 5
  max_frames_per_min: 600
  block_on_limit: true
  strict_mode: true
  enable_ping: true
  enable_pong: true
  enable_close: true
```
