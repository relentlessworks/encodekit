# encodekit

> Agentic-first encoding and decoding service. The agent IS the interface.

Encode and decode data in multiple formats: Base64, Base64URL, Base64Raw, Base32, Base32Hex, Hex, URL, HTML entities, ROT13, and Binary. Plain text API, agent-driven, single Go binary.

## Quick Start

```bash
# Build
make build

# Run (defaults to :7700)
./encodekit

# Or with custom address
./encodekit -addr :8080
```

## Auth Flow

```bash
# 1. Request OTP
curl -X POST http://localhost:7700/auth/request -d 'email=user@example.com'

# 2. Verify OTP (code is logged to stderr in dev mode)
curl -X POST http://localhost:7700/auth/verify -d 'email=user@example.com&code=123456'

# 3. Use the token
curl -H "Authorization: Bearer <token>" http://localhost:7700/encode/base64 -d 'data=Hello World'
```

## API Reference

### GET /help
Self-documenting operating manual for agents.

### GET /encodings
List all supported encoding types.

### POST /encode/{type}
Encode text to the specified format.
- Body: `data=<text>&save=true` (save is optional)
- Types: `base64`, `base64url`, `base64raw`, `base32`, `base32hex`, `hex`, `url`, `html`, `rot13`, `binary`

### POST /decode/{type}
Decode encoded data back to text.
- Body: `data=<encoded>&save=true` (save is optional)

### GET /operations
List all saved operations.

### GET /operations/{handle}
Get a specific saved operation.

### DELETE /operations/{handle}
Delete a saved operation.

### GET /audit?limit=10
View recent audit log entries.

### POST /mcp
MCP JSON-RPC 2.0 endpoint for chat client integrations.

## Response Format

Plain text by default (one labeled line per record):
```
type=base64 input=Hello World output=SGVsbG8gV29ybGQ=
```

JSON available via `Accept: application/json` or `?format=json`.

## Configuration

| Source | Variable | Default | Description |
|--------|----------|---------|-------------|
| Flag | `-addr` | `:7700` | Listen address |
| Env | `ENCODEKIT_ADDR` | `:7700` | Listen address |
| Flag | `-secret` | auto | Token signing secret |
| Env | `ENCODEKIT_SECRET` | auto | Token signing secret |
| Env | `ENCODEKIT_DATA` | `encodekit-data.json` | Data file path |

## Build

```bash
make build    # CGO_ENABLED=0, single binary
make test     # go test -race
make vet      # go vet
```

## License

MIT
