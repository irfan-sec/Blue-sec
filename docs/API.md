# Blue-sec API Documentation

## Overview

The Blue-sec API provides programmatic access to Bluetooth security testing capabilities for enterprise integration.

## Base URL

```
http://localhost:8000
```

## Authentication

API key authentication is required for all endpoints (except health check):

```
X-API-Key: your_api_key_here
```

## Endpoints

### Health Check

```http
GET /health
```

Returns the health status of the API.

**Response:**
```json
{
  "status": "healthy"
}
```

### Scan Devices

```http
POST /scan
```

Scan for Bluetooth devices.

**Request Body:**
```json
{
  "scan_type": "all",  // "ble", "classic", or "all"
  "duration": 30       // optional, in seconds
}
```

**Response:**
```json
{
  "success": true,
  "devices_found": 2,
  "devices": [...]
}
```

### Vulnerability Scan

```http
POST /vuln-scan
```

Perform vulnerability assessment on a device.

**Request Body:**
```json
{
  "target": "AA:BB:CC:DD:EE:FF"
}
```

**Response:**
```json
{
  "success": true,
  "device": {...},
  "vulnerabilities_found": 3,
  "vulnerabilities": [...]
}
```

### Execute Attack

```http
POST /attack
```

Execute attack simulation (requires confirmation in config).

**Request Body:**
```json
{
  "attack_type": "mitm",
  "target": "AA:BB:CC:DD:EE:FF",
  "target2": "11:22:33:44:55:66"  // for MITM
}
```

**Response:**
```json
{
  "success": true,
  "result": {...}
}
```

### List CVEs

```http
GET /cves
```

List all known Bluetooth CVEs.

**Response:**
```json
{
  "success": true,
  "total_cves": 6,
  "cves": {...}
}
```

### Get CVE Details

```http
GET /cves/{cve_id}
```

Get details for a specific CVE.

**Response:**
```json
{
  "success": true,
  "cve": {...}
}
```

## Running the API

```bash
# Start the API server
python -m modules.api

# Or with custom host/port
python -m modules.api --host 0.0.0.0 --port 8080
```

## Error Responses

All endpoints return standard HTTP status codes:

- `200` - Success
- `400` - Bad request (invalid parameters)
- `403` - Forbidden (invalid API key)
- `404` - Not found
- `500` - Internal server error

Error response format:
```json
{
  "detail": "Error message"
}
```

## Rate Limiting

API requests are subject to rate limiting as configured in the security settings.

## SIEM Integration

Events and alerts can be forwarded to SIEM systems. Configure in `config/blue-sec.yaml`:

```yaml
enterprise:
  siem_enabled: true
  siem_url: http://siem.example.com
  api_key: your_siem_key
```
