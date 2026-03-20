# 🔒 Security Documentation

## Overview

This is the **SECURE** version of OpenClaw Command Center with the following security enhancements:

- ✅ **API Key Authentication** - All endpoints require valid API key
- ✅ **Rate Limiting** - Prevents abuse and DoS attacks
- ✅ **Helmet Security Headers** - CSP, HSTS, XSS protection
- ✅ **CORS Protection** - Configurable allowed origins
- ✅ **Input Validation** - Whitelisting and sanitization
- ✅ **WebSocket Authentication** - Session-based auth with timeout
- ✅ **Security Logging** - All security events are logged
- ✅ **Secure Defaults** - Binds to localhost by default

## Quick Start

### 1. Generate API Keys

```bash
# Generate a secure API key
openssl rand -hex 32
```

### 2. Configure Environment

```bash
cp .env.example .env
nano .env
```

Set your API keys:
```
API_KEYS=your-generated-api-key-here
```

### 3. Install Dependencies

```bash
npm install
```

### 4. Start Server

```bash
npm start
```

## Authentication

### HTTP API

Include your API key in requests:

```bash
# Via header (recommended)
curl -H "X-API-Key: your-api-key" http://localhost:3000/api/status

# Via Authorization header
curl -H "Authorization: Bearer your-api-key" http://localhost:3000/api/status
```

### WebSocket

1. First, obtain a session token:

```bash
curl -X POST http://localhost:3000/api/auth/session \
  -H "Content-Type: application/json" \
  -d '{"apiKey": "your-api-key"}'
```

2. Authenticate WebSocket connection:

```javascript
const ws = new WebSocket('ws://localhost:3000');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'your-session-token'
  }));
};
```

## Rate Limits

| Endpoint Type | Requests/Minute |
|--------------|-----------------|
| General API | 120 |
| Voice (STT) | 20 |
| Voice (TTS) | 30 |
| Auth | 10 |
| Health | 120 |

## Security Events

View recent security events:

```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:3000/api/security/log
```

## Production Deployment

### Recommended Setup

1. **Use a reverse proxy** (nginx, Caddy, Traefik) with:
   - SSL/TLS termination
   - Additional rate limiting
   - Request logging

2. **Set environment variables:**
   ```
   NODE_ENV=production
   BIND_ADDRESS=127.0.0.1
   TRUST_PROXY=true
   CORS_ORIGINS=https://yourdomain.com
   ```

3. **Use HTTPS** - Either:
   - Place cert.pem and key.pem in server/ directory, OR
   - Use reverse proxy with SSL

### Example Nginx Config

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Checklist

- [ ] API keys configured and kept secret
- [ ] .env file is NOT in version control
- [ ] BIND_ADDRESS set to 127.0.0.1 (or use reverse proxy)
- [ ] CORS_ORIGINS configured for your domains only
- [ ] HTTPS enabled (direct or via reverse proxy)
- [ ] Rate limiting tested
- [ ] Security logging enabled
- [ ] Regular security updates applied

## Reporting Security Issues

If you discover a security vulnerability, please report it privately.

## Changelog

### v2.0.0 (Secure Version)
- Added API key authentication
- Added rate limiting
- Added Helmet security headers
- Added CORS protection
- Added input validation
- Added WebSocket authentication
- Added security event logging
- Changed default bind address to localhost
- Added file type validation for uploads
- Added request ID tracking
