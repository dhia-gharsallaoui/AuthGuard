# Development Environment

This directory contains the complete development environment for testing AuthGuard with nginx integration.

## 🚀 Quick Start

1. **Set up environment variables:**
   ```bash
   make setup-env  # Creates .env from template
   # Edit .env with your Firebase credentials
   ```

2. **Start the development environment:**
   ```bash
   make dev-up
   ```

3. **Test the system:**
   ```bash
   # Health check
   make test-nginx-health
   
   # IP whitelist (should work from localhost)
   make test-ip
   
   # Firebase authentication (requires valid token)
   make test-nginx-firebase TOKEN=your_firebase_token
   
   # Multi-provider admin endpoint
   make test-nginx-admin TOKEN=your_firebase_token
   ```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     nginx       │    │   AuthGuard     │    │   Backend       │
│   (Port 80)     │    │   (Port 8080)   │    │   (Internal)    │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │auth_request │ ├────┤ │  Firebase   │ │    │ │   Demo API  │ │
│ │   module    │ │    │ │ IP Whitelist│ │    │ │  Responses  │ │
│ └─────────────┘ │    │ │ Multi-Auth  │ │    │ └─────────────┘ │
└─────────────────┘    │ └─────────────┘ │    └─────────────────┘
                       │                 │
                       │ ┌─────────────┐ │
                       │ │   Metrics   │ │
                       │ │ (Port 9090) │ │
                       │ └─────────────┘ │
                       └─────────────────┘
```

## 🔐 Authentication Endpoints

### Public Endpoints (No Auth)
- `GET /` - Welcome page with documentation
- `GET /health` - System health check
- `GET /metrics` - Prometheus metrics

### Protected Endpoints

#### 🔥 Firebase Authentication Only
- `GET /api/*` - Public API endpoints  
- `GET /protected` - Protected resource

**Headers required:**
```bash
Authorization: Bearer YOUR_FIREBASE_TOKEN
```

#### 🌐 IP Whitelist Only  
- `GET /internal` - Internal service endpoints

**Requirements:**
- Request must come from allowed IP addresses/networks
- No additional headers required

#### 🔄 Multi-Provider (Firebase + IP Whitelist)
- `GET /admin` - Admin panel endpoints

**Requirements:**
- Must have valid Firebase token AND
- Must come from allowed IP address

## 🧪 Testing Commands

```bash
# Start development environment
make dev-up

# Health checks
curl http://localhost/health
curl http://localhost:8080/health  # Direct to AuthGuard

# Direct auth testing (new endpoints)
curl -v http://localhost/auth/ip-only           # IP whitelist only
curl -v http://localhost/auth/firebase \       # Firebase only
  -H "Authorization: Bearer YOUR_TOKEN"
curl -v http://localhost/auth/firebase-ip \    # Multi-provider
  -H "Authorization: Bearer YOUR_TOKEN"

# Protected endpoints through auth_request
curl http://localhost/protected/internal       # IP whitelist protected
curl -H "Authorization: Bearer TOKEN" \        # Firebase protected
  http://localhost/protected/api
curl -H "Authorization: Bearer TOKEN" \        # Multi-provider admin
  http://localhost/protected/admin

# Monitoring
curl http://localhost:8080/metrics            # Prometheus metrics
docker exec -it authguard-redis redis-cli    # Redis cache inspection
docker logs -f authguard-app                 # AuthGuard logs
docker logs -f authguard-nginx               # nginx logs

# Stop environment
make dev-down
```

## 📊 Monitoring

- **nginx logs:** Show auth status and user information
- **AuthGuard logs:** Authentication attempts and results  
- **Metrics:** Available at `http://localhost:9090/metrics`
- **Backend logs:** Show forwarded user headers

## 🔧 Configuration Files

- `docker-compose.yml` - Complete development stack
- `nginx.conf` - nginx configuration with auth_request setup
- `backend.conf` - Demo backend service  
- `.env.example` - Environment variables template
- `html/index.html` - Welcome page and documentation

## 🐳 Services

### nginx (Port 80)
- Main reverse proxy
- Handles auth_request to AuthGuard
- Routes to backend services
- Forwards user information via headers

### AuthGuard (Port 8080)
- Composable authentication service
- Firebase + IP whitelist providers
- Health checks and metrics
- Direct access for testing

### Backend (Internal)
- Demo backend service
- Shows forwarded authentication headers
- Returns JSON responses with user info

### Redis (Port 6379)
- Authentication result caching
- Provider-specific cache keys (firebase:*, ip_whitelist:*)
- Configurable TTL based on token expiration
- Memory fallback if Redis unavailable

## 🔍 Debugging

### View nginx auth logs:
```bash
docker-compose -f dev/docker-compose.yml logs nginx
```

### View AuthGuard logs:
```bash
docker-compose -f dev/docker-compose.yml logs authguard
```

### Check auth_request responses:
```bash
# Should return 200 for valid auth
curl -I -H "Authorization: Bearer TOKEN" http://localhost:8080/validate

# Check specific provider
curl -I -H "X-Auth-Providers: ip_whitelist" http://localhost:8080/validate
```

### Test provider combinations:
```bash
# Use convenient testing endpoints
curl -v http://localhost/auth/firebase \
     -H "Authorization: Bearer TOKEN"

curl -v http://localhost/auth/ip-only

curl -v http://localhost/auth/firebase-ip \
     -H "Authorization: Bearer TOKEN"
```

### Inspect Redis cache:
```bash
# Connect to Redis
docker exec -it authguard-redis redis-cli -a authguard_redis_password

# View cache keys by provider
keys firebase:*
keys ip_whitelist:*

# Check specific cached result
get firebase:abc123def456
```

## 🚨 Troubleshooting

### Firebase "Project ID not found"
1. Ensure `AUTHGUARD_FIREBASE_CREDENTIALS_BASE64` is set in `.env`
2. Verify the base64 string is valid:
   ```bash
   echo $AUTHGUARD_FIREBASE_CREDENTIALS_BASE64 | base64 -d | jq .
   ```

### IP Whitelist Issues
1. Check allowed IPs include Docker networks:
   ```bash
   AUTHGUARD_IP_WHITELIST_ALLOWED_IPS="127.0.0.1,::1,172.16.0.0/12"
   ```
2. Verify proxy headers are configured correctly

### nginx auth_request Fails
1. Check nginx can reach AuthGuard:
   ```bash
   docker-compose -f dev/docker-compose.yml exec nginx curl http://authguard:8080/health
   ```
2. Review nginx logs for auth_request status codes

## 🔄 Development Workflow

1. **Start environment:** `make dev-up`
2. **Make changes** to AuthGuard code
3. **Rebuild:** `docker-compose -f dev/docker-compose.yml build authguard`
4. **Restart:** `docker-compose -f dev/docker-compose.yml restart authguard`
5. **Test:** Use the various `make test-*` commands
6. **View logs:** `make dev-logs`