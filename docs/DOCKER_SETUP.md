# Docker Setup Guide

KratosComply can be run entirely with Docker Compose for easy local development and production deployment.

## Quick Start

### Development Mode

```bash
# Start all services
docker-compose up --build

# Backend: http://localhost:8000
# Frontend: http://localhost:5173
```

### Production Mode

```bash
# Build and start production services
docker-compose -f docker-compose.prod.yml up --build -d

# Frontend: http://localhost (served via nginx)
# Backend: http://localhost:8000
```

## Services

### Backend
- **Port**: 8000
- **Health**: `curl http://localhost:8000/`
- **Database**: SQLite stored in `./kratos.db` (persisted via volume)

### Frontend
- **Dev Port**: 5173 (Vite dev server with HMR)
- **Prod Port**: 80 (nginx serving static build)
- **Environment**: Set `VITE_BACKEND_URL` to point to backend

### Agent (Optional)
- **Profile**: `agent` (only runs when explicitly invoked)
- **Usage**: 
  ```bash
  docker-compose run --rm agent scan /workspace/sample-app \
    --output /workspace/sample-app/aegis-report.json \
    --keystore /root/.kratos/keys
  ```

## Environment Variables

Create a `.env` file in the project root:

```bash
# Backend
DATABASE_URL=sqlite:///./kratos.db
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=http://localhost:5173/github/callback

# Frontend
VITE_BACKEND_URL=http://localhost:8000
```

## Building Individual Services

### Backend
```bash
docker build -f backend/Dockerfile -t kratos-backend .
docker run -p 8000:8000 kratos-backend
```

### Agent
```bash
docker build -f agent/Dockerfile -t kratos-agent .
docker run -v $(pwd)/examples:/workspace kratos-agent scan /workspace/sample-app \
  --output /workspace/sample-app/aegis-report.json
```

### Frontend (Dev)
```bash
cd frontend
docker build -f Dockerfile -t kratos-frontend .
docker run -p 5173:5173 kratos-frontend
```

### Frontend (Production)
```bash
cd frontend
docker build -f Dockerfile.prod -t kratos-frontend-prod .
docker run -p 80:80 kratos-frontend-prod
```

## Troubleshooting

### Port conflicts
If ports 8000 or 5173 are in use, modify `docker-compose.yml`:
```yaml
ports:
  - "8001:8000"  # Backend on 8001
  - "5174:5173"  # Frontend on 5174
```

### Database persistence
The SQLite database is stored in `./kratos.db`. To reset:
```bash
rm kratos.db
docker-compose restart backend
```

### Frontend can't reach backend
Ensure `VITE_BACKEND_URL` in `docker-compose.yml` matches your backend URL.
In production, use the service name: `http://backend:8000`

### Agent keystore
The agent service mounts `~/.kratos/keys` from your host. Ensure the directory exists:
```bash
mkdir -p ~/.kratos/keys
```
