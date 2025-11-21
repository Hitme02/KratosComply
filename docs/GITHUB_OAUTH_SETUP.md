# GitHub OAuth Setup Guide

To enable cloud-based scanning via GitHub OAuth, you need to create a GitHub OAuth App and configure the backend.

## Step 1: Create GitHub OAuth App

1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in:
   - **Application name**: `KratosComply`
   - **Homepage URL**: `http://localhost:5173` (or your production URL)
   - **Authorization callback URL**: `http://localhost:5173/github/callback` (or your production callback URL)
4. Click "Register application"
5. Copy the **Client ID** and generate a **Client Secret**

## Step 2: Configure Backend

Create a `.env` file in the `backend/` directory (or project root):

```bash
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_REDIRECT_URI=http://localhost:5173/github/callback
```

For production:
```bash
GITHUB_CLIENT_ID=your_production_client_id
GITHUB_CLIENT_SECRET=your_production_client_secret
GITHUB_REDIRECT_URI=https://yourdomain.com/github/callback
```

## Step 3: Test OAuth Flow

1. Start the backend: `uvicorn backend.main:app --reload`
2. Start the frontend: `cd frontend && npm run dev`
3. Visit `http://localhost:5173`
4. Click "Connect GitHub"
5. You should be redirected to GitHub for authorization

## Current Status

The OAuth flow is **partially implemented**:
- ✅ OAuth authorization URL generation
- ✅ Environment variable configuration
- ❌ Token exchange (TODO)
- ❌ Repository scanning (TODO)
- ❌ Report generation (TODO)

## Next Steps for Full Implementation

1. **Token Exchange**: Implement `POST https://github.com/login/oauth/access_token` in `/github/callback`
2. **Repository Access**: Use GitHub API to list/fetch repositories
3. **Agent Integration**: Trigger agent scans on repositories (via queue/worker)
4. **Async Processing**: Use Celery/Redis for background scanning
5. **Status Updates**: WebSocket or polling for scan progress

## Security Notes

- Never commit `.env` files with secrets
- Use environment variables in production (Docker, Kubernetes, etc.)
- Rotate client secrets regularly
- Use HTTPS in production
- Validate state parameter to prevent CSRF attacks
