# Stage E Enhanced Workflow - Landing Page & Mode Selection

## What Changed

The frontend now starts with a **landing page** that guides startup owners through the compliance workflow step-by-step, with clear mode selection (Docker vs GitHub OAuth).

## New User Flow

### 1. Landing Page (`/`)
- **Step-by-step tiles** showing the 4-step process
- **Mode selection cards**:
  - **Docker Agent (Offline)**: For local, air-gapped scanning
  - **GitHub OAuth (Cloud)**: For automatic cloud-based scanning
- Privacy-first messaging

### 2. Docker Mode Flow
1. User clicks "Use Docker Agent" → navigates to `/docker-setup`
2. **Docker Setup Page** shows:
   - Step-by-step Docker commands (copy-paste ready)
   - Instructions for generating keys and reports
   - Link to dashboard for upload
3. User runs Docker commands locally
4. User navigates to `/dashboard` and uploads `aegis-report.json` + public key
5. **Enhanced Upload Component**:
   - Drag & drop or file picker for report
   - Public key input (paste or load from file)
   - Visual feedback when files are loaded
6. Report appears with charts, findings, verification panel

### 3. GitHub OAuth Flow (Stub)
1. User clicks "Connect GitHub" → redirects to GitHub OAuth
2. **GitHub Callback Page** (`/github/callback`):
   - Shows loading state while scanning
   - On success: displays repo info and redirects to dashboard
   - On error: shows error message with retry option
3. Report automatically appears on dashboard (when implemented)

### 4. Dashboard (`/dashboard`)
- **Enhanced Upload** component (for Docker mode)
- **Verification Panel** (works for both modes)
- **Charts & Metrics** (severity bar, compliance radar)
- **Attestation History**

## Backend Changes

- Added `/api/auth/github` endpoint (redirects to GitHub OAuth)
- Added `/github/callback` endpoint (stub - returns 501 for now)
- Note: Full GitHub integration requires OAuth app setup and agent worker queue

## Files Added/Modified

### Frontend
- `src/pages/Landing.tsx` - New landing page with mode selection
- `src/pages/DockerSetup.tsx` - Docker instructions page
- `src/pages/GitHubCallback.tsx` - OAuth callback handler
- `src/components/EnhancedUpload.tsx` - Upload + credentials input
- `src/App.tsx` - Updated routing (landing is now `/`)
- `src/services/api.ts` - Added GitHub OAuth functions

### Backend
- `backend/main.py` - Added GitHub OAuth endpoints (stub)

## How to Test

1. **Start backend**: `uvicorn backend.main:app --reload`
2. **Start frontend**: `cd frontend && npm run dev`
3. **Visit**: `http://localhost:5173`
4. **Test Docker flow**:
   - Click "Use Docker Agent"
   - Follow instructions
   - Upload report on dashboard
5. **Test GitHub flow** (will show 501 error until implemented):
   - Click "Connect GitHub"
   - See OAuth redirect (or error if not configured)

## Next Steps for Full Implementation

1. Set up GitHub OAuth app (client ID/secret)
2. Implement token exchange in `/github/callback`
3. Add agent worker/queue to scan repos
4. Store scan results and return reports
5. Add real-time status updates (WebSocket/polling)
