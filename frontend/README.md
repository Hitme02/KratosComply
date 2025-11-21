# KratosComply Frontend

React + Vite + Tailwind + shadcn/ui dashboard that visualises Aegis reports,
verifies them against the FastAPI backend, and records attestations.

## Stack
- React 19 + TypeScript + Vite
- TailwindCSS + shadcn/ui components + Lucide icons + Framer Motion
- Recharts for severity / compliance charts
- Zustand for state, Axios for API calls

## Quickstart
```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, expects backend on http://localhost:8000
npm run build    # production bundle
```

Set `VITE_BACKEND_URL` in `.env` if the backend runs elsewhere.

## Features
- Drag & drop upload of `aegis-report.json` with validation + findings preview
- Signature + Merkle verification flow (POST `/verify-report`)
- Attestation creation + local ledger view (POST `/attest`, optional GET `/attestations`)
- Severity bar chart, compliance radar, KPI cards, attestation history table
- Dark/light mode, responsive design, and polished animations
