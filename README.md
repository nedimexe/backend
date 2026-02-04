# Helios Offline Account Backend

This service provides a simple API for managing offline accounts used by the Helios launcher. It stores accounts in PostgreSQL and exposes admin-only endpoints to create/delete accounts.

## Features
- Admin login (JWT)
- Create offline accounts
- List offline accounts (public read)
- Offline account login (username/password)
- Delete offline accounts

## Environment Variables
- `PORT` (default: 3000)
- `DATABASE_URL` (PostgreSQL connection string)
- `ADMIN_USER` (admin username)
- `ADMIN_PASS` (admin password)
- `JWT_SECRET` (signing secret for admin tokens)
- `CORS_ORIGIN` (default: `*`)

## API Endpoints
- `POST /admin/login`
  - Body: `{ "username": "admin", "password": "rp123" }`
  - Response: `{ "token": "..." }`

- `POST /admin/offline-accounts` (admin)
  - Body: `{ "username": "player1", "password": "secret", "uuid": "...", "skinUrl": "https://..." }`

- `GET /offline-accounts`
  - Response: `[ { "id": "...", "username": "...", "uuid": "...", "skin_url": "..." } ]`

- `POST /offline-accounts/login`
  - Body: `{ "username": "player1", "password": "secret" }`

- `DELETE /admin/offline-accounts/:id` (admin)

## Render (free) deployment
1. Push this repository to GitHub.
2. In Render, create a **PostgreSQL** database (free tier) and copy the connection string.
3. Create a new **Web Service** from your repo.
4. Set Build Command: `npm install` (Render will run this in the `backend` folder if you set root).
5. Set Start Command: `npm start`.
6. Add environment variables:
   - `DATABASE_URL` (from Render DB)
   - `ADMIN_USER`
   - `ADMIN_PASS`
   - `JWT_SECRET`
   - `CORS_ORIGIN`

> Tip: In Render, set the **Root Directory** to `backend` so it uses the backend package.json.

## Local Run
```bash
cd backend
npm install
npm start
```

You can test health:
```bash
curl http://localhost:3000/health
```
