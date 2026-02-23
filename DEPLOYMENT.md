# AURION Deployment Guide (Render)

This project is set up to run as one Node.js web service:
- Backend API from `backend/src/server.js`
- Frontend static pages from `frontend/` served by Express

## 1) Push Code to GitHub

From `tvashta-event`:

```powershell
git init
git add .
git commit -m "Prepare production deployment"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

## 2) Create Render Service

1. Open Render dashboard.
2. Click `New` -> `Blueprint`.
3. Connect your GitHub repo.
4. Render will detect `render.yaml`.
5. Create service.

## 3) Set Secret Environment Variables in Render

Set these in Render service settings:
- `MONGODB_URI`
- `ADMIN_ID`
- `ADMIN_PASSWORD`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `EMAIL_USER` (optional)
- `EMAIL_PASS` (optional)

Non-secret defaults are already in `render.yaml`.

## 4) Verify Deployment

After deploy, verify:
- `https://<your-service>.onrender.com/api/health`
- `https://<your-service>.onrender.com/index.html`
- `https://<your-service>.onrender.com/register.html`
- `https://<your-service>.onrender.com/admin.html`

## 5) Go Live Checklist

- Confirm a test registration works end-to-end.
- Confirm admin login + file view/download works.
- Confirm Excel export works.
- Add custom domain in Render (`Settings -> Custom Domains`).
- Enable HTTPS (automatic on Render).

## Notes

- Frontend API URLs are already production-safe (same-origin on hosted domain).
- If you run frontend separately in local LAN, it still targets `http://<host>:5000/api`.
