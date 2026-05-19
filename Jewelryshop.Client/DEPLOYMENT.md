# Deployment Guide

## Backend API

Recommended options:

- Render
- Railway
- Azure App Service
- VPS with PostgreSQL

Required environment settings:

```text
ConnectionStrings__DefaultConnection=your_postgres_connection_string
Cloudinary__CloudName=your_cloud_name
Cloudinary__ApiKey=your_api_key
Cloudinary__ApiSecret=your_api_secret
ASPNETCORE_ENVIRONMENT=Production
```

Build command:

```powershell
dotnet publish -c Release
```

## Frontend React

Recommended options:

- Netlify
- Vercel
- Render Static Site

Required environment variable:

```text
VITE_API_BASE_URL=https://your-backend-domain.com
```

Build command:

```powershell
npm.cmd install
npm.cmd run build
```

Publish folder:

```text
dist
```

## Local development

Backend:

```powershell
cd "c:\Users\hp\OneDrive\Desktop\jewelry shop\Jewelryshop.Api"
dotnet run
```

Frontend:

```powershell
cd "c:\Users\hp\OneDrive\Desktop\jewelry shop\Jewelryshop.Client"
npm.cmd run dev
```
