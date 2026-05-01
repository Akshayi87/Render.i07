# 🚀 AKSHU ADMIN SERVER

Complete Node.js server for managing Lua scripts with API key authentication.

## ⚡ Features
- ✅ API Key Management (Create, Delete, Monitor)
- ✅ Lua Script Upload & Distribution
- ✅ Encrypted Script Delivery
- ✅ Rate Limiting (60 req/min)
- ✅ Admin Dashboard (Responsive)
- ✅ SQLite Database (No setup needed)
- ✅ Request Logging
- ✅ Time-based key expiration

## 🔑 Default Credentials
- **Admin Username:** `akshu`
- **Admin Password:** `akshu123`
- **Default API Key:** `akshu-default-key-2024`

## 📁 Project Structure
```
akshu-admin-server/
├── server.js          # Main server file
├── package.json       # Dependencies
├── public/
│   ├── index.html     # Landing page
│   └── admin.html     # Admin panel
├── lua_scripts/       # Upload Lua files here
└── database/
    └── akshu.db       # SQLite database (auto-created)
```

## 🚀 Deploy on Render

### Step 1: Push to GitHub
1. Create new repo on GitHub
2. Upload these files
3. Commit and push

### Step 2: Create Render Account
1. Go to [render.com](https://render.com)
2. Login with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repo

### Step 3: Configure Settings
- **Name:** `akshu-admin` (or any name)
- **Runtime:** `Node`
- **Build Command:** `npm install`
- **Start Command:** `node server.js`
- **Plan:** Free

### Step 4: Deploy
Click "Create Web Service" → Wait 2-3 minutes → Done!

Your URL will be: `https://akshu-admin.onrender.com`

## 🔌 API Endpoints

### Public API (for Lua scripts)
```
GET  /api/status?key=YOUR_KEY     → Check key status
GET  /api/script?key=YOUR_KEY     → Get script (base64)
POST /api/execute                 → Execute script (encrypted)
```

### Admin API
```
POST /admin/login                 → Login (returns session)
GET  /admin/stats                 → Dashboard stats
GET  /admin/keys                  → List all keys
POST /admin/keys                  → Create new key
DELETE /admin/keys/:id            → Delete key
GET  /admin/logs                  → View logs
GET  /admin/scripts               → List scripts
POST /admin/scripts               → Upload script
```

## 🛡️ Security Notes
- Change default password after first login
- Use HTTPS in production
- Rotate API keys regularly
- Monitor logs for suspicious activity
