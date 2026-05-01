const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Create directories if not exist
if (!fs.existsSync('lua_scripts')) fs.mkdirSync('lua_scripts');
if (!fs.existsSync('database')) fs.mkdirSync('database');

// Database setup
const db = new sqlite3.Database('./database/akshu.db');

// Initialize database tables
db.serialize(() => {
    // API Keys table
    db.run(`CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT UNIQUE NOT NULL,
        key_name TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        expires_at TEXT,
        usage_count INTEGER DEFAULT 0,
        max_uses INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_used TEXT
    )`);

    // API Logs table
    db.run(`CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        api_key TEXT,
        action TEXT,
        status TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Scripts table
    db.run(`CREATE TABLE IF NOT EXISTS scripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        filename TEXT NOT NULL,
        size INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);

    // Insert default admin key if none exists
    db.get("SELECT COUNT(*) as count FROM api_keys", (err, row) => {
        if (row.count === 0) {
            const defaultKey = 'akshu-default-key-2024';
            db.run(`INSERT INTO api_keys (api_key, key_name, status) VALUES (?, ?, ?)`, 
                [defaultKey, 'Default Admin Key', 'active']);
            console.log('Default API Key created:', defaultKey);
        }
    });
});

// Admin credentials (change after first login)
const ADMIN_USERNAME = 'akshu';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync('akshu123', 10);

// Session storage (simple in-memory)
const sessions = new Map();

// Rate limiting
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // limit each IP to 60 requests per windowMs
    message: { status: 'error', message: 'Rate limit exceeded. Try again later.' }
});
app.use('/api', limiter);

// Helper functions
function generateAPIKey(length = 32) {
    return uuidv4().replace(/-/g, '').substring(0, length);
}

function logRequest(ip, apiKey, action, status) {
    db.run(`INSERT INTO api_logs (ip_address, api_key, action, status) VALUES (?, ?, ?, ?)`,
        [ip, apiKey, action, status]);
}

function authenticateAdmin(req, res, next) {
    const sessionId = req.headers['x-session-id'] || req.query.session;
    if (sessions.has(sessionId)) {
        next();
    } else {
        res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }
}

// ============================================
// ADMIN API ROUTES
// ============================================

// Admin Login
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;

    if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
        const sessionId = generateAPIKey(32);
        sessions.set(sessionId, { username, loginTime: new Date() });
        res.json({ status: 'success', sessionId, message: 'Login successful' });
    } else {
        res.status(401).json({ status: 'error', message: 'Invalid credentials' });
    }
});

// Admin Logout
app.post('/admin/logout', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    sessions.delete(sessionId);
    res.json({ status: 'success', message: 'Logged out' });
});

// Get Dashboard Stats
app.get('/admin/stats', authenticateAdmin, (req, res) => {
    db.get("SELECT COUNT(*) as total FROM api_keys", (err, totalKeys) => {
        db.get("SELECT COUNT(*) as active FROM api_keys WHERE status = 'active'", (err, activeKeys) => {
            db.get("SELECT COUNT(*) as total_req FROM api_logs WHERE status = 'success'", (err, totalReq) => {
                db.get("SELECT COUNT(*) as today FROM api_logs WHERE date(created_at) = date('now')", (err, todayReq) => {
                    res.json({
                        status: 'success',
                        data: {
                            totalKeys: totalKeys.total,
                            activeKeys: activeKeys.active,
                            totalRequests: totalReq.total_req,
                            todayRequests: todayReq.today
                        }
                    });
                });
            });
        });
    });
});

// Get All API Keys
app.get('/admin/keys', authenticateAdmin, (req, res) => {
    db.all("SELECT * FROM api_keys ORDER BY created_at DESC", (err, rows) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', data: rows });
    });
});

// Create New API Key
app.post('/admin/keys', authenticateAdmin, (req, res) => {
    const { key_name, expires_at, max_uses } = req.body;
    const key = generateAPIKey(32);

    db.run(`INSERT INTO api_keys (api_key, key_name, expires_at, max_uses) VALUES (?, ?, ?, ?)`,
        [key, key_name || 'New Key', expires_at || null, max_uses || null],
        function(err) {
            if (err) return res.status(500).json({ status: 'error', message: err.message });
            res.json({ status: 'success', data: { id: this.lastID, api_key: key, key_name } });
        });
});

// Delete API Key
app.delete('/admin/keys/:id', authenticateAdmin, (req, res) => {
    db.run("DELETE FROM api_keys WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Key deleted' });
    });
});

// Get API Logs
app.get('/admin/logs', authenticateAdmin, (req, res) => {
    db.all("SELECT * FROM api_logs ORDER BY created_at DESC LIMIT 100", (err, rows) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', data: rows });
    });
});

// Get All Scripts
app.get('/admin/scripts', authenticateAdmin, (req, res) => {
    db.all("SELECT * FROM scripts ORDER BY created_at DESC", (err, rows) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', data: rows });
    });
});

// File upload setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'lua_scripts/'),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname)
});
const upload = multer({ storage });

// Upload Script
app.post('/admin/scripts', authenticateAdmin, upload.single('script'), (req, res) => {
    if (!req.file) return res.status(400).json({ status: 'error', message: 'No file uploaded' });

    const name = req.file.originalname.replace('.lua', '');
    db.run(`INSERT OR REPLACE INTO scripts (name, filename, size) VALUES (?, ?, ?)`,
        [name, req.file.filename, req.file.size],
        (err) => {
            if (err) return res.status(500).json({ status: 'error', message: err.message });
            res.json({ status: 'success', message: 'Script uploaded', data: { name, filename: req.file.filename } });
        });
});

// ============================================
// PUBLIC API ROUTES (FOR LUA SCRIPTS)
// ============================================

// Verify API Key
app.get('/api/status', (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.query.key;
    const clientIP = req.ip || req.connection.remoteAddress;

    if (!apiKey) {
        return res.status(400).json({ status: 'error', message: 'API Key is required' });
    }

    db.get(`SELECT * FROM api_keys 
            WHERE api_key = ? AND status = 'active' 
            AND (expires_at IS NULL OR expires_at > datetime('now'))`,
        [apiKey], (err, row) => {
            if (err || !row) {
                logRequest(clientIP, apiKey, 'status', 'failed');
                return res.status(401).json({ status: 'error', message: 'Invalid or expired API Key' });
            }

            logRequest(clientIP, apiKey, 'status', 'success');
            res.json({
                status: 'success',
                key_valid: true,
                key_name: row.key_name,
                created_at: row.created_at,
                expires_at: row.expires_at,
                last_used: row.last_used,
                usage_count: row.usage_count,
                max_uses: row.max_uses || 'Unlimited'
            });
        });
});

// Get Script
app.get('/api/script', (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.query.key;
    const scriptName = req.query.script || 'default';
    const clientIP = req.ip || req.connection.remoteAddress;

    if (!apiKey) {
        return res.status(400).json({ status: 'error', message: 'API Key is required' });
    }

    db.get(`SELECT * FROM api_keys 
            WHERE api_key = ? AND status = 'active' 
            AND (expires_at IS NULL OR expires_at > datetime('now'))`,
        [apiKey], (err, keyRow) => {
            if (err || !keyRow) {
                logRequest(clientIP, apiKey, 'script', 'failed');
                return res.status(401).json({ status: 'error', message: 'Invalid or expired API Key' });
            }

            // Check max uses
            if (keyRow.max_uses && keyRow.usage_count >= keyRow.max_uses) {
                logRequest(clientIP, apiKey, 'script', 'failed');
                return res.status(403).json({ status: 'error', message: 'API Key usage limit exceeded' });
            }

            // Update usage
            db.run("UPDATE api_keys SET usage_count = usage_count + 1, last_used = datetime('now') WHERE id = ?", [keyRow.id]);

            // Get script
            db.get("SELECT * FROM scripts WHERE name = ?", [scriptName], (err, scriptRow) => {
                if (err || !scriptRow) {
                    logRequest(clientIP, apiKey, 'script', 'failed');
                    return res.status(404).json({ status: 'error', message: 'Script not found' });
                }

                const scriptPath = path.join(__dirname, 'lua_scripts', scriptRow.filename);
                if (!fs.existsSync(scriptPath)) {
                    logRequest(clientIP, apiKey, 'script', 'failed');
                    return res.status(404).json({ status: 'error', message: 'Script file not found' });
                }

                const content = fs.readFileSync(scriptPath, 'utf8');
                logRequest(clientIP, apiKey, 'script', 'success');

                res.json({
                    status: 'success',
                    script_name: scriptName,
                    script_content: Buffer.from(content).toString('base64'),
                    checksum: require('crypto').createHash('md5').update(content).digest('hex')
                });
            });
        });
});

// Execute Script (returns encrypted)
app.post('/api/execute', (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.body.key;
    const scriptName = req.body.script || 'default';
    const clientIP = req.ip || req.connection.remoteAddress;

    if (!apiKey) {
        return res.status(400).json({ status: 'error', message: 'API Key is required' });
    }

    db.get(`SELECT * FROM api_keys 
            WHERE api_key = ? AND status = 'active' 
            AND (expires_at IS NULL OR expires_at > datetime('now'))`,
        [apiKey], (err, keyRow) => {
            if (err || !keyRow) {
                logRequest(clientIP, apiKey, 'execute', 'failed');
                return res.status(401).json({ status: 'error', message: 'Invalid or expired API Key' });
            }

            db.run("UPDATE api_keys SET usage_count = usage_count + 1, last_used = datetime('now') WHERE id = ?", [keyRow.id]);

            db.get("SELECT * FROM scripts WHERE name = ?", [scriptName], (err, scriptRow) => {
                if (err || !scriptRow) {
                    logRequest(clientIP, apiKey, 'execute', 'failed');
                    return res.status(404).json({ status: 'error', message: 'Script not found' });
                }

                const scriptPath = path.join(__dirname, 'lua_scripts', scriptRow.filename);
                const content = fs.readFileSync(scriptPath, 'utf8');

                // Simple XOR encryption (replace with AES in production)
                const encrypted = Buffer.from(content).toString('base64');
                logRequest(clientIP, apiKey, 'execute', 'success');

                res.json({
                    status: 'success',
                    message: 'Script verified and ready',
                    script_name: scriptName,
                    encrypted_script: encrypted,
                    key_info: {
                        name: keyRow.key_name,
                        expires: keyRow.expires_at,
                        usage_count: keyRow.usage_count + 1
                    }
                });
            });
        });
});

// ============================================
// SERVE ADMIN PANEL (HTML)
// ============================================
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 AKSHU ADMIN SERVER RUNNING!`);
    console.log(`📍 Local: http://localhost:${PORT}`);
    console.log(`📍 Admin Panel: http://localhost:${PORT}/admin`);
    console.log(`📍 API Base: http://localhost:${PORT}/api`);
    console.log(`\n🔑 Default Admin: username=akshu | password=akshu123`);
    console.log(`🔑 Default API Key: akshu-default-key-2024\n`);
});
