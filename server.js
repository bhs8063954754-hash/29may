const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Hardcoded Admin Credentials
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'SecureAdminPassword123!';

// Render और लोकल दोनों के लिए ऑटोमैटिक फोल्डर क्रिएशन लॉजिक
const IS_RENDER = process.env.RENDER === 'true';
const BASE_DATA_DIR = IS_RENDER ? '/data' : __dirname;

const UPLOADS_DIR = path.join(BASE_DATA_DIR, 'uploads');
const DATA_DIR = path.join(BASE_DATA_DIR, 'data');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// SQLite डेटाबेस ऑटो-क्रिएशन
const db = new sqlite3.Database(path.join(DATA_DIR, 'metadata.db'), (err) => {
    if (err) console.error('Database error:', err.message);
    else console.log('Database initialized successfully.');
});

db.run(`CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    originalname TEXT NOT NULL,
    filepath TEXT NOT NULL,
    password_hash TEXT,
    expiry_type TEXT NOT NULL,
    expiry_time INTEGER,
    download_count INTEGER DEFAULT 0
)`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniquePrefix = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
        cb(null, uniquePrefix + '-' + file.originalname);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB Limit
});

// Auto-Delete Cron Job (Every 1 minute)
setInterval(() => {
    const now = Date.now();
    db.all(`SELECT * FROM files WHERE expiry_time IS NOT NULL AND expiry_time <= ?`, [now], (err, rows) => {
        if (err) return;
        rows.forEach(file => {
            if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
            db.run(`DELETE FROM files WHERE id = ?`, [file.id]);
        });
    });
}, 60000);

// --- API ROUTES ---

app.post('/api/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
        const { password, expiry } = req.body;
        const fileId = crypto.randomBytes(8).toString('hex');
        
        let passwordHash = null;
        if (password && password.trim() !== "") {
            passwordHash = await bcrypt.hash(password, 10);
        }

        let expiryTime = null;
        const now = Date.now();
        if (expiry === '1h') expiryTime = now + (60 * 60 * 1000);
        else if (expiry === '24h') expiryTime = now + (24 * 60 * 60 * 1000);
        
        db.run(
            `INSERT INTO files (id, filename, originalname, filepath, password_hash, expiry_type, expiry_time, download_count) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
            [fileId, req.file.filename, req.file.originalname, req.file.path, passwordHash, expiry, expiryTime],
            (err) => {
                if (err) return res.status(500).json({ error: 'Database saving error.' });
                const downloadLink = `${req.protocol}://${req.get('host')}/download/${fileId}`;
                res.json({ success: true, link: downloadLink });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Internal Error' });
    }
});

app.get('/api/file/:id', (req, res) => {
    db.get(`SELECT id, originalname, password_hash FROM files WHERE id = ?`, [req.params.id], (err, file) => {
        if (err || !file) return res.status(404).json({ error: 'File not found.' });
        res.json({ id: file.id, originalname: file.originalname, passwordRequired: !!file.password_hash });
    });
});

app.post('/api/download/:id', (req, res) => {
    const fileId = req.params.id;
    const { password } = req.body;

    db.get(`SELECT * FROM files WHERE id = ?`, [fileId], async (err, file) => {
        if (err || !file) return res.status(404).json({ error: 'File not found.' });

        if (file.expiry_time && Date.now() > file.expiry_time) {
            if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
            db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
            return res.status(410).json({ error: 'File expired.' });
        }

        if (file.password_hash) {
            if (!password) return res.status(401).json({ error: 'Password required.' });
            const match = await bcrypt.compare(password, file.password_hash);
            if (!match) return res.status(401).json({ error: 'Invalid password.' });
        }

        if (!fs.existsSync(file.filepath)) {
            db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
            return res.status(404).json({ error: 'File missing from server.' });
        }

        if (file.expiry_type === '1d') {
            res.download(file.filepath, file.originalname, () => {
                if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
                db.run(`DELETE FROM files WHERE id = ?`, [fileId]);
            });
        } else {
            db.run(`UPDATE files SET download_count = download_count + 1 WHERE id = ?`, [fileId], () => {
                res.download(file.filepath, file.originalname);
            });
        }
    });
});

app.post('/api/admin/dashboard', (req, res) => {
    if (req.body.username !== ADMIN_USERNAME || req.body.password !== ADMIN_PASSWORD) {
        return res.status(403).json({ error: 'Unauthorized.' });
    }
    db.all(`SELECT id, originalname, expiry_type, download_count FROM files`, [], (err, rows) => {
        res.json({ success: true, files: rows });
    });
});

app.post('/api/admin/delete', (req, res) => {
    if (req.body.username !== ADMIN_USERNAME || req.body.password !== ADMIN_PASSWORD) {
        return res.status(403).json({ error: 'Unauthorized.' });
    }
    db.get(`SELECT filepath FROM files WHERE id = ?`, [req.body.fileId], (err, file) => {
        if (file && fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
        db.run(`DELETE FROM files WHERE id = ?`, [req.body.fileId], () => {
            res.json({ success: true });
        });
    });
});

// --- INBUILT FRONTEND HTML ---
const HTML_CONTENT = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>24/7 Advanced File Cloud</title>
    <style>
        :root { --bg-p: #0f172a; --bg-s: #1e293b; --accent: #3b82f6; --text: #f8fafc; --text-m: #94a3b8; --danger: #ef4444; }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: sans-serif; }
        body { background: var(--bg-p); color: var(--text); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { background: var(--bg-s); width: 100%; max-width: 600px; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h1, h2 { text-align: center; margin-bottom: 20px; }
        .subtitle { text-align: center; color: var(--text-m); margin-bottom: 30px; font-size: 14px; }
        .drop-zone { border: 2px dashed var(--accent); border-radius: 8px; padding: 40px 20px; text-align: center; cursor: pointer; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-size: 14px; color: var(--text-m); }
        input, select, button { width: 100%; padding: 12px; background: var(--bg-p); border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 14px; outline: none; }
        button { background: var(--accent); font-weight: bold; cursor: pointer; border: none; margin-top: 10px; }
        .progress-container { display: none; margin: 20px 0; }
        .progress-bar { width: 100%; background: var(--bg-p); height: 10px; border-radius: 5px; overflow: hidden; }
        .progress-fill { width: 0%; height: 100%; background: var(--accent); }
        .alert { padding: 12px; border-radius: 6px; font-size: 14px; margin-bottom: 20px; display: none; text-align: center; background: rgba(239, 68, 68, 0.2); border: 1px solid var(--danger); }
        .result-panel { display: none; background: var(--bg-p); padding: 20px; border-radius: 8px; margin-top: 20px; text-align: center; }
        .share-link { word-break: break-all; color: var(--accent); font-weight: bold; display: block; margin-bottom: 15px; }
        .admin-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .admin-table th, .admin-table td { padding: 10px; text-align: left; border-bottom: 1px solid #334155; }
        .hidden { display: none !important; }
    </style>
</head>
<body>
<div class="container">
    <div id="alertBox" class="alert"></div>

    <!-- UPLOAD VIEW -->
    <div id="uploadView">
        <h1>CloudVault 24/7</h1>
        <p class="subtitle">Secure, fast, and configuration-free file hosting.</p>
        <form id="uploadForm">
            <div class="drop-zone" id="dropZone">
                <p id="dropZoneText">Drag & drop file here or click to browse</p>
                <input type="file" id="fileInput" class="hidden" required>
            </div>
            <div class="form-group"><label>Optional File Password</label><input type="password" id="filePassword"></div>
            <div class="form-group">
                <label>Auto-Destruction Config</label>
                <select id="fileExpiry">
                    <option value="never">Never</option>
                    <option value="1d">After 1 Download</option>
                    <option value="1h">After 1 Hour</option>
                    <option value="24h">After 24 Hours</option>
                </select>
            </div>
            <button type="submit">Deploy File</button>
        </form>
        <div class="progress-container" id="progressContainer">
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
        </div>
        <div class="result-panel" id="resultPanel">
            <h3>File Live At:</h3>
            <span class="share-link" id="shareLink"></span>
            <button id="copyBtn" style="background:#475569;">Copy Link</button>
        </div>
    </div>

    <!-- DOWNLOAD VIEW -->
    <div id="downloadView" class="hidden">
        <h2>Secure Download Gateway</h2>
        <p class="subtitle" id="downloadMetaText">Loading file data...</p>
        <div id="passwordFieldContainer" class="form-group hidden"><label>Password Protected</label><input type="password" id="downloadPassword"></div>
        <button id="downloadBtn">Download File</button>
    </div>

    <!-- ADMIN VIEW -->
    <div id="adminView" class="hidden">
        <h2>Admin Console</h2>
        <div id="adminAuthForm">
            <div class="form-group"><label>Username</label><input type="text" id="adminUser"></div>
            <div class="form-group"><label>Password</label><input type="password" id="adminPass"></div>
            <button id="adminLoginBtn">Login</button>
        </div>
        <div id="adminConsole" class="hidden">
            <table class="admin-table"><thead><tr><th>File</th><th>Downloads</th><th>Action</th></tr></thead><tbody id="adminTableBody"></tbody></table>
        </div>
    </div>
</div>

<script>
    const path = window.location.pathname;
    const isDownload = path.startsWith('/download/');
    const isAdmin = path === '/admin';
    const alertBox = document.getElementById('alertBox');

    function showMsg(msg, bg = 'rgba(239, 68, 68, 0.2)') { alertBox.textContent = msg; alertBox.style.background = bg; alertBox.style.display = 'block'; }

    if (!isDownload && !isAdmin) {
        const fileInput = document.getElementById('fileInput');
        document.getElementById('dropZone').addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', () => { if(fileInput.files.length) document.getElementById('dropZoneText').textContent = fileInput.files[0].name; });

        document.getElementById('uploadForm').addEventListener('submit', (e) => {
            e.preventDefault();
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('password', document.getElementById('filePassword').value);
            formData.append('expiry', document.getElementById('fileExpiry').value);

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/upload', true);
            document.getElementById('progressContainer').style.display = 'block';
            
            xhr.upload.onprogress = (e) => { if(e.lengthComputable) document.getElementById('progressFill').style.width = (e.loaded/e.total)*100 + '%'; };
            xhr.onload = () => {
                document.getElementById('progressContainer').style.display = 'none';
                const res = JSON.parse(xhr.responseText);
                if(xhr.status === 200) {
                    document.getElementById('resultPanel').style.display = 'block';
                    document.getElementById('shareLink').textContent = res.link;
                } else { showMsg(res.error); }
            };
            xhr.send(formData);
        });
        document.getElementById('copyBtn').addEventListener('click', () => { navigator.clipboard.writeText(document.getElementById('shareLink').textContent); alert('Copied!'); });
    }

    if (isDownload) {
        document.getElementById('uploadView').classList.add('hidden');
        document.getElementById('downloadView').classList.remove('hidden');
        const fileId = path.split('/').pop();

        fetch('/api/file/' + fileId).then(res => res.json()).then(file => {
            if(file.error) { document.getElementById('downloadMetaText').textContent = file.error; document.getElementById('downloadBtn').style.display='none'; }
            else {
                document.getElementById('downloadMetaText').textContent = "File: " + file.originalname;
                if(file.passwordRequired) document.getElementById('passwordFieldContainer').classList.remove('hidden');
            }
        });

        document.getElementById('downloadBtn').addEventListener('click', () => {
            fetch('/api/download/' + fileId, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: document.getElementById('downloadPassword').value })
            }).then(async res => {
                if(!res.ok) { const e = await res.json(); throw new Error(e.error); }
                return res.blob();
            }).then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = ""; document.body.appendChild(a); a.click(); a.remove();
            }).catch(err => showMsg(err.message));
        });
    }

    if (isAdmin) {
        document.getElementById('uploadView').classList.add('hidden');
        document.getElementById('adminView').classList.remove('hidden');
        
        const u = document.getElementById('adminUser'), p = document.getElementById('adminPass');
        function loadAdmin() {
            fetch('/api/admin/dashboard', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u.value, password: p.value }) })
            .then(res => res.json()).then(data => {
                if(data.error) return showMsg(data.error);
                document.getElementById('adminAuthForm').classList.add('hidden');
                document.getElementById('adminConsole').classList.remove('hidden');
                const tbody = document.getElementById('adminTableBody'); tbody.innerHTML = '';
                data.files.forEach(f => {
                    tbody.innerHTML += "<tr><td>"+f.originalname+"</td><td>"+f.download_count+"</td><td><button style='background:red;padding:5px;margin:0;' onclick=\\"purge('"+f.id+"')\\">Delete</button></td></tr>";
                });
            });
        }
        document.getElementById('adminLoginBtn').addEventListener('click', loadAdmin);
        window.purge = function(id) {
            fetch('/api/admin/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u.value, password: p.value, fileId: id }) }).then(loadAdmin);
        };
    }
</script>
</body>
</html>
`;

// Render HTML for routes
app.get('/', (req, res) => res.send(HTML_CONTENT));
app.get('/download/:id', (req, res) => res.send(HTML_CONTENT));
app.get('/admin', (req, res) => res.send(HTML_CONTENT));

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large! Max 50MB.' });
    }
    res.status(500).json({ error: err.message || 'Server Error' });
});

app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
