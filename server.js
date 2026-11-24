const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const db = require('./db');
const auth = require('./auth');

// 1. Initialize Database & Default Admin
const defaultAdminUser = process.env.ADMIN_USERNAME || 'admin';
const defaultAdminPass = process.env.ADMIN_PASSWORD || 'Wedding2026!Secure';
const defaultSalt = auth.generateSalt();
const defaultPassHash = auth.hashPassword(defaultAdminPass, defaultSalt);

db.initDb(defaultAdminUser, defaultPassHash, defaultSalt);

// Clean up expired sessions periodically
setInterval(() => {
    try {
        db.cleanupExpiredSessions();
    } catch (e) {
        console.error('Session cleanup error:', e.message);
    }
}, 60 * 60 * 1000);

const app = express();
const PORT = process.env.PORT || 3000;

// Determine static directories
const nestedStaticDir = path.join(__dirname, 'Wedding_Invite');
const staticDir = fs.existsSync(path.join(nestedStaticDir, 'Index.html')) ? nestedStaticDir : __dirname;
const adminDir = path.join(__dirname, 'admin');

// Trust reverse proxies if configured
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

// 2. Security Middleware (Helmet)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                "'unsafe-eval'",
                "https://cdn.tailwindcss.com",
                "https://cdnjs.cloudflare.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com",
                "https://cdnjs.cloudflare.com",
                "data:"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "blob:",
                "https://images.unsplash.com"
            ],
            mediaSrc: [
                "'self'",
                "data:",
                "blob:"
            ],
            connectSrc: [
                "'self'",
                "blob:",
                "https://images.unsplash.com",
                "https://cdn.tailwindcss.com"
            ],
            frameAncestors: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// CORS Configuration (protect against unauthorized cross-site requests)
app.use(cors({
    origin: true,
    credentials: true
}));

// Parse Cookies & JSON with strict body limit (prevent memory exhaustion)
app.use(cookieParser());
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// 3. Rate Limiters
// General API Rate Limiter
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'សំណើរច្រើនពេក សូមព្យាយាមម្តងទៀតនៅពេលក្រោយ (Too many requests, please try again later)' },
    standardHeaders: true,
    legacyHeaders: false
});

// Strict RSVP Submission Limiter (anti-spam)
const rsvpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // max 10 submissions per IP in 15 mins
    message: { error: 'អ្នកបានបញ្ជូនទិន្នន័យច្រើនដងពេក សូមរង់ចាំបន្តិច (Too many RSVP submissions, please wait a moment)' },
    standardHeaders: true,
    legacyHeaders: false
});

// Strict Admin Login Limiter (anti-brute-force)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // max 5 attempts per IP in 15 mins
    message: { error: 'ការប៉ុនប៉ងចូលច្រើនពេក គណនីត្រូវបានផ្អាកបណ្តោះអាសន្ន ១៥ នាទី (Too many login attempts, please try again in 15 minutes)' },
    standardHeaders: true,
    legacyHeaders: false
});

// 4. API Endpoints

// [Public] Submit RSVP
app.post('/api/rsvp', rsvpLimiter, async (req, res) => {
    try {
        const { name, status, wish, hp, preferred_venue_code } = req.body;

        // Anti-Bot Honeypot Check: legitimate users won't fill hidden fields
        if (hp || preferred_venue_code) {
            // Silently pretend success to deceive automated bot scripts
            return res.json({ success: true, message: 'RSVP received' });
        }

        // Validate Name
        const cleanName = auth.sanitizeText(name, 100);
        if (!cleanName) {
            return res.status(400).json({ error: 'សូមបញ្ចូលឈ្មោះរបស់អ្នក (Guest name is required)' });
        }

        // Validate Status
        const cleanStatus = auth.sanitizeText(status, 50);
        if (!cleanStatus) {
            return res.status(400).json({ error: 'សូមជ្រើសរើសស្ថានភាពចូលរួម (Attendance status is required)' });
        }

        // Sanitize Wish (optional)
        const cleanWish = auth.sanitizeText(wish, 1000);

        // Salted hash of IP for privacy-preserving rate-limiting and analytics
        const ipHash = auth.hashIp(req.ip);

        // Save to SQLite
        const record = db.addRsvp({
            name: cleanName,
            status: cleanStatus,
            wish: cleanWish,
            ipHash
        });

        // Asynchronously forward to Google Sheets backup if configured
        const googleSheetsUrl = process.env.GOOGLE_SHEETS_SCRIPT_URL;
        if (googleSheetsUrl && googleSheetsUrl.startsWith('http')) {
            // Run in background without blocking response
            (async () => {
                try {
                    const formData = new URLSearchParams();
                    formData.append('name', cleanName);
                    formData.append('status', cleanStatus);
                    formData.append('wish', cleanWish || 'គ្មានពាក្យជូនពរទេ');

                    await fetch(googleSheetsUrl, {
                        method: 'POST',
                        body: formData
                    });
                } catch (gErr) {
                    console.error('[GoogleSheets Backup Error]:', gErr.message);
                }
            })();
        }

        return res.json({
            success: true,
            message: 'ការចូលរួមរបស់អ្នកត្រូវបានកត់ត្រាទុកដោយជោគជ័យ',
            data: { id: record.id, name: record.name, status: record.status }
        });
    } catch (err) {
        console.error('RSVP Error:', err);
        return res.status(500).json({ error: 'មានបញ្ហាបច្ចេកទេសក្នុងប្រព័ន្ធ សូមព្យាយាមម្តងទៀត' });
    }
});

// [Public] Get Recent Wishes (Guestbook Feed)
app.get('/api/wishes', generalLimiter, (req, res) => {
    try {
        const wishes = db.getRecentWishes(25);
        res.json({ wishes });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch wishes' });
    }
});

// [Admin] Login
app.post('/api/admin/login', loginLimiter, (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'សូមបញ្ចូលឈ្មោះអ្នកប្រើប្រាស់ និងពាក្យសម្ងាត់' });
        }

        const user = db.getAdminByUsername(username.trim());
        if (!user) {
            return res.status(401).json({ error: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវទេ' });
        }

        const isValid = auth.verifyPassword(password, user.password_hash, user.salt);
        if (!isValid) {
            return res.status(401).json({ error: 'ឈ្មោះអ្នកប្រើប្រាស់ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវទេ' });
        }

        // Generate session
        const token = auth.generateSessionToken();
        const expiresAt = Date.now() + auth.SESSION_DURATION_MS;
        db.createSession(token, user.username, expiresAt);

        // Set secure HttpOnly cookie
        res.cookie(auth.SESSION_COOKIE_NAME, token, {
            httpOnly: true,
            secure: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: auth.SESSION_DURATION_MS
        });

        return res.json({ success: true, username: user.username });
    } catch (err) {
        console.error('Login Error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// [Admin] Logout
app.post('/api/admin/logout', (req, res) => {
    const token = req.cookies?.[auth.SESSION_COOKIE_NAME];
    if (token) {
        db.deleteSession(token);
    }
    res.clearCookie(auth.SESSION_COOKIE_NAME);
    res.json({ success: true, message: 'Logged out successfully' });
});

// [Admin] Current User Info
app.get('/api/admin/me', auth.requireAuth, (req, res) => {
    res.json({ username: req.user });
});

// [Admin] Dashboard Stats
app.get('/api/admin/stats', auth.requireAuth, (req, res) => {
    try {
        const stats = db.getStats();
        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve stats' });
    }
});

// [Admin] List RSVPs with Pagination & Filters
app.get('/api/admin/rsvps', auth.requireAuth, (req, res) => {
    try {
        const search = req.query.search ? String(req.query.search).trim() : '';
        const status = req.query.status ? String(req.query.status).trim() : '';
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
        const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

        const items = db.getRsvps({ search, status, limit, offset });
        const total = db.getRsvpCount({ search, status });

        res.json({ items, total, limit, offset });
    } catch (err) {
        console.error('Error fetching RSVPs:', err);
        res.status(500).json({ error: 'Failed to retrieve RSVPs' });
    }
});

// [Admin] Toggle Hide RSVP (Hide/Unhide)
app.patch('/api/admin/rsvps/:id/hide', auth.requireAuth, (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!id) return res.status(400).json({ error: 'Invalid ID' });
        const newStatus = db.toggleHideRsvp(id);
        if (newStatus === null) return res.status(404).json({ error: 'រកមិនឃើញទិន្នន័យ (Record not found)' });
        res.json({
            success: true,
            is_hidden: newStatus,
            message: newStatus === 1 ? 'បានលាក់ទិន្នន័យដោយជោគជ័យ' : 'បានបង្ហាញទិន្នន័យឡើងវិញដោយជោគជ័យ'
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update visibility' });
    }
});

// [Admin] Delete RSVP
app.delete('/api/admin/rsvps/:id', auth.requireAuth, (req, res) => {
    try {
        const id = parseInt(req.params.id, 10);
        if (!id) return res.status(400).json({ error: 'Invalid ID' });
        db.deleteRsvp(id);
        res.json({ success: true, message: 'Deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete record' });
    }
});

// [Admin] Export RSVPs to CSV (with UTF-8 BOM for Khmer characters in Excel)
app.get('/api/admin/export', auth.requireAuth, (req, res) => {
    try {
        const rows = db.getAllRsvpsForExport();

        // CSV Header
        let csv = '\uFEFF'; // UTF-8 Byte Order Mark for Excel Khmer script rendering
        csv += '"ល.រ (ID)","ឈ្មោះភ្ញៀវ (Guest Name)","ស្ថានភាព (Status)","ពាក្យជូនពរ (Wish / Message)","ស្ថានភាពបង្ហាញ (Visibility)","កាលបរិច្ឆេទ (Date Submitted)"\r\n';

        rows.forEach(r => {
            const id = r.id;
            const name = (r.name || '').replace(/"/g, '""');
            const status = (r.status || '').replace(/"/g, '""');
            const wish = (r.wish || '').replace(/"/g, '""');
            const visibility = r.is_hidden === 1 ? 'បានលាក់ (Hidden)' : 'ធម្មតា (Visible)';
            const date = r.created_at ? new Date(r.created_at).toLocaleString('km-KH') : '';

            csv += `"${id}","${name}","${status}","${wish}","${visibility}","${date}"\r\n`;
        });

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="wedding_rsvps_${Date.now()}.csv"`);
        res.send(csv);
    } catch (err) {
        console.error('Export Error:', err);
        res.status(500).send('Error exporting CSV');
    }
});

// [Admin] Change Password
app.post('/api/admin/change-password', auth.requireAuth, (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword || newPassword.length < 8) {
            return res.status(400).json({ error: 'ពាក្យសម្ងាត់ថ្មីត្រូវតែមានយ៉ាងហោចណាស់ ៨ តួអក្សរ (New password must be at least 8 characters)' });
        }

        const user = db.getAdminByUsername(req.user);
        if (!user) {
            return res.status(404).json({ error: 'រកមិនឃើញអ្នកប្រើប្រាស់ទេ' });
        }

        const isValid = auth.verifyPassword(currentPassword, user.password_hash, user.salt);
        if (!isValid) {
            return res.status(400).json({ error: 'ពាក្យសម្ងាត់បច្ចុប្បន្នមិនត្រឹមត្រូវទេ' });
        }

        const newSalt = auth.generateSalt();
        const newHash = auth.hashPassword(newPassword, newSalt);
        db.updateAdminPassword(req.user, newHash, newSalt);

        res.json({ success: true, message: 'ពាក្យសម្ងាត់ត្រូវបានផ្លាស់ប្តូរដោយជោគជ័យ' });
    } catch (err) {
        console.error('Change Password Error:', err);
        res.status(500).json({ error: 'Failed to update password' });
    }
});

// 5. Static Files Serving
// Serve Admin Dashboard
app.use('/admin', express.static(adminDir));
app.get('/admin', (req, res) => {
    res.sendFile(path.join(adminDir, 'index.html'));
});

// Serve Wedding Invitation Static Assets & Index.html
app.use(express.static(staticDir, {
    maxAge: '1d',
    index: 'Index.html'
}));

// Fallback to Index.html for all other unmatched GET requests
app.use((req, res, next) => {
    if (req.method === 'GET' && !req.path.startsWith('/api/')) {
        res.sendFile(path.join(staticDir, 'Index.html'));
    } else {
        res.status(404).json({ error: 'Endpoint not found' });
    }
});

// 6. Global Error Handling Middleware (Always return clean JSON, never HTML)
app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }
    const statusCode = err.status || err.statusCode || 500;
    res.status(statusCode).json({
        error: err.message || 'Internal Server Error'
    });
});

// 6. Start Server
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`💍 Wedding Invitation Server is running!`);
    console.log(`🌐 Guest Invitation: http://localhost:${PORT}`);
    console.log(`🔐 Admin Dashboard:  http://localhost:${PORT}/admin`);
    console.log(`👤 Default Admin:    ${defaultAdminUser}`);
    console.log(`🔑 Default Password: ${defaultAdminPass}`);
    console.log(`📁 Static files from: ${staticDir}`);
    console.log(`=================================================`);
});
