const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'wedding.db');
const db = new DatabaseSync(dbPath);

// Enable WAL mode for concurrency and foreign keys
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

function initDb(defaultAdminUsername, defaultAdminPasswordHash, defaultAdminSalt) {
    // 1. RSVPs Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            wish TEXT,
            ip_hash TEXT,
            is_hidden INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_rsvps_status ON rsvps(status);
        CREATE INDEX IF NOT EXISTS idx_rsvps_created_at ON rsvps(created_at);
    `);

    // Ensure is_hidden column exists for existing databases
    try {
        db.exec('ALTER TABLE rsvps ADD COLUMN is_hidden INTEGER DEFAULT 0;');
    } catch (e) {
        // Column already exists
    }

    // 2. Admin Users Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    `);

    // 3. Admin Sessions Table
    db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
    `);

    // Ensure default admin user exists if table is empty
    if (defaultAdminUsername && defaultAdminPasswordHash && defaultAdminSalt) {
        const countRow = db.prepare('SELECT COUNT(*) as count FROM admin_users').get();
        if (countRow.count === 0) {
            const insertAdmin = db.prepare(`
                INSERT INTO admin_users (username, password_hash, salt)
                VALUES (?, ?, ?)
            `);
            insertAdmin.run(defaultAdminUsername, defaultAdminPasswordHash, defaultAdminSalt);
            console.log(`[DB] Created default admin user: "${defaultAdminUsername}"`);
        }
    }
}

// RSVP Operations
function addRsvp({ name, status, wish, ipHash }) {
    const stmt = db.prepare(`
        INSERT INTO rsvps (name, status, wish, ip_hash)
        VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(name, status, wish, ipHash);
    return {
        id: result.lastInsertRowid,
        name,
        status,
        wish,
        created_at: new Date().toISOString()
    };
}

function getRsvps({ search = '', status = '', limit = 50, offset = 0 } = {}) {
    let query = 'SELECT id, name, status, wish, is_hidden, created_at FROM rsvps WHERE 1=1';
    const params = [];

    if (status) {
        query += ' AND status = ?';
        params.push(status);
    }
    if (search) {
        query += ' AND (name LIKE ? OR wish LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    return db.prepare(query).all(...params);
}

function getRsvpCount({ search = '', status = '' } = {}) {
    let query = 'SELECT COUNT(*) as count FROM rsvps WHERE 1=1';
    const params = [];

    if (status) {
        query += ' AND status = ?';
        params.push(status);
    }
    if (search) {
        query += ' AND (name LIKE ? OR wish LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }

    const row = db.prepare(query).get(...params);
    return row ? row.count : 0;
}

function getStats() {
    const totalRow = db.prepare('SELECT COUNT(*) as count FROM rsvps').get();
    const attendingRow = db.prepare("SELECT COUNT(*) as count FROM rsvps WHERE status LIKE '%អញ្ជើញ%' OR status LIKE '%attending%'").get();
    const declinedRow = db.prepare("SELECT COUNT(*) as count FROM rsvps WHERE status LIKE '%អភ័យទោស%' OR status LIKE '%declined%'").get();
    const wishRow = db.prepare("SELECT COUNT(*) as count FROM rsvps WHERE wish IS NOT NULL AND TRIM(wish) != '' AND wish != 'គ្មានពាក្យជូនពរទេ'").get();

    return {
        total: totalRow.count,
        attending: attendingRow.count,
        declined: declinedRow.count,
        wishesCount: wishRow.count
    };
}

function getRecentWishes(limit = 20) {
    const stmt = db.prepare(`
        SELECT id, name, wish, created_at
        FROM rsvps
        WHERE (is_hidden IS NULL OR is_hidden = 0)
          AND wish IS NOT NULL AND TRIM(wish) != '' AND wish != 'គ្មានពាក្យជូនពរទេ'
        ORDER BY id DESC
        LIMIT ?
    `);
    return stmt.all(limit);
}

function toggleHideRsvp(id) {
    const row = db.prepare('SELECT is_hidden FROM rsvps WHERE id = ?').get(id);
    if (!row) return null;
    const newStatus = (row.is_hidden === 1) ? 0 : 1;
    db.prepare('UPDATE rsvps SET is_hidden = ? WHERE id = ?').run(newStatus, id);
    return newStatus;
}

function deleteRsvp(id) {
    const stmt = db.prepare('DELETE FROM rsvps WHERE id = ?');
    stmt.run(id);
    return true;
}

function getAllRsvpsForExport() {
    return db.prepare('SELECT id, name, status, wish, is_hidden, created_at FROM rsvps ORDER BY id ASC').all();
}

// Admin Operations
function getAdminByUsername(username) {
    return db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
}

function updateAdminPassword(username, passwordHash, salt) {
    const stmt = db.prepare(`
        UPDATE admin_users
        SET password_hash = ?, salt = ?
        WHERE username = ?
    `);
    stmt.run(passwordHash, salt, username);
    return true;
}

// Session Operations
function createSession(token, username, expiresAt) {
    const stmt = db.prepare(`
        INSERT INTO sessions (token, username, expires_at)
        VALUES (?, ?, ?)
    `);
    stmt.run(token, username, expiresAt);
}

function getSession(token) {
    const now = Date.now();
    const session = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(token, now);
    return session || null;
}

function deleteSession(token) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
}

function cleanupExpiredSessions() {
    const now = Date.now();
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
}

module.exports = {
    initDb,
    addRsvp,
    getRsvps,
    getRsvpCount,
    getStats,
    getRecentWishes,
    toggleHideRsvp,
    deleteRsvp,
    getAllRsvpsForExport,
    getAdminByUsername,
    updateAdminPassword,
    createSession,
    getSession,
    deleteSession,
    cleanupExpiredSessions
};
