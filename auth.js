const crypto = require('crypto');
const db = require('./db');

const SESSION_COOKIE_NAME = 'wedding_session';
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const IP_SALT = process.env.SESSION_SECRET || 'wedding_invite_default_salt_2026';

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, storedHash, salt) {
    const computedHash = crypto.scryptSync(password, salt, 64).toString('hex');
    const computedBuf = Buffer.from(computedHash, 'hex');
    const storedBuf = Buffer.from(storedHash, 'hex');

    if (computedBuf.length !== storedBuf.length) {
        return false;
    }
    return crypto.timingSafeEqual(computedBuf, storedBuf);
}

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashIp(ip) {
    if (!ip) return 'unknown';
    return crypto.createHmac('sha256', IP_SALT).update(ip).digest('hex').substring(0, 16);
}

function sanitizeText(str, maxLength = 500) {
    if (typeof str !== 'string') return '';
    // Strip control characters, excessive whitespace, and basic HTML tags
    let clean = str
        .replace(/<[^>]*>/g, '') // remove HTML tags
        .replace(/[\r\n\t]+/g, ' ') // normalize whitespace
        .trim();
    if (clean.length > maxLength) {
        clean = clean.substring(0, maxLength);
    }
    return clean;
}

// Authentication middleware for protected admin routes
function requireAuth(req, res, next) {
    const token = req.cookies?.[SESSION_COOKIE_NAME] ||
                  (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.substring(7) : null);

    if (!token) {
        return res.status(401).json({ error: 'សូមចូលប្រើប្រាស់ជាមុនសិន (Authentication required)' });
    }

    const session = db.getSession(token);
    if (!session) {
        // Clear invalid cookie
        res.clearCookie(SESSION_COOKIE_NAME);
        return res.status(401).json({ error: 'សម័យការបានផុតកំណត់ សូមចូលម្តងទៀត (Session expired)' });
    }

    req.user = session.username;
    req.sessionToken = token;
    next();
}

module.exports = {
    SESSION_COOKIE_NAME,
    SESSION_DURATION_MS,
    generateSalt,
    hashPassword,
    verifyPassword,
    generateSessionToken,
    hashIp,
    sanitizeText,
    requireAuth
};
