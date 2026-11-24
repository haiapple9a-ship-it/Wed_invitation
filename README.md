# 💍 Wedding Invitation System (Backend & Security Architecture)
**សិរីសួស្ដី អាពាហ៍ពិពាហ៍ | Luxury Khmer Wedding Invitation & RSVP Management**

---

## 🌟 Overview

This project provides a complete, hardened, production-grade **Node.js / Express** backend with **SQLite (`node:sqlite`)** database persistence, an **Anti-Bot & Anti-Spam Security Layer**, and a dedicated **Admin Management Portal** for the wedding invitation web application.

---

## 🚀 Quick Start

### 1. Requirements
- **Node.js** v22+ or v24+ (uses native `node:sqlite` for high performance and zero native compilation issues)
- **npm** v10+

### 2. Start the Server
From `c:\Users\Administrator\Downloads\Wedding_Invite`:

```bash
# Normal Start
npm start

# Development Mode (auto-restart on changes)
npm run dev

# Run Automated Security & Functionality Tests
npm test
```

### 3. Open in Browser
- **Guest Wedding Invitation:** [http://localhost:3000](http://localhost:3000)
- **Admin Management Dashboard:** [http://localhost:3000/admin](http://localhost:3000/admin)

---

## 🔐 Default Admin Credentials

| Field | Value |
|---|---|
| **URL** | [http://localhost:3000/admin](http://localhost:3000/admin) |
| **Username** | `admin` |
| **Password** | `Wedding2026!Secure` |

> 💡 **Tip:** You can change your password directly from the Admin Dashboard using the **"ប្តូរពាក្យសម្ងាត់ (Change Password)"** button, or customize the defaults in `.env`.

---

## 🛡️ Security Protections Implemented

### 1. Anti-Bot & Honeypot Trap
- Forms include an invisible honeypot trap field (`preferred_venue_code`).
- Automated spam scripts and bots that blindly fill all form fields are silently caught and discarded without polluting your database or Google Sheet.

### 2. Rate Limiting (`express-rate-limit`)
- **RSVP Submissions:** Limited to 10 submissions per 15 minutes per IP to prevent spam floods and DoS.
- **Admin Login:** Strictly limited to 5 attempts per 15 minutes per IP to completely block credential stuffing and brute-force attacks.
- **General API:** 200 requests per 15 minutes.

### 3. HTTP Security Headers (`helmet`)
- Strict **Content Security Policy (CSP)** restricting scripts, styles, fonts, and images to authorized domains.
- `X-Frame-Options: SAMEORIGIN` (prevents clickjacking attacks).
- `X-Content-Type-Options: nosniff` (prevents MIME sniffing).
- `Referrer-Policy: strict-origin-when-cross-origin`.

### 4. Input Sanitization & 100% SQL Injection Immunity
- All input fields (`name`, `status`, `wish`) are strictly validated and sanitized (HTML tag stripping, length limiting).
- Database operations use **Parameterized Prepared Statements** via `node:sqlite`, making SQL injection impossible.

### 5. Secure Session & Password Management
- Passwords hashed using **Node's native `scrypt`** with unique cryptographic salts (`crypto.randomBytes(16)`).
- Verification uses **`crypto.timingSafeEqual`** to prevent side-channel timing attacks.
- Sessions use **`HttpOnly`**, **`SameSite=Strict`** cookies with cryptographically random 256-bit tokens, preventing XSS-based cookie theft.
- Expired sessions are automatically pruned every hour.

### 6. Guest Privacy (Salted IP Hashing)
- Raw guest IP addresses are never stored in plain text.
- An HMAC-SHA256 salted hash is used for rate-limiting and abuse tracking, respecting guest privacy.

### 7. Google Sheets Sync Proxy
- Previously, the Google Apps Script URL was exposed in client-side JavaScript.
- Now, the URL is stored securely on the server in `.env`.
- The server forwards RSVPs to Google Sheets in the background without exposing the endpoint to the public or stalling the guest's browser if Google is slow.

---

## 📊 Admin Dashboard Features (`/admin`)

- **Live Guest Statistics:** Instant counters for Total Responses, Attending Guests (អញ្ជើញចូលរួម), Regrets/Declined (អភ័យទោសខកខាន), and Total Wishes.
- **Real-Time Search:** Search guests by name or wish keywords instantly.
- **Status Filter:** Switch between "All", "Attending", and "Declined".
- **Excel / CSV Export:** One-click download with **UTF-8 Byte Order Mark (BOM)** so all Khmer characters display correctly in Microsoft Excel.
- **Guest Deletion:** Moderation controls to remove duplicates or test entries.
- **Change Password:** Secure in-dashboard password update modal.

---

## 📁 File Structure

```text
c:\Users\Administrator\Downloads\Wedding_Invite\
├── .env                  # Private server configuration & credentials (git-ignored)
├── .env.example          # Template configuration
├── .gitignore            # Git exclusion rules
├── package.json          # Dependencies & scripts
├── server.js             # Express application & API routes
├── db.js                 # SQLite database & data access layer
├── auth.js               # Crypto auth, password hashing & session middleware
├── test_server.js        # Automated security & feature test suite
├── README.md             # This documentation
├── admin/
│   └── index.html        # Royal dark-gold Khmer Admin Dashboard
├── data/
│   └── wedding.db        # SQLite database (auto-created)
└── Wedding_Invite/       # Wedding Invitation Frontend
    ├── Index.html        # Main wedding invitation page with secure RSVP & wishes wall
    └── [media assets]    # Photos, audio (mp3), video (mp4), and QR codes
```

---

## 🌐 Production Deployment Tips

1. Set `NODE_ENV=production` in `.env`.
2. Generate a long, random secret for `SESSION_SECRET`:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
3. Set `COOKIE_SECURE=true` once running behind HTTPS (e.g., Nginx, Caddy, or Cloudflare).
4. Run continuously using PM2:
   ```bash
   npm install -g pm2
   pm2 start server.js --name "wedding-invite"
   pm2 save
   ```
