const assert = require('assert');
const http = require('http');

// Wait 1 second and then run test queries against localhost:3000
async function runTests() {
    console.log('--- STARTING BACKEND SECURITY & FUNCTIONALITY TESTS ---');

    const BASE_URL = 'http://127.0.0.1:3000';

    // Helper to send HTTP requests
    function request(path, options = {}, body = null) {
        return new Promise((resolve, reject) => {
            const url = new URL(path, BASE_URL);
            const req = http.request(url, options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: data,
                        json: () => {
                            try { return JSON.parse(data); } catch (e) { return null; }
                        }
                    });
                });
            });
            req.on('error', reject);
            if (body) {
                req.write(typeof body === 'string' ? body : JSON.stringify(body));
            }
            req.end();
        });
    }

    try {
        // Test 1: Check Static Home Page & Security Headers
        console.log('Test 1: Check Home Page & Security Headers...');
        const homeRes = await request('/');
        assert.strictEqual(homeRes.statusCode, 200, 'Home page should return 200');
        assert(homeRes.headers['x-content-type-options'], 'Missing X-Content-Type-Options');
        assert(homeRes.headers['content-security-policy'], 'Missing Content-Security-Policy');
        console.log('✓ Home page and Security Headers verified.');

        // Test 2: Submit Valid RSVP
        console.log('Test 2: Submit Valid RSVP...');
        const rsvpRes = await request('/api/rsvp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, {
            name: 'លោក សុខ និង ភរិយា',
            status: 'អញ្ជើញចូលរួម',
            wish: 'សូមជូនពរឱ្យគូស្វាមីភរិយាថ្មីមានសុភមង្គល និងស្រឡាញ់គ្នារហូតដល់ចាស់កោងខ្នង!'
        });
        assert.strictEqual(rsvpRes.statusCode, 200, 'RSVP should return 200');
        const rsvpJson = rsvpRes.json();
        assert.strictEqual(rsvpJson.success, true, 'RSVP success should be true');
        console.log('✓ Valid RSVP submission verified.');

        // Test 3: Anti-Bot Honeypot Trap
        console.log('Test 3: Anti-Bot Honeypot Trap...');
        const botRes = await request('/api/rsvp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, {
            name: 'SpamBot 3000',
            status: 'អញ្ជើញចូលរួម',
            wish: 'Buy cheap shoes at http://spam.com',
            preferred_venue_code: 'I AM A BOT'
        });
        assert.strictEqual(botRes.statusCode, 200, 'Honeypot returns 200 to fool bot');
        console.log('✓ Anti-Bot Honeypot verified.');

        // Test 4: Input Validation (Missing Name)
        console.log('Test 4: Input Validation (Missing Name)...');
        const invalidRes = await request('/api/rsvp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, {
            name: '',
            status: 'អញ្ជើញចូលរួម',
            wish: 'Hello'
        });
        assert.strictEqual(invalidRes.statusCode, 400, 'Empty name should return 400');
        console.log('✓ Input validation verified.');

        // Test 5: Get Recent Wishes Feed
        console.log('Test 5: Get Recent Wishes Feed...');
        const wishesRes = await request('/api/wishes');
        assert.strictEqual(wishesRes.statusCode, 200);
        const wishesJson = wishesRes.json();
        assert(Array.isArray(wishesJson.wishes), 'Wishes should be an array');
        assert(wishesJson.wishes.length > 0, 'Should have at least 1 wish');
        // Ensure bot spam did NOT enter the database
        const botInWishes = wishesJson.wishes.find(w => w.name === 'SpamBot 3000');
        assert(!botInWishes, 'Spambot entry must not be saved!');
        console.log('✓ Wishes feed & bot isolation verified.');

        // Test 6: Admin Login (Wrong Password)
        console.log('Test 6: Admin Login with Wrong Password...');
        const wrongLoginRes = await request('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, {
            username: 'admin',
            password: 'wrong_password_123'
        });
        assert.strictEqual(wrongLoginRes.statusCode, 401, 'Wrong password must return 401');
        console.log('✓ Invalid login rejection verified.');

        // Test 7: Admin Login (Correct Credentials)
        console.log('Test 7: Admin Login with Correct Credentials...');
        const correctLoginRes = await request('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, {
            username: 'admin',
            password: 'Wedding2026!Secure'
        });
        assert.strictEqual(correctLoginRes.statusCode, 200, 'Valid login should return 200');
        const cookies = correctLoginRes.headers['set-cookie'];
        assert(cookies && cookies.length > 0, 'Set-Cookie header must be present');
        assert(cookies[0].includes('HttpOnly'), 'Cookie must be HttpOnly');
        assert(cookies[0].includes('SameSite=Strict'), 'Cookie must be SameSite=Strict');
        const sessionCookie = cookies[0].split(';')[0];
        console.log('✓ Admin login and secure cookie verified.');

        // Test 8: Admin Protected Route (/api/admin/stats)
        console.log('Test 8: Admin Stats Route with Session...');
        const statsRes = await request('/api/admin/stats', {
            headers: { 'Cookie': sessionCookie }
        });
        assert.strictEqual(statsRes.statusCode, 200);
        const statsJson = statsRes.json();
        assert(statsJson.total >= 1, 'Total RSVPs should be at least 1');
        assert(statsJson.attending >= 1, 'Attending count should be at least 1');
        console.log('✓ Admin stats verified:', statsJson);

        // Test 9: Admin CSV Export with UTF-8 BOM
        console.log('Test 9: Admin CSV Export with UTF-8 BOM...');
        const exportRes = await request('/api/admin/export', {
            headers: { 'Cookie': sessionCookie }
        });
        assert.strictEqual(exportRes.statusCode, 200);
        assert(exportRes.headers['content-type'].includes('text/csv'), 'Content-Type must be text/csv');
        assert(exportRes.body.startsWith('\uFEFF'), 'CSV must start with UTF-8 BOM for Excel Khmer support');
        console.log('✓ Admin CSV export with UTF-8 BOM verified.');

        // Test 10: Admin Hide & Unhide RSVP Feature
        console.log('Test 10: Admin Hide & Unhide Feature...');
        const listRes = await request('/api/admin/rsvps', {
            headers: { 'Cookie': sessionCookie }
        });
        const listJson = listRes.json();
        assert(listJson.items && listJson.items.length > 0, 'Should have at least 1 RSVP item');
        const targetItem = listJson.items[0];

        // Toggle Hide
        const hideRes = await request(`/api/admin/rsvps/${targetItem.id}/hide`, {
            method: 'PATCH',
            headers: { 'Cookie': sessionCookie }
        });
        assert.strictEqual(hideRes.statusCode, 200);
        const hideJson = hideRes.json();
        assert.strictEqual(hideJson.is_hidden, 1, 'Item should be hidden (is_hidden = 1)');

        // Verify hidden wish is filtered out of public wishes wall
        const wishesAfterHide = await request('/api/wishes');
        const wishesAfterHideJson = wishesAfterHide.json();
        const foundInPublic = wishesAfterHideJson.wishes.find(w => w.id === targetItem.id);
        assert(!foundInPublic, 'Hidden wish must NOT be displayed on public wishes wall');

        // Toggle Unhide
        const unhideRes = await request(`/api/admin/rsvps/${targetItem.id}/hide`, {
            method: 'PATCH',
            headers: { 'Cookie': sessionCookie }
        });
        const unhideJson = unhideRes.json();
        assert.strictEqual(unhideJson.is_hidden, 0, 'Item should be unhidden (is_hidden = 0)');
        console.log('✓ Admin Hide/Unhide toggle verified.');

        console.log('\n========================================');
        console.log('🎉 ALL BACKEND & SECURITY TESTS PASSED!');
        console.log('========================================\n');
        process.exit(0);
    } catch (err) {
        console.error('❌ TEST FAILED:', err);
        process.exit(1);
    }
}

setTimeout(runTests, 1500);
