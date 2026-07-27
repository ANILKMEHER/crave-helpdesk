const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./helpdesk.db', (err) => {
    if (err) console.error("Database initialization error:", err.message);
});
require('dotenv').config();
const msal = require('@azure/msal-node');
const session = require('express-session');

// MSAL Configuration
const msalConfig = {
    auth: {
        clientId: process.env.CLIENT_ID,
        authority: `https://login.microsoftonline.com/${process.env.TENANT_ID}`,
        clientSecret: process.env.CLIENT_SECRET,
    }
};

const cca = new msal.ConfidentialClientApplication(msalConfig);

// Configure Express Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true in production with HTTPS
}));

// Middleware Guard: Strictly allow Admin access only
function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'Admin') {
        return next();
    }
    return res.status(403).json({ error: "Access Denied: Master Admin privileges required." });
}

// 1. GET: Fetch all registered users for Admin Management
app.get('/api/admin/users', requireAdmin, (req, res) => {
    db.all(`SELECT id, email, name, role, created_at FROM users ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

// 2. PUT: Update an employee's role in real time
app.put('/api/admin/users/:id/role', requireAdmin, (req, res) => {
    const { role } = req.body;
    const userId = req.params.id;

    const validRoles = ['Employee', 'Helpdesk', 'Admin'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ error: "Invalid role specified." });
    }

    db.run(`UPDATE users SET role = ? WHERE id = ?`, [role, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `Role updated to ${role}` });
    });
});

// --- SSO AUTHENTICATION ROUTES ---

// 1. Initiate Login
app.get('/auth/login', async (req, res) => {
    const authCodeUrlParameters = {
        scopes: ["user.read"],
        redirectUri: process.env.REDIRECT_URI,
    };
    const authUrl = await cca.getAuthCodeUrl(authCodeUrlParameters);
    res.redirect(authUrl);
});

// 2. Auth Redirect Callback (Validates Crave Domain & Pulls Role)
// Auth Redirect Callback - Auto-Recovering Version
app.get('/auth/redirect', async (req, res) => {
    // If no auth code is present in query, send back to login
    if (!req.query.code) {
        return res.redirect('/auth/login');
    }

    const tokenRequest = {
        code: req.query.code,
        scopes: ["user.read"],
        redirectUri: process.env.REDIRECT_URI,
    };

    try {
        const response = await cca.acquireTokenByCode(tokenRequest);
        const userEmail = response.account.username.toLowerCase();
        const userName = response.account.name;

        // Domain restriction check
        if (!userEmail.endsWith(`@${process.env.ALLOWED_DOMAIN}`)) {
            return res.status(403).send(`
                <div style="font-family:sans-serif; padding:20px;">
                    <h2 style="color:#DC2626;">403 Access Denied</h2>
                    <p>Only verified <strong>@${process.env.ALLOWED_DOMAIN}</strong> accounts can log in.</p>
                </div>
            `);
        }

        // Fetch or Create User in DB
        db.get(`SELECT * FROM users WHERE email = ?`, [userEmail], (err, row) => {
            let role = 'Employee';
            if (row) {
                role = row.role;
            } else {
                db.run(`INSERT INTO users (email, name, role) VALUES (?, ?, 'Employee')`, [userEmail, userName]);
            }

            req.session.user = { email: userEmail, name: userName, role: role };
            res.redirect('/');
        });

    } catch (error) {
        console.error("SSO Token Exchange Error:", error.errorMessage || error);

        // If authorization code is expired, reused, or invalid, auto-retry with a clean login request
        if (error.errorCode === 'request_cannot_be_made' || error.errorCode === 'invalid_grant') {
            return res.redirect('/auth/login');
        }

        res.status(500).send(`
            <div style="font-family:sans-serif; padding:20px;">
                <h3>Authentication Error</h3>
                <p>${error.errorMessage || error.message}</p>
                <a href="/auth/login" style="padding:8px 12px; background:#0A58CA; color:white; text-decoration:none; border-radius:4px;">Try Logging In Again</a>
            </div>
        `);
    }
});
// 3. Logout Route
app.get('/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect(`https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri=http://localhost:3000/auth/login`);
    });
});

// 4. API to fetch logged-in user profile & role
app.get('/api/me', (req, res) => {
    if (!req.session.user) return res.status(401).json({ authenticated: false });
    res.json({ authenticated: true, user: req.session.user });
});

// --- ROLE-BASED MIDDLEWARE GUARDS ---
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ error: "Unauthorized" });
}

function requireHelpdeskOrAdmin(req, res, next) {
    if (req.session.user && (req.session.user.role === 'Helpdesk' || req.session.user.role === 'Admin')) {
        return next();
    }
    res.status(403).json({ error: "Forbidden: IT Helpdesk or Admin role required." });
}

// Structural schema updates
db.serialize(() => {
    // 1. Create Users Table with RBAC Roles
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        name TEXT,
        role TEXT DEFAULT 'Employee', -- 'Employee', 'Helpdesk', or 'Admin'
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 2. Existing Tickets Table
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_ref TEXT UNIQUE,
        user_id TEXT,
        subject TEXT,
        category TEXT,
        description TEXT,
        priority TEXT,
        input_handler TEXT,
        attachments TEXT,
        status TEXT DEFAULT 'Open',
        assigned_to TEXT DEFAULT 'Unassigned',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME
    )`);

    // Pre-seed an Admin User (Replace with your actual email)
    db.run(`INSERT OR IGNORE INTO users (email, name, role) VALUES ('anil.meher@craveinfotech.com', 'Anil Meher', 'Admin')`);
});
// Structural schema updates
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_ref TEXT UNIQUE,
        user_id TEXT DEFAULT 'CI-USER-101', 
        subject TEXT,
        category TEXT,
        description TEXT,
        priority TEXT,
        input_handler TEXT,
        attachments TEXT,
        status TEXT DEFAULT 'Open',
        assigned_to TEXT DEFAULT 'Unassigned',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER,
        note TEXT,
        changed_by TEXT DEFAULT 'System',
        changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Endpoint 1: Raise Ticket (Fixed insert matrix bindings)
app.post('/api/tickets', (req, res) => {
    const { subject, category, description, priority, user_id, input_handler, attachments } = req.body;
    const ticketRef = `TIC-${Math.floor(100000 + Math.random() * 900000)}`;
    const callerId = user_id || 'CI-USER-101';

    const query = `INSERT INTO tickets (ticket_ref, user_id, subject, category, description, priority, input_handler, attachments) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(query, [ticketRef, callerId, subject, category, description, priority || 'Low', input_handler || 'General', attachments || null], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        db.run(`INSERT INTO ticket_history (ticket_id, note, changed_by) VALUES (?, ?, ?)`, 
            [this.lastID, `Ticket logged under ${input_handler || 'General'} queue. Priority: ${priority || 'Low'}.`, 'Employee']);
        res.json({ success: true, ticket_ref: ticketRef });
    });
});

// Endpoint 2: Fetch Tickets
app.get('/api/tickets', (req, res) => {
    db.all(`SELECT * FROM tickets ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const now = new Date();
        const updatedRows = (rows || []).map(ticket => {
            let sla_breached = false;
            if (ticket.status !== 'Closed' && ticket.priority === 'Urgent') {
                const createdTime = new Date(ticket.created_at + " UTC");
                const hoursOpened = Math.abs(now - createdTime) / 36e5;
                if (hoursOpened > 4) sla_breached = true;
            }
            return { ...ticket, sla_breached };
        });
        res.json(updatedRows);
    });
});

// Endpoint 3: Update Ticket (Status / Assignment)
app.put('/api/tickets/:id', (req, res) => {
    const { status, note, assigned_to } = req.body;
    const ticketId = req.params.id;
    const resolvedAt = status === 'Closed' ? new Date().toISOString() : null;

    db.get(`SELECT * FROM tickets WHERE id = ?`, [ticketId], (err, ticket) => {
        if (!ticket) return res.status(404).json({ error: "Ticket missing." });

        const nextStatus = status || ticket.status;
        const nextAgent = assigned_to || ticket.assigned_to;

        db.run(`UPDATE tickets SET status = ?, assigned_to = ?, resolved_at = COALESCE(?, resolved_at) WHERE id = ?`, 
            [nextStatus, nextAgent, resolvedAt, ticketId], function(err) {
                if (err) return res.status(500).json({ error: err.message });

                let logNote = `Status modified to ${nextStatus}. Agent assigned: ${nextAgent}.`;
                if (note) logNote += ` Details: ${note}`;

                db.run(`INSERT INTO ticket_history (ticket_id, note, changed_by) VALUES (?, ?, ?)`, [ticketId, logNote, 'Agent/Admin']);
                res.json({ success: true });
        });
    });
});

// Endpoint 4: Log Timelines History
app.get('/api/tickets/:ref/history', (req, res) => {
    const refToken = req.params.ref;
    db.get(`SELECT * FROM tickets WHERE ticket_ref = ?`, [refToken], (err, ticket) => {
        if (err || !ticket) return res.status(404).json({ error: "History logs not found." });

        db.all(`SELECT * FROM ticket_history WHERE ticket_id = ? ORDER BY id DESC`, [ticket.id], (err, history) => {
            res.json({ ticket, history });
        });
    });
});

// Endpoint 5: Overview Analytical Aggregator with Priority Metrics
app.get('/api/analytics', (req, res) => {
    const { year, month } = req.query;
    const stats = {};
    
    let dateFilterClause = "1=1";
    let filterParams = [];

    if (year && year !== 'all') {
        dateFilterClause += " AND strftime('%Y', created_at) = ?";
        filterParams.push(year);
    }
    if (month && month !== 'all') {
        dateFilterClause += " AND strftime('%m', created_at) = ?";
        filterParams.push(month);
    }

    db.all(`SELECT status, COUNT(*) as count FROM tickets WHERE ${dateFilterClause} GROUP BY status`, filterParams, (err, rows) => {
        stats.statusCounts = rows || [];

        db.all(`SELECT category, COUNT(*) as count FROM tickets WHERE ${dateFilterClause} GROUP BY category ORDER BY count DESC`, filterParams, (err, rows) => {
            stats.categoryCounts = rows || [];

            db.all(`SELECT assigned_to, COUNT(*) as count FROM tickets WHERE assigned_to != 'Unassigned' AND ${dateFilterClause} GROUP BY assigned_to ORDER BY count DESC LIMIT 10`, filterParams, (err, rows) => {
                stats.topAssignees = rows || [];

                db.all(`SELECT assigned_to as resolver, COUNT(*) as count FROM tickets WHERE status='Closed' AND assigned_to != 'Unassigned' AND ${dateFilterClause} GROUP BY assigned_to ORDER BY count DESC LIMIT 10`, filterParams, (err, rows) => {
                    stats.topResolvers = rows || [];

                    // 5. Query Priority load distributions (For the new bar chart)
                    db.all(`SELECT priority, COUNT(*) as count FROM tickets WHERE ${dateFilterClause} GROUP BY priority`, filterParams, (err, rows) => {
                        stats.priorityCounts = rows || [];
                        res.json(stats);
                    });
                });
            });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});