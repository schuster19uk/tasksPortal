const express = require('express');
const path = require('path');
const pool = require('./database/pool'); // Imports your native mariadb pool
const session = require('express-session'); // Added express-session
// Todo Login endpoint
const bcrypt = require('bcrypt'); // Make sure this is at the top of server.js if it isn't already

require('dotenv').config();

const app = express();
app.use(express.json());
app.locals.db = pool;

// --- SESSION CONFIGURATION ---
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 600 * 60 * 1000, // Session auto-expires after 600 minutes of inactivity
        secure: false,          // Set to true if your server uses HTTPS/SSL in production
        httpOnly: true          // Helps protect against Cross-Site Scripting (XSS) attacks
    }
}));

app.use(express.static('views'));
app.use('/css', express.static(path.join(__dirname, 'css')));



// --- AUTH MIDDLEWARE ---


// Protects standard management routes
const adminAuth = (req, res, next) => {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    res.status(401).json({ error: 'Authentication required. Session expired.' });
};

// NEW: Protects multi-timezone management routes
const multiAdminAuth = (req, res, next) => {
    if (req.session && req.session.isMultiAdmin) {
        return next();
    }
    res.status(401).json({ error: 'Authentication required. Session expired.' });
};


// ── 2. NEW MEMBER AUTHENTICATION MIDDLEWARE (Uses database records) ────────
const memberAuth = (req, res, next) => {
    if (req.session && req.session.memberId) {
        return next();
    }
    res.status(401).json({ error: 'Portal authentication required.' });
};

// ── 3. PROJECT ADMIN MIDDLEWARE (restricts project creation to admin/owner) ─
// Must run after memberAuth (relies on req.session.memberTypeName being set).
const projectAdminAuth = (req, res, next) => {
    const typeName = (req.session.memberTypeName || '').toLowerCase();
    if (typeName === 'admin' || typeName === 'owner') {
        return next();
    }
    res.status(403).send('Only admins can create projects.');
};


// ── ADD THIS: MOUNT THE MEMBERS ROUTER WITH AUTH MIDDLEWARE ────────────────
const membersRouter = require('./routes/members');
app.use('/api/admin/members', adminAuth, membersRouter); 

// ... [Keep your existing authentication endpoints and standard booking APIs] ...

// ── ADD THIS: ROUTE TO SERVE THE HTML INTERFACE ────────────────────────────
// Protects your frontend management view to authorized administrators only
app.get('/admin/members', adminAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'views/members.html')); 
});


// --- AUTHENTICATION API ENDPOINTS ---

// Standard Login endpoint
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
        req.session.isAdmin = true; // Store authenticated status inside the session
        return res.json({ success: true, message: 'Logged in successfully' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});


// ── 3. MEMBER LOGIN ENDPOINT ──────────────────────────────────────────────
app.post('/api/auth/member-login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        // Query database table natively using the mariadb pool
        const rows = await pool.query(
            'SELECT member_id, display_name, username, password_hash, is_active FROM project_members WHERE username = ?',
            [username.trim()]
        );
        const member = rows[0];

        if (!member || !member.password_hash) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        if (!member.is_active) {
            return res.status(403).json({ error: 'This portal account is currently inactive.' });
        }

        // Compare using bcrypt
        const match = await bcrypt.compare(password, member.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // Write specific session properties completely separate from the root admin block
        req.session.memberId = member.member_id.toString(); // stringified BigInt
        req.session.memberDisplayName = member.display_name;

        res.json({ success: true, displayName: member.display_name });
    } catch (err) {
        console.error('[Member login error]', err);
        res.status(500).json({ error: 'Database authentication error.' });
    }
});



// ── NEW DATABASE-DRIVEN MEMBER LOGIN ─────────────────────────────────────
app.post('/api/todo/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    try {
        // Query your MariaDB pool natively (no array destructuring wrapper)
        const rows = await pool.query(
            `SELECT pm.member_id, pm.display_name, pm.username, pm.password_hash, pm.is_active,
                    lmt.type_name
             FROM project_members pm
             LEFT JOIN lk_member_types lmt ON pm.type_id = lmt.type_id
             WHERE pm.username = ?`,
            [username.trim()]
        );
        const member = rows[0];

        // Safe validation: don't reveal if it was the username or password that failed
        if (!member || !member.password_hash) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // Enforce active account status
        if (!member.is_active) {
            return res.status(403).json({ error: 'This account has been deactivated.' });
        }

        // Verify the bcrypt password hash
        const match = await bcrypt.compare(password, member.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        // Establish a distinct member session (keeping it isolated from root admin)
        req.session.memberId = member.member_id.toString(); // Converts BigInt safely to String
        req.session.memberDisplayName = member.display_name;
        req.session.memberTypeName = member.type_name || 'Member'; // Store type for task visibility

        res.json({ success: true, displayName: member.display_name });
    } catch (err) {
        console.error('[Todo Member Login Error]', err);
        res.status(500).json({ error: 'Internal server database error.' });
    }
});

// ── GET CURRENT USER PROFILE ──────────────────────────────────────────────
app.get('/api/todo/me', memberAuth, (req, res) => {
    if (req.session.memberId && req.session.memberDisplayName) {
        return res.json({
            member_id: parseInt(req.session.memberId),
            display_name: req.session.memberDisplayName,
            type_name: req.session.memberTypeName || 'Member'
        });
    }
    res.status(401).json({ error: 'User session not found.' });
});

// NEW: Multi-timezone Login endpoint
app.post('/api/multi-admin/login', (req, res) => {
    const { username, password } = req.body;
    
    if (username === process.env.MULTI_ADMIN_USERNAME && password === process.env.MULTI_ADMIN_PASSWORD) {
        req.session.isMultiAdmin = true; // Store multi-admin authenticated status inside the session
        return res.json({ success: true, message: 'Logged in successfully' });
    }
    
    res.status(401).json({ error: 'Invalid credentials' });
});

// Explicit Logout endpoint (Clears both session flags)
app.post('/api/admin/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Could not log out');
        }
        res.clearCookie('connect.sid'); // Clears the session identifier cookie from browser
        res.sendStatus(200);
    });
});


// --- SERVE PAGES ---

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'views/todo.html')));

// Standard Login Page
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views/login/login.html')));


// todo login
app.get('/todo-login', (req, res) => res.sendFile(path.join(__dirname, 'views/login/todo-login.html')));


app.get('/todo', (req, res) => {
    if (req.session && req.session.isAdmin) {
        return res.sendFile(path.join(__dirname, 'views/todo.html'));
    }
    res.redirect('/todo-login');
});


// --- TODO TASK API (protected by adminAuth) ---

// GET tasks with role-based visibility:
//   Owner     -> all tasks
//   Admin     -> own tasks + other admin tasks (owner tasks assigned to project)
//   Everyone  -> own tasks + tasks not assigned to owners or admins
app.get('/api/todo/tasks', memberAuth, async (req, res) => {
    const memberId  = req.session.memberId;
    const typeName  = (req.session.memberTypeName || '').toLowerCase();

    try {
        let rows;

        if (typeName === 'owner') {
            // Owners see everything
            rows = await pool.query(`
                SELECT 
                    pt.task_id, pt.title, pt.description,
                    pt.priority_id, pt.status_id,
                    pt.due_date, pt.created_at, pt.updated_at,
                    pt.project_id,
                    pm.display_name AS assignee_name,
                    pm.member_id    AS assignee_id,
                    p.project_name,
                    (SELECT COUNT(*) FROM project_task_notes ptn
                       WHERE ptn.task_id = pt.task_id AND ptn.is_deleted = FALSE) AS notes_count
                FROM project_tasks pt
                LEFT JOIN project_members pm ON pt.assignee_id = pm.member_id
                LEFT JOIN lk_member_types lmt ON pm.type_id = lmt.type_id
                LEFT JOIN projects p          ON pt.project_id = p.project_id
                WHERE pt.is_deleted = FALSE
                ORDER BY pt.priority_id ASC, pt.created_at DESC
            `);

        } else if (typeName === 'admin') {
            // Admins see all tasks except those assigned to owners
            rows = await pool.query(`
                SELECT 
                    pt.task_id, pt.title, pt.description,
                    pt.priority_id, pt.status_id,
                    pt.due_date, pt.created_at, pt.updated_at,
                    pt.project_id,
                    pm.display_name AS assignee_name,
                    pm.member_id    AS assignee_id,
                    p.project_name,
                    (SELECT COUNT(*) FROM project_task_notes ptn
                       WHERE ptn.task_id = pt.task_id AND ptn.is_deleted = FALSE) AS notes_count
                FROM project_tasks pt
                LEFT JOIN project_members pm ON pt.assignee_id = pm.member_id
                LEFT JOIN lk_member_types lmt ON pm.type_id = lmt.type_id
                LEFT JOIN projects p          ON pt.project_id = p.project_id
                WHERE pt.is_deleted = FALSE
                  AND ((LOWER(lmt.type_name) = 'owner' and pt.project_id IS NOT NULL) or  (LOWER(lmt.type_name) != 'owner'))
                ORDER BY pt.priority_id ASC, pt.created_at DESC
            `);

        } else {
            // Regular members see own tasks + tasks not assigned to owners or admins
            rows = await pool.query(`
                SELECT 
                    pt.task_id, pt.title, pt.description,
                    pt.priority_id, pt.status_id,
                    pt.due_date, pt.created_at, pt.updated_at,
                    pt.project_id,
                    pm.display_name AS assignee_name,
                    pm.member_id    AS assignee_id,
                    p.project_name,
                    (SELECT COUNT(*) FROM project_task_notes ptn
                       WHERE ptn.task_id = pt.task_id AND ptn.is_deleted = FALSE) AS notes_count
                FROM project_tasks pt
                LEFT JOIN project_members pm ON pt.assignee_id = pm.member_id
                LEFT JOIN lk_member_types lmt ON pm.type_id = lmt.type_id
                LEFT JOIN projects p          ON pt.project_id = p.project_id
                WHERE pt.is_deleted = FALSE
                  AND (
                      pt.assignee_id = ?
                      OR LOWER(lmt.type_name) NOT IN ('owner', 'admin')
                  )
                ORDER BY pt.priority_id ASC, pt.created_at DESC
            `, [memberId]);
        }

        // notes_count comes back from COUNT(*) as a BIGINT — the mariadb driver can
        // surface that as a native BigInt, which JSON.stringify can't serialize. Normalize it.
        rows = rows.map(r => ({ ...r, notes_count: Number(r.notes_count || 0) }));

        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// GET active members (for assignee dropdowns)
app.get('/api/todo/members', memberAuth, async (req, res) => {
    try {
        const rows = await pool.query(`
            SELECT pm.member_id, pm.display_name, lmt.type_name
            FROM project_members pm
            LEFT JOIN lk_member_types lmt ON pm.type_id = lmt.type_id
            WHERE pm.is_active = TRUE
            ORDER BY pm.display_name ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// GET active projects (for project dropdown)
app.get('/api/todo/projects', memberAuth, async (req, res) => {
    try {
        const rows = await pool.query(`
            SELECT project_id, project_name
            FROM projects
            ORDER BY project_name ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});


// ── ADD THIS NEW POST ENDPOINT RIGHT HERE ─────────────────────────────────
// Restricted to admins/owners — memberAuth confirms identity, projectAdminAuth confirms role.
app.post('/api/todo/projects', memberAuth, projectAdminAuth, async (req, res) => {
    // Extract both variables from the incoming request body
    const { projectName, description } = req.body;
    
    if (!projectName || !projectName.trim()) {
        return res.status(400).send('Project name is required');
    }

    try {
        // Update your INSERT SQL statement to store the descriptive notes
        await pool.query(
            `INSERT INTO projects (project_name, description) VALUES (?, ?)`,
            [projectName.trim(), description || null]
        );
        res.sendStatus(201); 
    } catch (err) {
        console.error('[Create Project Error]', err);
        res.status(500).send('Database error saving the project');
    }
});

// POST create a new task
app.post('/api/todo/tasks', memberAuth, async (req, res) => {
    const { title, description, priorityId, statusId, projectId, dueDate } = req.body;
    if (!title) {
        return res.status(400).send('Title is required');
    }
    const assigneeId = req.session.memberId;
    if (!assigneeId) {
        return res.status(401).send('Session expired or invalid assignee');
    }
    try {
        await pool.query(
            `INSERT INTO project_tasks (title, description, priority_id, status_id, assignee_id, project_id, due_date)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [title, description || null, priorityId || 2, statusId || 1, assigneeId, projectId || null, dueDate || null]
        );
        res.sendStatus(201);
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// PATCH update task fields (title, description, priority, status, assignee, project, due date)
app.patch('/api/todo/tasks/:id', memberAuth, async (req, res) => {
    const { title, description, priorityId, statusId, assigneeId, projectId, dueDate } = req.body;
    if (!title || !assigneeId) {
        return res.status(400).send('Title and assignee are required');
    }
    try {
        const result = await pool.query(
            `UPDATE project_tasks
             SET title = ?, description = ?, priority_id = ?, status_id = ?,
                 assignee_id = ?, project_id = ?, due_date = ?, updated_at = NOW()
             WHERE task_id = ? AND is_deleted = FALSE`,
            [title, description || null, priorityId, statusId, assigneeId,
             projectId || null, dueDate || null, req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Task not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// POST mark task as complete (status_id = 3)
app.post('/api/todo/tasks/:id/complete', memberAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE project_tasks SET status_id = 3, updated_at = NOW() WHERE task_id = ? AND is_deleted = FALSE`,
            [req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Task not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// POST reopen task (status_id back to 1 = To Do)
app.post('/api/todo/tasks/:id/reopen', memberAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE project_tasks SET status_id = 1, updated_at = NOW() WHERE task_id = ? AND is_deleted = FALSE`,
            [req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Task not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// POST reassign a task to a different member
app.post('/api/todo/tasks/:id/assign', memberAuth, async (req, res) => {
    const { assigneeId } = req.body;
    if (!assigneeId) return res.status(400).send('assigneeId is required');
    try {
        const result = await pool.query(
            `UPDATE project_tasks SET assignee_id = ?, updated_at = NOW() WHERE task_id = ? AND is_deleted = FALSE`,
            [assigneeId, req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Task not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// GET all notes for a task (author name joined in, same pattern as assignee_name)
app.get('/api/todo/tasks/:id/notes', memberAuth, async (req, res) => {
    try {
        const rows = await pool.query(`
            SELECT ptn.note_id, ptn.task_id, ptn.author_id, ptn.note_text,
                   ptn.created_at, ptn.updated_at,
                   pm.display_name AS author_name
            FROM project_task_notes ptn
            LEFT JOIN project_members pm ON ptn.author_id = pm.member_id
            WHERE ptn.task_id = ? AND ptn.is_deleted = FALSE
            ORDER BY ptn.created_at ASC
        `, [req.params.id]);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Database error' });
    }
});

// POST add a note to a task (author comes from the session, same as createTask does for assigneeId)
app.post('/api/todo/tasks/:id/notes', memberAuth, async (req, res) => {
    const { noteText } = req.body;
    if (!noteText || !noteText.trim()) {
        return res.status(400).send('Note text is required');
    }
    const authorId = req.session.memberId;
    if (!authorId) {
        return res.status(401).send('Session expired or invalid author');
    }
    try {
        await pool.query(
            `INSERT INTO project_task_notes (task_id, author_id, note_text) VALUES (?, ?, ?)`,
            [req.params.id, authorId, noteText.trim()]
        );
        res.sendStatus(201);
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// PATCH edit a note's text
app.patch('/api/todo/notes/:id', memberAuth, async (req, res) => {
    const { noteText } = req.body;
    if (!noteText || !noteText.trim()) {
        return res.status(400).send('Note text is required');
    }
    try {
        const result = await pool.query(
            `UPDATE project_task_notes SET note_text = ?, updated_at = NOW()
             WHERE note_id = ? AND is_deleted = FALSE`,
            [noteText.trim(), req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Note not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

// DELETE (soft-delete) a note
app.delete('/api/todo/notes/:id', memberAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE project_task_notes SET is_deleted = TRUE WHERE note_id = ?`,
            [req.params.id]
        );
        result.affectedRows > 0 ? res.sendStatus(200) : res.status(404).send('Note not found');
    } catch (err) {
        console.error(err);
        res.status(500).send('Database error');
    }
});

app.post('/api/todo/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// Start Server
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`🚀 Portal running on http://localhost:${PORT}`));