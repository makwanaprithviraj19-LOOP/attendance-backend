// server.js
require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');

const DB_PATH = './db.sqlite';
const db = new sqlite3.Database(DB_PATH);
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

app.use(cors());
app.use(bodyParser.json());

function runSQL(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function allSQL(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}
function getSQL(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// ---------- Auth routes ----------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password, type } = req.body;
    let user;
    if (type === 'gr') {
      user = await getSQL(`SELECT * FROM users WHERE gr_number = ?`, [identifier]);
    } else {
      user = await getSQL(`SELECT * FROM users WHERE phone = ? OR gr_number = ?`, [identifier, identifier]);
    }
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: user.role, name: user.name });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'internal' });
  }
});

function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'missing token' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'invalid token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'not authenticated' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

// ---------- API endpoints ----------
app.get('/api/classes', authenticateToken, async (req, res) => {
  try {
    const rows = await allSQL(`SELECT name FROM classes ORDER BY name`);
    res.json(rows.map(r => r.name));
  } catch (err) {
    res.status(500).json({ error: 'internal' });
  }
});

app.get('/api/students', authenticateToken, async (req, res) => {
  try {
    const cls = req.query.class;
    let rows;
    if (cls && cls !== 'all') rows = await allSQL(`SELECT * FROM students WHERE class_name = ?`, [cls]);
    else rows = await allSQL(`SELECT * FROM students`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'internal' }); }
});

app.post('/api/students', authenticateToken, authorizeRoles('teacher'), async (req, res) => {
  try {
    const { name, roll, class_name } = req.body;
    const info = await runSQL(`INSERT INTO students(name,roll,class_name) VALUES(?,?,?)`, [name, roll, class_name]);
    res.json({ id: info.lastID });
  } catch (err) { res.status(500).json({ error: 'internal' }); }
});

app.post('/api/attendance', authenticateToken, authorizeRoles('teacher'), async (req, res) => {
  try {
    const { date, class_name, records } = req.body;
    if (!date || !class_name || !Array.isArray(records)) return res.status(400).json({ error: 'bad request' });
    await runSQL(`DELETE FROM attendance WHERE date=? AND class_name=?`, [date, class_name]);
    const stmt = db.prepare(`INSERT INTO attendance(student_id, date, status, class_name) VALUES (?,?,?,?)`);
    records.forEach(r => {
      stmt.run(r.student_id, date, r.status, class_name);
    });
    stmt.finalize();
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.get('/api/attendance', authenticateToken, async (req, res) => {
  try {
    const date = req.query.date;
    const cls = req.query.class;
    let sql = `SELECT a.*, s.name as student_name, s.roll FROM attendance a LEFT JOIN students s ON s.id = a.student_id WHERE 1=1`;
    const params = [];
    if (date) { sql += ` AND a.date = ?`; params.push(date); }
    if (cls && cls !== 'all') { sql += ` AND a.class_name = ?`; params.push(cls); }
    sql += ` ORDER BY s.roll`;
    const rows = await allSQL(sql, params);
    res.json(rows);
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.get('/api/reports/class/:className', authenticateToken, authorizeRoles('teacher','parent'), async (req, res) => {
  try {
    const cls = req.params.className;
    const students = await allSQL(`SELECT id, name, roll FROM students WHERE class_name = ? ORDER BY roll`, [cls]);
    const summary = [];
    for (const s of students) {
      const presentCountRow = await getSQL(`SELECT COUNT(*) as cnt FROM attendance WHERE student_id=? AND class_name=? AND status='present'`, [s.id, cls]);
      const absentCountRow = await getSQL(`SELECT COUNT(*) as cnt FROM attendance WHERE student_id=? AND class_name=? AND status='absent'`, [s.id, cls]);
      summary.push({ id: s.id, name: s.name, roll: s.roll, present: presentCountRow.cnt || 0, absent: absentCountRow.cnt || 0 });
    }
    res.json({ class: cls, students: summary });
  } catch (err) { console.error(err); res.status(500).json({ error: 'internal' }); }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
