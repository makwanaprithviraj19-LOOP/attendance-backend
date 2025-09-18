// init_db.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const DB_PATH = './db.sqlite';
const db = new sqlite3.Database(DB_PATH);

async function run() {
  db.serialize(async () => {
    db.run(`DROP TABLE IF EXISTS users`);
    db.run(`DROP TABLE IF EXISTS classes`);
    db.run(`DROP TABLE IF EXISTS students`);
    db.run(`DROP TABLE IF EXISTS attendance`);

    db.run(`CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      role TEXT,
      phone TEXT,
      gr_number TEXT,
      password_hash TEXT
    )`);

    db.run(`CREATE TABLE classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE
    )`);

    db.run(`CREATE TABLE students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      roll INTEGER,
      class_name TEXT
    )`);

    db.run(`CREATE TABLE attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER,
      date TEXT,
      status TEXT,
      class_name TEXT,
      FOREIGN KEY(student_id) REFERENCES students(id)
    )`);

    const classes = ['1-A','1-B','2-A','2-B'];
    const insertClass = db.prepare(`INSERT INTO classes(name) VALUES(?)`);
    classes.forEach(c => insertClass.run(c));
    insertClass.finalize();

    const students = [
      ['Alice Johnson', 101, '1-A'],
      ['Bob Smith', 102, '1-A'],
      ['Carol Davis', 103, '1-A'],
      ['David Wilson', 104, '2-A'],
      ['Emma Brown', 105, '2-A'],
      ['Pruthvi', 106, '1-B'],
      ['Pratham', 107, '1-B'],
      ['Meet', 108, '2-B'],
      ['Hemali', 109, '2-A'],
      ['Kishan', 110, '1-A'],
      ['Ronit', 111, '1-B']
    ];
    const insertStudent = db.prepare(`INSERT INTO students(name,roll,class_name) VALUES(?,?,?)`);
    students.forEach(s => insertStudent.run(s[0], s[1], s[2]));
    insertStudent.finalize();

    const saltRounds = 10;
    const demoUsers = [
      { name: 'Mahipalsinh', role: 'teacher', phone: '+911234567890', gr_number: null, password: 'teacher123' },
      { name: 'ParentUser', role: 'parent', phone: '+919876543210', gr_number: null, password: 'parent123' },
      { name: 'StudentUser', role: 'student', phone: null, gr_number: 'ST123', password: 'student123' }
    ];

    const insertUser = db.prepare(`INSERT INTO users(name,role,phone,gr_number,password_hash) VALUES(?,?,?,?,?)`);
    for (const u of demoUsers) {
      const hash = await bcrypt.hash(u.password, saltRounds);
      insertUser.run(u.name, u.role, u.phone, u.gr_number, hash);
    }
    insertUser.finalize();

    console.log('Database initialized and seeded to', DB_PATH);
    db.close();
  });
}

run().catch(err => { console.error(err); db.close(); });
