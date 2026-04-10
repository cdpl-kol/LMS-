require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const nodemailer = require('nodemailer');
const fs = require('fs');
const zlib = require('zlib');

// ── PURE NODE.JS ZIP EXTRACTOR (no external deps) ────────────────────────────
function extractZip(zipBuffer, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const buf = zipBuffer;
  // Find End of Central Directory (signature 0x06054b50)
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf[i]===0x50 && buf[i+1]===0x4b && buf[i+2]===0x05 && buf[i+3]===0x06) {
      eocdOffset = i; break;
    }
  }
  if (eocdOffset < 0) throw new Error('Not a valid ZIP file');
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);
  const cdEntries = buf.readUInt16LE(eocdOffset + 10);
  let cdPos = cdOffset;
  const entries = [];
  for (let e = 0; e < cdEntries; e++) {
    if (buf.readUInt32LE(cdPos) !== 0x02014b50) break;
    const method     = buf.readUInt16LE(cdPos + 10);
    const compSize   = buf.readUInt32LE(cdPos + 20);
    const uncompSize = buf.readUInt32LE(cdPos + 24);
    const fnLen      = buf.readUInt16LE(cdPos + 28);
    const exLen      = buf.readUInt16LE(cdPos + 30);
    const cmLen      = buf.readUInt16LE(cdPos + 32);
    const localOff   = buf.readUInt32LE(cdPos + 42);
    const fileName   = buf.slice(cdPos + 46, cdPos + 46 + fnLen).toString('utf8');
    entries.push({ method, compSize, uncompSize, fnLen, localOff, fileName });
    cdPos += 46 + fnLen + exLen + cmLen;
  }
  for (const entry of entries) {
    const { method, compSize, uncompSize, fnLen, localOff, fileName } = entry;
    if (fileName.endsWith('/')) {
      fs.mkdirSync(path.join(destDir, fileName), { recursive: true });
      continue;
    }
    // Local file header
    const lhExLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + fnLen + lhExLen;
    const rawData = buf.slice(dataStart, dataStart + compSize);
    const outPath = path.join(destDir, fileName);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    if (method === 0) {
      fs.writeFileSync(outPath, rawData);
    } else if (method === 8) {
      fs.writeFileSync(outPath, zlib.inflateRawSync(rawData));
    }
  }
}

const app = express();

// ── SECURITY HEADERS ──────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, '..')));

// Serve uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many login attempts, try again in 15 minutes' } });
const otpLimiter  = rateLimit({ windowMs: 10*60*1000, max: 5,  message: { error: 'Too many OTP requests' } });
const apiLimiter  = rateLimit({ windowMs: 60*1000,    max: 300, message: { error: 'Rate limit exceeded' } });
app.use('/api/', apiLimiter);
app.use('/api/v1/auth/login', loginLimiter);
app.use('/api/v1/auth/forgot-password', otpLimiter);

// ── FILE UPLOAD (MULTER) ──────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(uploadsDir, req.uploadFolder || 'misc');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.round(Math.random()*1e6) + ext);
  }
});
const fileFilter = (req, file, cb) => {
  const allowed = ['.pdf','.doc','.docx','.ppt','.pptx','.xls','.xlsx','.jpg','.jpeg','.png','.gif','.mp4','.zip','.txt'];
  const ext = path.extname(file.originalname).toLowerCase();
  allowed.includes(ext) ? cb(null, true) : cb(new Error('File type not allowed'));
};
const upload = multer({ storage, fileFilter, limits: { fileSize: 50*1024*1024 } });

// ── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/lms_db',
  max: 20, idleTimeoutMillis: 30000, connectionTimeoutMillis: 2000
});
const JWT_SECRET  = process.env.JWT_SECRET  || 'lms-secret-2024-secure';
const JWT_REFRESH = process.env.JWT_REFRESH || 'lms-refresh-secret-2024';

// ── EMAIL TRANSPORTER ─────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER || '', pass: process.env.EMAIL_PASS || '' }
});
async function sendEmail(to, subject, html) {
  if (!process.env.EMAIL_USER) return false;
  try {
    await transporter.sendMail({ from: `"Smart LMS - Connecting Dot" <${process.env.EMAIL_USER}>`, to, subject, html });
    return true;
  } catch(e) { console.error('Email error:', e.message); return false; }
}

// ── AUTH MIDDLEWARES ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ success:false, error:'Unauthorized' });
  const token = header.split(' ')[1];
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ success:false, error:'Invalid or expired token' }); }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success:false, error:'Unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ success:false, error:'Access denied' });
    next();
  };
}
const adminOnly   = requireRole('admin');
const trainerOnly = requireRole('trainer');
const studentOnly = requireRole('student');
const bschoolOnly = requireRole('bschool');
const staffOnly   = requireRole('admin','trainer','bschool');

// ── RESPONSE HELPERS ──────────────────────────────────────────────────────────
const ok  = (res, data, msg='Success')  => res.json({ success:true, data, message:msg });
const err = (res, msg, code=500)        => res.status(code).json({ success:false, error:msg });
const sanitize = (s) => (typeof s === 'string') ? s.replace(/<[^>]*>/g,'').trim() : s;

// ── DB INIT ───────────────────────────────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY, username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS bschools (
        id SERIAL PRIMARY KEY, name VARCHAR(255), email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, contact VARCHAR(50), address TEXT,
        status VARCHAR(50) DEFAULT 'Active', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
        status VARCHAR(50) DEFAULT 'Active', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS trainers (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, contact VARCHAR(50), expertise TEXT,
        status VARCHAR(50) DEFAULT 'Active', profile_photo VARCHAR(500), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
        category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
        duration VARCHAR(100), description TEXT, thumbnail VARCHAR(500),
        status VARCHAR(50) DEFAULT 'Active', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS modules (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        duration VARCHAR(100), order_no INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS mcqs (
        id SERIAL PRIMARY KEY, question TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        option_a VARCHAR(500), option_b VARCHAR(500), option_c VARCHAR(500), option_d VARCHAR(500),
        correct_answer CHAR(1), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS exams (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        duration VARCHAR(100), pass_percentage VARCHAR(20), total_marks INTEGER, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS batches (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
        start_date DATE, end_date DATE,
        trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        max_students INTEGER DEFAULT 30, status VARCHAR(50) DEFAULT 'Active', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL, contact VARCHAR(50),
        course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
        batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
        status VARCHAR(50) DEFAULT 'Pending', profile_photo VARCHAR(500), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS company_info (
        id INTEGER PRIMARY KEY DEFAULT 1, name VARCHAR(255) DEFAULT 'Connecting Dot Consultancy Pvt. Ltd.',
        email VARCHAR(255) DEFAULT 'info.cdpl.kol@gmail.com', phone VARCHAR(50) DEFAULT '+91 98765 43210',
        address TEXT DEFAULT 'Kolkata, West Bengal, India', website VARCHAR(255) DEFAULT 'www.connectingdot.in',
        gst_no VARCHAR(100) DEFAULT '19AAACD1234A1Z5'
      );
      CREATE TABLE IF NOT EXISTS site_settings (
        id INTEGER PRIMARY KEY DEFAULT 1,
        logo_path VARCHAR(500) DEFAULT 'logo.png',
        site_title VARCHAR(255) DEFAULT 'Smart LMS',
        tagline VARCHAR(500) DEFAULT 'Empowering Learning, Transforming Careers',
        footer_text VARCHAR(500) DEFAULT '© 2026 Connecting Dot Consultancy Pvt. Ltd. All rights reserved.',
        primary_color VARCHAR(20) DEFAULT '#1a237e',
        accent_color VARCHAR(20) DEFAULT '#ff6b35',
        fb_url VARCHAR(500) DEFAULT '',
        instagram_url VARCHAR(500) DEFAULT '',
        linkedin_url VARCHAR(500) DEFAULT '',
        youtube_url VARCHAR(500) DEFAULT '',
        whatsapp_url VARCHAR(500) DEFAULT '',
        twitter_url VARCHAR(500) DEFAULT '',
        banner_image VARCHAR(500) DEFAULT '',
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS otp_requests (
        id SERIAL PRIMARY KEY, email VARCHAR(255) NOT NULL, otp_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50), expires_at TIMESTAMP NOT NULL, used BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, role VARCHAR(50) NOT NULL,
        token_hash VARCHAR(255) NOT NULL, expires_at TIMESTAMP NOT NULL,
        revoked BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        batch_id INTEGER REFERENCES batches(id) ON DELETE CASCADE,
        date DATE NOT NULL, status VARCHAR(20) DEFAULT 'Present',
        marked_by INTEGER, created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(student_id, batch_id, date)
      );
      CREATE TABLE IF NOT EXISTS student_progress (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        module_id INTEGER REFERENCES modules(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT FALSE, completed_at TIMESTAMP,
        UNIQUE(student_id, module_id)
      );
      CREATE TABLE IF NOT EXISTS student_exam_attempts (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        exam_id INTEGER REFERENCES exams(id) ON DELETE CASCADE,
        score INTEGER DEFAULT 0, max_score INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'Pending', answers JSONB,
        started_at TIMESTAMP DEFAULT NOW(), submitted_at TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS assignments (
        id SERIAL PRIMARY KEY, title VARCHAR(255) NOT NULL, description TEXT,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        batch_id INTEGER REFERENCES batches(id) ON DELETE CASCADE,
        trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        due_date DATE, max_marks INTEGER DEFAULT 100, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS assignment_submissions (
        id SERIAL PRIMARY KEY, assignment_id INTEGER REFERENCES assignments(id) ON DELETE CASCADE,
        student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        file_path VARCHAR(500), text_answer TEXT,
        submitted_at TIMESTAMP DEFAULT NOW(), marks_obtained INTEGER,
        feedback TEXT, graded_by INTEGER, graded_at TIMESTAMP,
        UNIQUE(assignment_id, student_id)
      );
      CREATE TABLE IF NOT EXISTS fee_payments (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        amount NUMERIC(10,2) NOT NULL, payment_date DATE DEFAULT CURRENT_DATE,
        payment_mode VARCHAR(50) DEFAULT 'Cash', receipt_no VARCHAR(100),
        status VARCHAR(50) DEFAULT 'Paid', remarks TEXT, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, role VARCHAR(50) NOT NULL,
        message TEXT NOT NULL, type VARCHAR(50) DEFAULT 'info',
        is_read BOOLEAN DEFAULT FALSE, link VARCHAR(500),
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS timetable (
        id SERIAL PRIMARY KEY, batch_id INTEGER REFERENCES batches(id) ON DELETE CASCADE,
        day_of_week VARCHAR(20), start_time TIME, end_time TIME,
        subject VARCHAR(255), trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        room_or_link VARCHAR(500), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS course_materials (
        id SERIAL PRIMARY KEY, module_id INTEGER REFERENCES modules(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL, type VARCHAR(50) DEFAULT 'PDF',
        file_path_or_url VARCHAR(500), uploaded_by INTEGER, created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS course_feedback (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        rating INTEGER CHECK(rating BETWEEN 1 AND 5), feedback_text TEXT,
        submitted_at TIMESTAMP DEFAULT NOW(), UNIQUE(student_id, course_id)
      );
      CREATE TABLE IF NOT EXISTS certificates (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
        issued_date DATE DEFAULT CURRENT_DATE, certificate_no VARCHAR(100) UNIQUE,
        status VARCHAR(50) DEFAULT 'Issued', created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY, user_id INTEGER, role VARCHAR(50), action VARCHAR(50),
        entity VARCHAR(100), entity_id INTEGER, description TEXT,
        ip_address VARCHAR(50), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS scorm_packages (
        id SERIAL PRIMARY KEY, module_id INTEGER REFERENCES modules(id) ON DELETE CASCADE,
        package_name VARCHAR(255), manifest_path VARCHAR(500),
        scorm_version VARCHAR(20) DEFAULT '1.2', upload_path VARCHAR(500), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS scorm_tracking (
        id SERIAL PRIMARY KEY, student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        package_id INTEGER REFERENCES scorm_packages(id) ON DELETE CASCADE,
        completion_status VARCHAR(50) DEFAULT 'not attempted',
        score_raw INTEGER DEFAULT 0, score_max INTEGER DEFAULT 100,
        total_time VARCHAR(50), suspend_data TEXT, last_accessed TIMESTAMP DEFAULT NOW(),
        UNIQUE(student_id, package_id)
      );
    `);

    await client.query(`INSERT INTO company_info (id) VALUES (1) ON CONFLICT DO NOTHING`);
    await client.query(`INSERT INTO site_settings (id) VALUES (1) ON CONFLICT DO NOTHING`);

    const adminCheck = await client.query('SELECT id FROM admins WHERE username=$1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hash = await bcrypt.hash('admin123', 12);
      await client.query('INSERT INTO admins(username,password_hash) VALUES($1,$2)', ['admin', hash]);
      console.log('✅ Default admin: admin / admin123');
    }
    const bsCheck = await client.query('SELECT id FROM bschools WHERE email=$1', ['bschool@cdpl.in']);
    if (bsCheck.rows.length === 0) {
      const hash = await bcrypt.hash('bschool123', 12);
      await client.query('INSERT INTO bschools(name,email,password_hash,contact,status) VALUES($1,$2,$3,$4,$5)',['B-School Demo','bschool@cdpl.in',hash,'9000000001','Active']);
      console.log('✅ Default bschool: bschool@cdpl.in / bschool123');
    }
    const trCheck = await client.query('SELECT id FROM trainers WHERE email=$1', ['trainer@cdpl.in']);
    if (trCheck.rows.length === 0) {
      const hash = await bcrypt.hash('trainer123', 12);
      await client.query('INSERT INTO trainers(name,email,password_hash,contact,expertise,status) VALUES($1,$2,$3,$4,$5,$6)',['Demo Trainer','trainer@cdpl.in',hash,'9000000002','General','Active']);
    }
    const catCheck = await client.query('SELECT COUNT(*) FROM categories');
    if (parseInt(catCheck.rows[0].count) === 0) {
      await client.query(`INSERT INTO categories(name,status) VALUES ('Programming','Active'),('Web Development','Active'),('Data Science','Active'),('Business Management','Active')`);
      await client.query(`INSERT INTO courses(name,category_id,duration,status,description) VALUES ('Python Basics',1,'3 Months','Active','Learn Python from scratch'),('Web Development 101',2,'4 Months','Active','HTML CSS JS Full Stack'),('Data Science Fundamentals',3,'5 Months','Active','Data Analysis & ML'),('Business Management',4,'6 Months','Active','MBA-level concepts')`);
      const suvroH = await bcrypt.hash('suvro123', 12);
      const anjaliH = await bcrypt.hash('anjali123', 12);
      await client.query(`INSERT INTO trainers(name,email,password_hash,contact,expertise,status) VALUES ('Suvro De','suvro@cdpl.in',$1,'9874210823','Python, Data Science','Active'),('Anjali Roy','anjali@cdpl.in',$2,'9874210824','Web Development, UI/UX','Active') ON CONFLICT(email) DO NOTHING`,[suvroH,anjaliH]);
      const s1 = (await client.query('SELECT id FROM trainers WHERE email=$1',['suvro@cdpl.in'])).rows[0]?.id;
      const s2 = (await client.query('SELECT id FROM trainers WHERE email=$1',['anjali@cdpl.in'])).rows[0]?.id;
      await client.query(`INSERT INTO batches(name,course_id,start_date,end_date,trainer_id,max_students,status) VALUES ('Batch 2024-A',1,'2024-01-15','2024-04-15',$1,32,'Completed'),('Batch 2024-B',2,'2024-03-01','2024-07-01',$2,28,'Active'),('Batch 2025-A',3,'2025-01-10','2025-06-10',$1,25,'Active')`,[s1,s2]);
      const b1 = (await client.query(`SELECT id FROM batches WHERE name='Batch 2024-A'`)).rows[0]?.id;
      const b2 = (await client.query(`SELECT id FROM batches WHERE name='Batch 2024-B'`)).rows[0]?.id;
      const b3 = (await client.query(`SELECT id FROM batches WHERE name='Batch 2025-A'`)).rows[0]?.id;
      const stHash = await bcrypt.hash('student123', 12);
      const stHash2 = await bcrypt.hash('student@123', 12);
      await client.query(`INSERT INTO students(name,email,password_hash,contact,course_id,batch_id,status) VALUES ('Student Demo','student@cdpl.in',$1,'9000000003',1,$4,'Active'),('Rahul Sharma','rahul@example.com',$2,'9876543210',1,$4,'Active'),('Priya Singh','priya@example.com',$2,'9876543211',2,$5,'Active'),('Amit Kumar','amit@example.com',$2,'9876543212',1,$4,'Completed'),('Sunita Dey','sunita@example.com',$2,'9876543213',3,$6,'Active') ON CONFLICT(email) DO NOTHING`,[stHash,stHash2,stHash2,b1,b2,b3]);
      console.log('✅ Sample data seeded. Student login: student@cdpl.in / student123');
    }
    console.log('✅ Database initialized');
  } catch(e) { console.error('❌ DB init error:', e.message); }
  finally { client.release(); }
}

// ── AUDIT LOG HELPER ──────────────────────────────────────────────────────────
async function logAudit(userId, role, action, entity, entityId, desc, ip) {
  try {
    await pool.query('INSERT INTO audit_logs(user_id,role,action,entity,entity_id,description,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [userId,role,action,entity,entityId||null,desc||null,ip||null]);
  } catch(e) {}
}

// ── NOTIFICATION HELPER ───────────────────────────────────────────────────────
async function notify(userId, role, message, type='info', link='') {
  try {
    await pool.query('INSERT INTO notifications(user_id,role,message,type,link) VALUES($1,$2,$3,$4,$5)',[userId,role,message,type,link]);
  } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════
// AUTH ROUTES /api/v1/auth
// ═══════════════════════════════════════════════════════════════
app.post('/api/v1/auth/login', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return err(res, 'Missing fields', 400);
  const clean = sanitize(username.toLowerCase().trim());
  try {
    let user = null;
    if (role==='admin') user = (await pool.query('SELECT * FROM admins WHERE username=$1',[clean])).rows[0];
    else if (role==='bschool') user = (await pool.query('SELECT * FROM bschools WHERE email=$1',[clean])).rows[0];
    else if (role==='trainer') user = (await pool.query('SELECT * FROM trainers WHERE email=$1',[clean])).rows[0];
    else if (role==='student') user = (await pool.query('SELECT * FROM students WHERE email=$1',[clean])).rows[0];
    else return err(res, 'Invalid role', 400);

    if (!user) return err(res, 'Invalid credentials', 401);
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return err(res, 'Invalid credentials', 401);

    const token = jwt.sign({ id:user.id, role, name:user.name||user.username, email:user.email||null }, JWT_SECRET, { expiresIn:'8h' });
    const rfToken = jwt.sign({ id:user.id, role }, JWT_REFRESH, { expiresIn:'7d' });
    const rfHash = await bcrypt.hash(rfToken, 8);
    const exp = new Date(Date.now() + 7*24*60*60*1000);
    await pool.query('INSERT INTO refresh_tokens(user_id,role,token_hash,expires_at) VALUES($1,$2,$3,$4)',[user.id,role,rfHash,exp]);
    await logAudit(user.id, role, 'LOGIN', role, user.id, 'User logged in', req.ip);
    ok(res, { token, refreshToken:rfToken, name:user.name||user.username, role, id:user.id });
  } catch(e) { console.error(e); err(res, 'Server error'); }
});

app.post('/api/v1/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return err(res, 'Refresh token required', 400);
  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH);
    const rows = await pool.query('SELECT * FROM refresh_tokens WHERE user_id=$1 AND role=$2 AND revoked=FALSE AND expires_at>NOW()',[decoded.id,decoded.role]);
    let valid = false;
    for (const r of rows.rows) { if (await bcrypt.compare(refreshToken, r.token_hash)) { valid = true; break; } }
    if (!valid) return err(res, 'Invalid refresh token', 401);
    const newToken = jwt.sign({ id:decoded.id, role:decoded.role }, JWT_SECRET, { expiresIn:'8h' });
    ok(res, { token: newToken });
  } catch(e) { err(res, 'Invalid refresh token', 401); }
});

app.get('/api/v1/auth/verify', auth, (req, res) => ok(res, { user: req.user }));

app.post('/api/v1/auth/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword || newPassword.length < 6) return err(res, 'Invalid input', 400);
  const { id, role } = req.user;
  try {
    const tbl = role==='admin'?'admins':role==='bschool'?'bschools':role==='trainer'?'trainers':'students';
    const r = await pool.query(`SELECT password_hash FROM ${tbl} WHERE id=$1`,[id]);
    if (!r.rows[0]) return err(res,'User not found',404);
    const ok2 = await bcrypt.compare(oldPassword, r.rows[0].password_hash);
    if (!ok2) return err(res,'Old password incorrect',401);
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query(`UPDATE ${tbl} SET password_hash=$1 WHERE id=$2`,[hash,id]);
    await logAudit(id, role, 'CHANGE_PASSWORD', tbl, id, null, req.ip);
    ok(res, {}, 'Password changed');
  } catch(e) { err(res, 'Server error'); }
});

app.post('/api/v1/auth/forgot-password', async (req, res) => {
  const { email, role } = req.body;
  if (!email || !role) return err(res,'Missing fields',400);
  const clean = sanitize(email.toLowerCase().trim());
  try {
    const tables = { admin:'admins', bschool:'bschools', trainer:'trainers', student:'students' };
    const col = role==='admin' ? 'username' : 'email';
    const tbl = tables[role];
    if (!tbl) return err(res,'Invalid role',400);
    const r = await pool.query(`SELECT id FROM ${tbl} WHERE ${col}=$1`,[clean]);
    // Always return success (security: don't reveal if email exists)
    if (r.rows.length > 0) {
      const otp = Math.floor(100000 + Math.random()*900000).toString();
      const hash = await bcrypt.hash(otp, 8);
      const exp = new Date(Date.now() + 10*60*1000);
      await pool.query('DELETE FROM otp_requests WHERE email=$1 AND role=$2',[clean,role]);
      await pool.query('INSERT INTO otp_requests(email,otp_hash,role,expires_at) VALUES($1,$2,$3,$4)',[clean,hash,role,exp]);
      await sendEmail(clean, 'Your OTP - Smart LMS', `<div style="font-family:Arial;padding:20px;"><h2 style="color:#1a237e;">Password Reset OTP</h2><p>Your OTP is: <strong style="font-size:28px;color:#ff6b35;letter-spacing:4px;">${otp}</strong></p><p>Valid for 10 minutes.</p><p>If you didn't request this, ignore this email.</p><hr/><small>Connecting Dot Consultancy Pvt. Ltd.</small></div>`);
      console.log('🔑 OTP for', clean, ':', otp); // Remove in production
    }
    ok(res, {}, 'OTP sent if email is registered');
  } catch(e) { err(res, 'Server error'); }
});

app.post('/api/v1/auth/verify-otp', async (req, res) => {
  const { email, otp, role } = req.body;
  if (!email||!otp||!role) return err(res,'Missing fields',400);
  const clean = sanitize(email.toLowerCase().trim());
  try {
    const r = await pool.query('SELECT * FROM otp_requests WHERE email=$1 AND role=$2 AND used=FALSE AND expires_at>NOW() ORDER BY created_at DESC LIMIT 1',[clean,role]);
    if (!r.rows[0]) return err(res,'OTP expired or invalid',400);
    const valid = await bcrypt.compare(otp, r.rows[0].otp_hash);
    if (!valid) return err(res,'Invalid OTP',400);
    await pool.query('UPDATE otp_requests SET used=TRUE WHERE id=$1',[r.rows[0].id]);
    const reset_token = jwt.sign({ email:clean, role, purpose:'reset' }, JWT_SECRET, { expiresIn:'15m' });
    ok(res, { reset_token });
  } catch(e) { err(res, 'Server error'); }
});

app.post('/api/v1/auth/reset-password', async (req, res) => {
  const { reset_token, newPassword } = req.body;
  if (!reset_token||!newPassword||newPassword.length<6) return err(res,'Invalid input',400);
  try {
    const decoded = jwt.verify(reset_token, JWT_SECRET);
    if (decoded.purpose !== 'reset') return err(res,'Invalid token',400);
    const { email, role } = decoded;
    const tables = { admin:'admins', bschool:'bschools', trainer:'trainers', student:'students' };
    const col = role==='admin'?'username':'email';
    const tbl = tables[role];
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query(`UPDATE ${tbl} SET password_hash=$1 WHERE ${col}=$2`,[hash,email]);
    ok(res,{},'Password reset successfully');
  } catch(e) { err(res,'Invalid or expired reset token',400); }
});

app.post('/api/v1/auth/register', async (req, res) => {
  const { name, email, password, contact, phone, course_id, role, specialization, expertise } = req.body;
  if (!name||!email||!password) return err(res,'Missing required fields',400);
  const contactVal = contact||phone||null;
  try {
    const hash = await bcrypt.hash(password, 12);
    if(role==='trainer'){
      const r=await pool.query('INSERT INTO trainers(name,email,password_hash,contact,expertise,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,email,contact,expertise,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contactVal,specialization||expertise||'','Active']);
      ok(res,r.rows[0],'Trainer registered.');
    } else if(role==='bschool'){
      const r=await pool.query('INSERT INTO bschools(name,email,password_hash,contact,status) VALUES($1,$2,$3,$4,$5) RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contactVal,'Active']);
      ok(res,r.rows[0],'B-School registered.');
    } else {
      const r = await pool.query(
        'INSERT INTO students(name,email,password_hash,contact,course_id,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,email,status',
        [sanitize(name),sanitize(email.toLowerCase()),hash,contactVal,course_id||null,'Pending']
      );
      await notify(1,'admin',`New student registration: ${sanitize(name)} (${sanitize(email)})`, 'info');
      ok(res, r.rows[0], 'Registration submitted. Awaiting admin approval.');
    }
  } catch(e) {
    if (e.code==='23505') return err(res,'Email already registered',409);
    err(res, 'Server error');
  }
});

// ── SITE SETTINGS ─────────────────────────────────────────────────────────────
app.get('/api/v1/settings', async (req, res) => {
  const r = await pool.query('SELECT * FROM site_settings WHERE id=1');
  ok(res, r.rows[0] || {});
});

app.put('/api/v1/settings', auth, adminOnly, async (req, res) => {
  const { site_title, tagline, footer_text, primary_color, accent_color, fb_url, instagram_url, linkedin_url, youtube_url, whatsapp_url, twitter_url } = req.body;
  try {
    const r = await pool.query(
      `UPDATE site_settings SET site_title=$1,tagline=$2,footer_text=$3,primary_color=$4,accent_color=$5,fb_url=$6,instagram_url=$7,linkedin_url=$8,youtube_url=$9,whatsapp_url=$10,twitter_url=$11,updated_at=NOW() WHERE id=1 RETURNING *`,
      [site_title,tagline,footer_text,primary_color,accent_color,fb_url,instagram_url,linkedin_url,youtube_url,whatsapp_url,twitter_url]
    );
    ok(res, r.rows[0]);
  } catch(e) { err(res, e.message); }
});

app.post('/api/v1/settings/logo', auth, adminOnly, (req, res) => {
  req.uploadFolder = 'logos';
  upload.single('logo')(req, res, async (uploadErr) => {
    if (uploadErr) return err(res, uploadErr.message, 400);
    if (!req.file) return err(res,'No file uploaded',400);
    const logoPath = '/uploads/logos/' + req.file.filename;
    await pool.query('UPDATE site_settings SET logo_path=$1 WHERE id=1',[logoPath]);
    ok(res, { logo_path: logoPath });
  });
});

// ── COMPANY INFO ──────────────────────────────────────────────────────────────
app.get('/api/v1/company', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM company_info WHERE id=1');
  ok(res, r.rows[0] || {});
});
app.put('/api/v1/company', auth, adminOnly, async (req, res) => {
  const { name, email, phone, address, website, gst_no } = req.body;
  const r = await pool.query('UPDATE company_info SET name=$1,email=$2,phone=$3,address=$4,website=$5,gst_no=$6 WHERE id=1 RETURNING *',[name,email,phone,address,website,gst_no]);
  ok(res, r.rows[0]);
});

// ── DASHBOARD STATS ───────────────────────────────────────────────────────────
app.get('/api/v1/dashboard/stats', auth, async (req, res) => {
  try {
    const [ts,ps,as,tc,tr,tb,rev] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM students'),
      pool.query("SELECT COUNT(*) FROM students WHERE status='Pending'"),
      pool.query("SELECT COUNT(*) FROM students WHERE status='Active'"),
      pool.query('SELECT COUNT(*) FROM courses'),
      pool.query('SELECT COUNT(*) FROM trainers'),
      pool.query('SELECT COUNT(*) FROM batches'),
      pool.query('SELECT COALESCE(SUM(amount),0) AS total FROM fee_payments WHERE status=$1',['Paid']),
    ]);
    ok(res, {
      totalStudents: +ts.rows[0].count,
      pendingStudents: +ps.rows[0].count,
      activeStudents: +as.rows[0].count,
      totalCourses: +tc.rows[0].count,
      totalTrainers: +tr.rows[0].count,
      totalBatches: +tb.rows[0].count,
      totalRevenue: +rev.rows[0].total,
    });
  } catch(e) { err(res, e.message); }
});

app.get('/api/v1/analytics/trends', auth, async (req, res) => {
  try {
    const monthly = await pool.query(`SELECT TO_CHAR(created_at,'Mon YYYY') AS month, COUNT(*) AS count FROM students WHERE created_at > NOW() - INTERVAL '6 months' GROUP BY month, DATE_TRUNC('month',created_at) ORDER BY DATE_TRUNC('month',created_at)`);
    const batchDist = await pool.query(`SELECT b.name AS batch, COUNT(s.id) AS students FROM batches b LEFT JOIN students s ON s.batch_id=b.id GROUP BY b.id, b.name ORDER BY b.id LIMIT 8`);
    const courseDist = await pool.query(`SELECT c.name AS course, COUNT(s.id) AS students FROM courses c LEFT JOIN students s ON s.course_id=c.id GROUP BY c.id, c.name ORDER BY students DESC LIMIT 6`);
    ok(res, { monthly: monthly.rows, batchDist: batchDist.rows, courseDist: courseDist.rows });
  } catch(e) { err(res, e.message); }
});

// ── CATEGORIES / COURSES / MODULES / MCQs / EXAMS ────────────────────────────
function crudRoutes(base, table, getQ, cols, idField='id') {
  app.get(base, auth, async (req, res) => {
    try { const r = await pool.query(getQ); ok(res, r.rows); } catch(e) { err(res, e.message); }
  });
}

// Categories
app.get('/api/v1/categories', auth, async (req,res) => { try { ok(res,(await pool.query('SELECT * FROM categories ORDER BY id')).rows); } catch(e){err(res,e.message);}});
app.post('/api/v1/categories', auth, adminOnly, async (req,res) => { try { const {name,status}=req.body; if(!name)return err(res,'Name required',400); ok(res,(await pool.query('INSERT INTO categories(name,status) VALUES($1,$2) RETURNING *',[sanitize(name),status||'Active'])).rows[0]); } catch(e){err(res,e.message);}});
app.put('/api/v1/categories/:id', auth, adminOnly, async (req,res) => { try { const {name,status}=req.body; ok(res,(await pool.query('UPDATE categories SET name=$1,status=$2 WHERE id=$3 RETURNING *',[sanitize(name),status,req.params.id])).rows[0]); } catch(e){err(res,e.message);}});
app.delete('/api/v1/categories/:id', auth, adminOnly, async (req,res) => { try { await pool.query('DELETE FROM categories WHERE id=$1',[req.params.id]); ok(res,{}); } catch(e){err(res,e.message);}});

// Courses
app.get('/api/v1/courses', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT c.id, c.name, c.name AS title, cat.name AS category, c.duration, c.duration AS duration_weeks, c.description, c.status, c.thumbnail, (SELECT COUNT(*) FROM students WHERE course_id=c.id) AS student_count FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id ORDER BY c.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/courses', auth, adminOnly, async (req,res)=>{ try{ const {name,category,duration,status,description}=req.body; const catR=await pool.query('SELECT id FROM categories WHERE name=$1',[category]); const catId=catR.rows[0]?.id||null; const r=await pool.query('INSERT INTO courses(name,category_id,duration,status,description) VALUES($1,$2,$3,$4,$5) RETURNING id',[sanitize(name),catId,duration,status||'Active',description||'']); const full=await pool.query('SELECT c.id,c.name,cat.name AS category,c.duration,c.description,c.status FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id WHERE c.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.put('/api/v1/courses/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,category,duration,status,description}=req.body; const catR=await pool.query('SELECT id FROM categories WHERE name=$1',[category]); const catId=catR.rows[0]?.id||null; const r=await pool.query('UPDATE courses SET name=$1,category_id=$2,duration=$3,status=$4,description=$5 WHERE id=$6 RETURNING id',[sanitize(name),catId,duration,status,description||'',req.params.id]); const full=await pool.query('SELECT c.id,c.name,cat.name AS category,c.duration,c.description,c.status FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id WHERE c.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/courses/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM courses WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Modules
app.get('/api/v1/modules', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT m.id,m.name,c.name AS course,m.duration,m.order_no FROM modules m LEFT JOIN courses c ON m.course_id=c.id ORDER BY m.course_id,m.order_no`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/modules', auth, adminOnly, async (req,res)=>{ try{ const {name,course,duration,order_no}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; const r=await pool.query('INSERT INTO modules(name,course_id,duration,order_no) VALUES($1,$2,$3,$4) RETURNING id',[sanitize(name),crsId,duration,order_no||0]); const full=await pool.query('SELECT m.id,m.name,c.name AS course,m.duration FROM modules m LEFT JOIN courses c ON m.course_id=c.id WHERE m.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.put('/api/v1/modules/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,course,duration}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; const r=await pool.query('UPDATE modules SET name=$1,course_id=$2,duration=$3 WHERE id=$4 RETURNING id',[sanitize(name),crsId,duration,req.params.id]); const full=await pool.query('SELECT m.id,m.name,c.name AS course,m.duration FROM modules m LEFT JOIN courses c ON m.course_id=c.id WHERE m.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/modules/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM modules WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// MCQs
app.get('/api/v1/mcqs', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT m.id,m.question,c.name AS course,m.correct_answer AS answer,m.option_a AS oa,m.option_b AS ob,m.option_c AS oc,m.option_d AS od FROM mcqs m LEFT JOIN courses c ON m.course_id=c.id ORDER BY m.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/mcqs', auth, adminOnly, async (req,res)=>{ try{ const {question,course,answer,oa,ob,oc,od}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; const r=await pool.query('INSERT INTO mcqs(question,course_id,option_a,option_b,option_c,option_d,correct_answer) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[sanitize(question),crsId,oa,ob,oc,od,answer]); const full=await pool.query("SELECT m.id,m.question,c.name AS course,m.correct_answer AS answer,m.option_a AS oa,m.option_b AS ob,m.option_c AS oc,m.option_d AS od FROM mcqs m LEFT JOIN courses c ON m.course_id=c.id WHERE m.id=$1",[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.put('/api/v1/mcqs/:id', auth, adminOnly, async (req,res)=>{ try{ const {question,course,answer,oa,ob,oc,od}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; await pool.query('UPDATE mcqs SET question=$1,course_id=$2,option_a=$3,option_b=$4,option_c=$5,option_d=$6,correct_answer=$7 WHERE id=$8',[sanitize(question),crsId,oa,ob,oc,od,answer,req.params.id]); const full=await pool.query("SELECT m.id,m.question,c.name AS course,m.correct_answer AS answer,m.option_a AS oa,m.option_b AS ob,m.option_c AS oc,m.option_d AS od FROM mcqs m LEFT JOIN courses c ON m.course_id=c.id WHERE m.id=$1",[req.params.id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/mcqs/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM mcqs WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Exams
app.get('/api/v1/exams', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT e.id,e.name,c.name AS course,e.duration,e.pass_percentage AS pass,e.total_marks AS marks FROM exams e LEFT JOIN courses c ON e.course_id=c.id ORDER BY e.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/exams', auth, adminOnly, async (req,res)=>{ try{ const {name,course,duration,pass,marks}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; const r=await pool.query('INSERT INTO exams(name,course_id,duration,pass_percentage,total_marks) VALUES($1,$2,$3,$4,$5) RETURNING id',[sanitize(name),crsId,duration,pass,parseInt(marks)||0]); const full=await pool.query("SELECT e.id,e.name,c.name AS course,e.duration,e.pass_percentage AS pass,e.total_marks AS marks FROM exams e LEFT JOIN courses c ON e.course_id=c.id WHERE e.id=$1",[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.put('/api/v1/exams/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,course,duration,pass,marks}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const crsId=crsR.rows[0]?.id||null; await pool.query('UPDATE exams SET name=$1,course_id=$2,duration=$3,pass_percentage=$4,total_marks=$5 WHERE id=$6',[sanitize(name),crsId,duration,pass,parseInt(marks)||0,req.params.id]); const full=await pool.query("SELECT e.id,e.name,c.name AS course,e.duration,e.pass_percentage AS pass,e.total_marks AS marks FROM exams e LEFT JOIN courses c ON e.course_id=c.id WHERE e.id=$1",[req.params.id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/exams/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM exams WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Batches
app.get('/api/v1/batches', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT b.id, b.name, c.name AS course, c.name AS course_title, b.start_date, b.start_date AS start, b.end_date, b.end_date AS "end", t.name AS trainer, t.name AS trainer_name, b.max_students, b.max_students AS students, b.status, (SELECT COUNT(*) FROM students WHERE batch_id=b.id) AS student_count FROM batches b LEFT JOIN courses c ON b.course_id=c.id LEFT JOIN trainers t ON b.trainer_id=t.id ORDER BY b.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/batches', auth, adminOnly, async (req,res)=>{ try{ const {name,course,start,end,trainer,students,status}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const trR=await pool.query('SELECT id FROM trainers WHERE name=$1',[trainer]); const crsId=crsR.rows[0]?.id||null; const trId=trR.rows[0]?.id||null; const r=await pool.query('INSERT INTO batches(name,course_id,start_date,end_date,trainer_id,max_students,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',[sanitize(name),crsId,start||null,end||null,trId,parseInt(students)||30,status||'Active']); const full=await pool.query(`SELECT b.id,b.name,c.name AS course,b.start_date AS start,b.end_date AS "end",t.name AS trainer,b.max_students AS students,b.status FROM batches b LEFT JOIN courses c ON b.course_id=c.id LEFT JOIN trainers t ON b.trainer_id=t.id WHERE b.id=$1`,[r.rows[0].id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.put('/api/v1/batches/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,course,start,end,trainer,students,status}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const trR=await pool.query('SELECT id FROM trainers WHERE name=$1',[trainer]); const crsId=crsR.rows[0]?.id||null; const trId=trR.rows[0]?.id||null; await pool.query('UPDATE batches SET name=$1,course_id=$2,start_date=$3,end_date=$4,trainer_id=$5,max_students=$6,status=$7 WHERE id=$8',[sanitize(name),crsId,start||null,end||null,trId,parseInt(students)||30,status,req.params.id]); const full=await pool.query(`SELECT b.id,b.name,c.name AS course,b.start_date AS start,b.end_date AS "end",t.name AS trainer,b.max_students AS students,b.status FROM batches b LEFT JOIN courses c ON b.course_id=c.id LEFT JOIN trainers t ON b.trainer_id=t.id WHERE b.id=$1`,[req.params.id]); ok(res,full.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/batches/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM batches WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Trainers
app.get('/api/v1/trainers', auth, async (req,res)=>{ try{ const r=await pool.query('SELECT id,name,email,contact,expertise,status,profile_photo,created_at FROM trainers ORDER BY id'); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/trainers', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,expertise,status,password}=req.body; const hash=await bcrypt.hash(password||'trainer@123',12); const r=await pool.query('INSERT INTO trainers(name,email,password_hash,contact,expertise,status) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,email,contact,expertise,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contact||'',expertise||'',status||'Active']); ok(res,r.rows[0]); }catch(e){ if(e.code==='23505')return err(res,'Email already exists',409); err(res,e.message);}});
app.put('/api/v1/trainers/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,expertise,status}=req.body; const r=await pool.query('UPDATE trainers SET name=$1,email=$2,contact=$3,expertise=$4,status=$5 WHERE id=$6 RETURNING id,name,email,contact,expertise,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',expertise||'',status,req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/trainers/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM trainers WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Students
app.get('/api/v1/students', auth, staffOnly, async (req,res)=>{ try{ const {page=1,limit=50,search='',status='',batch_id='',trainer=''}=req.query; const offset=(page-1)*limit; let q=`SELECT s.id,s.name,s.email,s.contact AS phone,s.contact,c.name AS course,c.name AS course_title,b.name AS batch,b.name AS batch_name,b.id AS batch_id,s.status,s.created_at,0 AS progress FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE 1=1`; const params=[]; if(search){params.push('%'+sanitize(search)+'%');q+=` AND (s.name ILIKE $${params.length} OR s.email ILIKE $${params.length})`;} if(status){params.push(status);q+=` AND s.status=$${params.length}`;} if(batch_id){params.push(batch_id);q+=` AND s.batch_id=$${params.length}`;} if(trainer==='me' && req.user.role==='trainer'){params.push(req.user.id);q+=` AND b.trainer_id=$${params.length}`;} q+=` ORDER BY s.id DESC LIMIT ${parseInt(limit)} OFFSET ${offset}`; const r=await pool.query(q,params); const cnt=await pool.query('SELECT COUNT(*) FROM students'); ok(res,{students:r.rows,rows:r.rows,total:+cnt.rows[0].count,page:+page,limit:+limit}); }catch(e){err(res,e.message);}});
app.post('/api/v1/students', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,course,batch,status,password}=req.body; const hash=await bcrypt.hash(password||'student@123',12); const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const batR=await pool.query('SELECT id FROM batches WHERE name=$1',[batch]); const crsId=crsR.rows[0]?.id||null; const batId=batR.rows[0]?.id||null; const r=await pool.query('INSERT INTO students(name,email,password_hash,contact,course_id,batch_id,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contact||'',crsId,batId,status||'Active']); ok(res,r.rows[0]); }catch(e){ if(e.code==='23505')return err(res,'Email already exists',409); err(res,e.message);}});
app.put('/api/v1/students/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,course,batch,status}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const batR=await pool.query('SELECT id FROM batches WHERE name=$1',[batch]); const crsId=crsR.rows[0]?.id||null; const batId=batR.rows[0]?.id||null; const r=await pool.query('UPDATE students SET name=$1,email=$2,contact=$3,course_id=$4,batch_id=$5,status=$6 WHERE id=$7 RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',crsId,batId,status,req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/students/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM students WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});
app.put('/api/v1/students/:id/approve', auth, adminOnly, async (req,res)=>{ try{ await pool.query("UPDATE students SET status='Active' WHERE id=$1",[req.params.id]); const s=await pool.query('SELECT name,email FROM students WHERE id=$1',[req.params.id]); if(s.rows[0]) await sendEmail(s.rows[0].email,'Registration Approved - Smart LMS',`<h2>Congratulations ${s.rows[0].name}!</h2><p>Your registration has been approved. You can now log in to the LMS.</p><p>Login: <a href="#">Smart LMS</a></p><small>Connecting Dot Consultancy Pvt. Ltd.</small>`); ok(res,{},'Student approved'); }catch(e){err(res,e.message);}});

// ── ME / PROFILE ──────────────────────────────────────────────────────────────
app.get('/api/v1/me', auth, async (req,res)=>{ try{ const {id,role}=req.user; let row; if(role==='admin') row=(await pool.query('SELECT id,username AS name,username AS email FROM admins WHERE id=$1',[id])).rows[0]; else if(role==='bschool') row=(await pool.query('SELECT id,name,email,contact,address,status FROM bschools WHERE id=$1',[id])).rows[0]; else if(role==='trainer') row=(await pool.query('SELECT id,name,email,contact,expertise,status,profile_photo FROM trainers WHERE id=$1',[id])).rows[0]; else { const r=await pool.query(`SELECT s.id,s.name,s.email,s.contact,s.status,c.name AS course,b.name AS batch,s.course_id,s.batch_id,s.profile_photo FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE s.id=$1`,[id]); row=r.rows[0]; } ok(res,row||{}); }catch(e){err(res,e.message);}});
app.put('/api/v1/me', auth, async (req,res)=>{ try{ const {id,role}=req.user; const {name,email,contact,expertise,address}=req.body; if(role==='trainer'){const r=await pool.query('UPDATE trainers SET name=$1,email=$2,contact=$3,expertise=$4 WHERE id=$5 RETURNING id,name,email,contact,expertise,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',expertise||'',id]); ok(res,r.rows[0]);} else if(role==='bschool'){const r=await pool.query('UPDATE bschools SET name=$1,email=$2,contact=$3,address=$4 WHERE id=$5 RETURNING id,name,email,contact,address,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',address||'',id]); ok(res,r.rows[0]);} else if(role==='student'){const r=await pool.query('UPDATE students SET name=$1,email=$2,contact=$3 WHERE id=$4 RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',id]); ok(res,r.rows[0]);} else ok(res,{}); }catch(e){err(res,e.message);}});

// Profile photo upload
app.post('/api/v1/me/photo', auth, (req,res)=>{ req.uploadFolder='profiles'; upload.single('photo')(req,res,async(e)=>{ if(e)return err(res,e.message,400); if(!req.file)return err(res,'No file',400); const photoPath='/uploads/profiles/'+req.file.filename; const {id,role}=req.user; const tbl=role==='trainer'?'trainers':'students'; await pool.query(`UPDATE ${tbl} SET profile_photo=$1 WHERE id=$2`,[photoPath,id]); ok(res,{profile_photo:photoPath}); });});

// ── REPORT ────────────────────────────────────────────────────────────────────
app.get('/api/v1/report', auth, staffOnly, async (req,res)=>{ const {course,batch,from,to,status}=req.query; let q=`SELECT s.name,s.email,s.contact,c.name AS course,b.name AS batch,s.created_at AS enrolled_on,s.status FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE 1=1`; const params=[]; if(course&&course!=='All') {params.push(course);q+=` AND c.name=$${params.length}`;} if(batch&&batch!=='All') {params.push(batch);q+=` AND b.name=$${params.length}`;} if(status&&status!=='All') {params.push(status);q+=` AND s.status=$${params.length}`;} if(from){params.push(from);q+=` AND s.created_at>=$${params.length}`;} if(to){params.push(to);q+=` AND s.created_at<=$${params.length}`;} q+=' ORDER BY s.id'; try{const r=await pool.query(q,params); ok(res,r.rows);}catch(e){err(res,e.message);}});

// ── ATTENDANCE ────────────────────────────────────────────────────────────────
app.post('/api/v1/attendance', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ const {batch_id,date,records}=req.body; for(const rec of records){ await pool.query('INSERT INTO attendance(student_id,batch_id,date,status,marked_by) VALUES($1,$2,$3,$4,$5) ON CONFLICT(student_id,batch_id,date) DO UPDATE SET status=$4,marked_by=$5',[rec.student_id,batch_id,date,rec.status,req.user.id]); } ok(res,{},'Attendance marked'); }catch(e){err(res,e.message);}});
app.get('/api/v1/attendance/batch/:id', auth, staffOnly, async (req,res)=>{
  try{
    if(req.params.id==='summary'){
      // Trainer summary route
      const r=await pool.query(`SELECT a.date, b.name AS batch_name, COUNT(*) AS total, SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS present, SUM(CASE WHEN a.status='Absent' THEN 1 ELSE 0 END) AS absent FROM attendance a JOIN batches b ON a.batch_id=b.id WHERE (b.trainer_id=$1 OR $2='admin') GROUP BY a.date, b.name ORDER BY a.date DESC LIMIT 30`,[req.user.id,req.user.role]);
      return ok(res,r.rows);
    }
    const {from,to}=req.query;
    const params=[req.params.id];
    let dateFilter='';
    if(from){params.push(from);dateFilter+=` AND a.date>=$${params.length}`;}
    if(to){params.push(to);dateFilter+=` AND a.date<=$${params.length}`;}
    const r=await pool.query(`SELECT a.date,a.status,s.name AS student,s.name AS student_name,s.id AS student_id FROM attendance a JOIN students s ON a.student_id=s.id WHERE a.batch_id=$1${dateFilter} ORDER BY a.date DESC,s.name`,params);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});
app.get('/api/v1/attendance/student/:id', auth, async (req,res)=>{ try{ const sid=req.user.role==='student'?req.user.id:req.params.id; const r=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present, SUM(CASE WHEN status='Absent' THEN 1 ELSE 0 END) AS absent FROM attendance WHERE student_id=$1`,[sid]); const details=await pool.query(`SELECT a.date, a.status, b.name AS batch_name, COALESCE(t.name,'Admin') AS marked_by_name FROM attendance a LEFT JOIN batches b ON a.batch_id=b.id LEFT JOIN trainers t ON a.marked_by=t.id WHERE a.student_id=$1 ORDER BY a.date DESC LIMIT 50`,[sid]); const {total,present,absent}=r.rows[0]; const pct=+total>0?Math.round((+present/+total)*100):0; ok(res,{total:+total,present:+present,present_days:+present,absent:+absent,absent_days:+absent,percentage:pct,records:details.rows,details:details.rows}); }catch(e){err(res,e.message);}});

// ── EXAM ATTEMPTS ─────────────────────────────────────────────────────────────
app.get('/api/v1/exam/questions/:examId', auth, studentOnly, async (req,res)=>{ try{ const exam=await pool.query('SELECT * FROM exams WHERE id=$1',[req.params.examId]); if(!exam.rows[0])return err(res,'Exam not found',404); const qs=await pool.query('SELECT id,question,option_a,option_b,option_c,option_d FROM mcqs WHERE course_id=$1 ORDER BY RANDOM() LIMIT 20',[exam.rows[0].course_id]); ok(res,{exam:exam.rows[0],questions:qs.rows}); }catch(e){err(res,e.message);}});
app.post('/api/v1/exam/attempt', auth, studentOnly, async (req,res)=>{ try{ const {exam_id,answers}=req.body; const exam=await pool.query('SELECT * FROM exams WHERE id=$1',[exam_id]); if(!exam.rows[0])return err(res,'Exam not found',404); const qs=await pool.query('SELECT id,correct_answer FROM mcqs WHERE course_id=$1',[exam.rows[0].course_id]); let score=0; for(const q of qs.rows){ if(answers[q.id]===q.correct_answer) score++; } const maxScore=qs.rows.length; const pct=maxScore>0?Math.round((score/maxScore)*100):0; const pass_pct=parseInt(exam.rows[0].pass_percentage)||60; const status=pct>=pass_pct?'Passed':'Failed'; const r=await pool.query('INSERT INTO student_exam_attempts(student_id,exam_id,score,max_score,status,answers,submitted_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) RETURNING *',[req.user.id,exam_id,score,maxScore,status,JSON.stringify(answers)]); ok(res,{score,max_score:maxScore,percentage:pct,status,attempt:r.rows[0]},'Exam submitted'); }catch(e){err(res,e.message);}});
app.get('/api/v1/exam/results/:studentId', auth, async (req,res)=>{ try{ const sid=req.user.role==='student'?req.user.id:req.params.studentId; const r=await pool.query(`SELECT sea.id, e.name AS exam, e.name AS exam_title, c.name AS course_title, sea.score, sea.max_score, sea.status, sea.submitted_at FROM student_exam_attempts sea JOIN exams e ON sea.exam_id=e.id LEFT JOIN courses c ON e.course_id=c.id WHERE sea.student_id=$1 ORDER BY sea.submitted_at DESC`,[sid]); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── ASSIGNMENTS ───────────────────────────────────────────────────────────────
app.get('/api/v1/assignments', auth, async (req,res)=>{ try{ const {batch_id,trainer}=req.query; let q=`SELECT a.id,a.title,a.description,c.name AS course,c.name AS course_name,b.name AS batch,b.name AS batch_name,t.name AS trainer,a.due_date,a.max_marks,a.created_at,(SELECT COUNT(*) FROM assignment_submissions WHERE assignment_id=a.id) AS submission_count FROM assignments a LEFT JOIN courses c ON a.course_id=c.id LEFT JOIN batches b ON a.batch_id=b.id LEFT JOIN trainers t ON a.trainer_id=t.id WHERE 1=1`; const params=[]; if(batch_id){params.push(batch_id);q+=` AND a.batch_id=$${params.length}`;} if(trainer==='me'&&req.user.role==='trainer'){q+=` AND a.trainer_id=${req.user.id}`;} q+=' ORDER BY a.created_at DESC'; ok(res,(await pool.query(q,params)).rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/assignments', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ const {title,description,course_id,batch_id,due_date,max_marks}=req.body; const trainer_id=req.user.role==='trainer'?req.user.id:null; const r=await pool.query('INSERT INTO assignments(title,description,course_id,batch_id,trainer_id,due_date,max_marks) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[sanitize(title),sanitize(description||''),course_id,batch_id,trainer_id,due_date,max_marks||100]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/assignments/:id', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ await pool.query('DELETE FROM assignments WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

app.post('/api/v1/assignments/:id/submit', auth, studentOnly, (req,res)=>{ req.uploadFolder='assignments'; upload.single('file')(req,res,async(e)=>{ if(e)return err(res,e.message,400); try{ const fp=req.file?'/uploads/assignments/'+req.file.filename:null; const {text_answer}=req.body; const r=await pool.query('INSERT INTO assignment_submissions(assignment_id,student_id,file_path,text_answer) VALUES($1,$2,$3,$4) ON CONFLICT(assignment_id,student_id) DO UPDATE SET file_path=$3,text_answer=$4,submitted_at=NOW() RETURNING *',[req.params.id,req.user.id,fp,text_answer||null]); ok(res,r.rows[0],'Assignment submitted'); }catch(ex){err(res,ex.message);} });});

app.get('/api/v1/assignments/:id/submissions', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ const r=await pool.query(`SELECT asub.id,s.name AS student,asub.submitted_at,asub.file_path,asub.marks_obtained,asub.feedback FROM assignment_submissions asub JOIN students s ON asub.student_id=s.id WHERE asub.assignment_id=$1`,[req.params.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.put('/api/v1/assignments/grade/:subId', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ const {marks,feedback}=req.body; const r=await pool.query('UPDATE assignment_submissions SET marks_obtained=$1,feedback=$2,graded_by=$3,graded_at=NOW() WHERE id=$4 RETURNING *',[marks,feedback,req.user.id,req.params.subId]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});

// ── PROGRESS ──────────────────────────────────────────────────────────────────
app.post('/api/v1/progress/complete', auth, studentOnly, async (req,res)=>{ try{ const {module_id}=req.body; await pool.query('INSERT INTO student_progress(student_id,module_id,completed,completed_at) VALUES($1,$2,TRUE,NOW()) ON CONFLICT(student_id,module_id) DO UPDATE SET completed=TRUE,completed_at=NOW()',[req.user.id,module_id]); ok(res,{},'Module marked complete'); }catch(e){err(res,e.message);}});
app.get('/api/v1/progress/me', auth, studentOnly, async (req,res)=>{ try{ const courseR=await pool.query(`SELECT c.id,c.name FROM courses c JOIN students s ON s.course_id=c.id WHERE s.id=$1`,[req.user.id]); const r=await pool.query(`SELECT m.id,m.name,m.order_no,COALESCE(sp.completed,FALSE) AS completed,sp.completed_at FROM modules m LEFT JOIN student_progress sp ON sp.module_id=m.id AND sp.student_id=$1 WHERE m.course_id=(SELECT course_id FROM students WHERE id=$1) ORDER BY m.order_no`,[req.user.id]); const total=r.rows.length; const done=r.rows.filter(x=>x.completed).length; const pct=total>0?Math.round((done/total)*100):0; const courses=courseR.rows.map(c=>({id:c.id,title:c.name,percentage:pct,completed_modules:done,total_modules:total})); ok(res,{modules:r.rows,total,completed:done,percentage:pct,overall_percentage:pct,courses}); }catch(e){err(res,e.message);}});

// ── CERTIFICATES ──────────────────────────────────────────────────────────────
app.post('/api/v1/certificates/issue', auth, adminOnly, async (req,res)=>{ try{ const {student_id,course_id,batch_id}=req.body; const certNo='CDPL-'+Date.now(); const r=await pool.query('INSERT INTO certificates(student_id,course_id,batch_id,certificate_no) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING *',[student_id,course_id,batch_id,certNo]); if(r.rows[0]){ const s=await pool.query('SELECT name,email FROM students WHERE id=$1',[student_id]); if(s.rows[0]) await sendEmail(s.rows[0].email,'Certificate Issued - Smart LMS',`<h2>Congratulations ${s.rows[0].name}!</h2><p>Your completion certificate (${certNo}) has been issued.</p><small>Connecting Dot Consultancy Pvt. Ltd.</small>`); } ok(res,r.rows[0]||{},'Certificate issued'); }catch(e){err(res,e.message);}});
app.get('/api/v1/certificates/student/:id', auth, async (req,res)=>{ try{ const sid=req.user.role==='student'?req.user.id:req.params.id; const r=await pool.query(`SELECT cert.*,s.name AS student,c.name AS course FROM certificates cert JOIN students s ON cert.student_id=s.id JOIN courses c ON cert.course_id=c.id WHERE cert.student_id=$1`,[sid]); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── FEE MANAGEMENT ────────────────────────────────────────────────────────────
app.get('/api/v1/fees', auth, adminOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT f.*,s.name AS student FROM fee_payments f JOIN students s ON f.student_id=s.id ORDER BY f.created_at DESC`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.get('/api/v1/fees/student/:id', auth, async (req,res)=>{ try{ const sid=req.user.role==='student'?req.user.id:req.params.id; const r=await pool.query('SELECT * FROM fee_payments WHERE student_id=$1 ORDER BY created_at DESC',[sid]); const total=await pool.query('SELECT COALESCE(SUM(amount),0) AS total FROM fee_payments WHERE student_id=$1 AND status=$2',[sid,'Paid']); ok(res,{payments:r.rows,totalPaid:+total.rows[0].total}); }catch(e){err(res,e.message);}});
app.post('/api/v1/fees', auth, adminOnly, async (req,res)=>{ try{ const {student_id,amount,payment_date,payment_mode,status,remarks}=req.body; const rcpt='RCPT-'+Date.now(); const r=await pool.query('INSERT INTO fee_payments(student_id,amount,payment_date,payment_mode,receipt_no,status,remarks) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[student_id,amount,payment_date,payment_mode||'Cash',rcpt,status||'Paid',remarks||'']); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.get('/api/v1/fees/report', auth, adminOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT s.name AS student,s.email,f.amount,f.payment_date,f.payment_mode,f.receipt_no,f.status FROM fee_payments f JOIN students s ON f.student_id=s.id ORDER BY f.created_at DESC`); const total=await pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM fee_payments WHERE status='Paid'"); ok(res,{records:r.rows,totalPaid:+total.rows[0].total}); }catch(e){err(res,e.message);}});

// ── NOTIFICATIONS ─────────────────────────────────────────────────────────────
app.get('/api/v1/notifications', auth, async (req,res)=>{ try{ const r=await pool.query('SELECT * FROM notifications WHERE user_id=$1 AND role=$2 ORDER BY created_at DESC LIMIT 20',[req.user.id,req.user.role]); const unread=r.rows.filter(n=>!n.is_read).length; ok(res,{notifications:r.rows,unread}); }catch(e){err(res,e.message);}});
app.put('/api/v1/notifications/read', auth, async (req,res)=>{ try{ await pool.query('UPDATE notifications SET is_read=TRUE WHERE user_id=$1 AND role=$2',[req.user.id,req.user.role]); ok(res,{}); }catch(e){err(res,e.message);}});
app.post('/api/v1/notifications/broadcast', auth, adminOnly, async (req,res)=>{ try{ const {message,roles}=req.body; const targetRoles=roles||['student','trainer','bschool']; for(const role of targetRoles){ const users=await pool.query(`SELECT id FROM ${role==='student'?'students':role==='trainer'?'trainers':'bschools'}`); for(const u of users.rows){ await pool.query('INSERT INTO notifications(user_id,role,message,type) VALUES($1,$2,$3,$4)',[u.id,role,sanitize(message),'broadcast']); } } ok(res,{},'Notification broadcast sent'); }catch(e){err(res,e.message);}});

// ── COURSE MATERIALS ──────────────────────────────────────────────────────────
app.get('/api/v1/materials/:moduleId', auth, async (req,res)=>{ try{ const r=await pool.query('SELECT * FROM course_materials WHERE module_id=$1 ORDER BY created_at',[req.params.moduleId]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/materials', auth, requireRole('admin','trainer'), (req,res)=>{ req.uploadFolder='materials'; upload.single('file')(req,res,async(e)=>{ if(e)return err(res,e.message,400); try{ const {module_id,course_id,title,type,url}=req.body; const fp=req.file?'/uploads/materials/'+req.file.filename:(url||null); const r=await pool.query('INSERT INTO course_materials(module_id,course_id,title,type,file_path_or_url,uploaded_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[module_id,course_id,sanitize(title),type||'PDF',fp,req.user.id]); ok(res,r.rows[0]); }catch(ex){err(res,ex.message);} });});
app.delete('/api/v1/materials/:id', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ await pool.query('DELETE FROM course_materials WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// ── TIMETABLE ─────────────────────────────────────────────────────────────────
app.get('/api/v1/timetable/:batchId', auth, async (req,res)=>{ try{ let bId=req.params.batchId; if(bId==='me'&&req.user.role==='student'){const sr=await pool.query('SELECT batch_id FROM students WHERE id=$1',[req.user.id]);bId=sr.rows[0]?.batch_id;} const r=await pool.query(`SELECT t.*,b.name AS batch_name,tr.name AS trainer_name FROM timetable t LEFT JOIN batches b ON t.batch_id=b.id LEFT JOIN trainers tr ON t.trainer_id=tr.id WHERE t.batch_id=$1 ORDER BY CASE day_of_week WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 ELSE 7 END,t.start_time`,[bId]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/timetable', auth, adminOnly, async (req,res)=>{ try{ const {batch_id,day_of_week,start_time,end_time,subject,trainer_id,room_or_link}=req.body; const r=await pool.query('INSERT INTO timetable(batch_id,day_of_week,start_time,end_time,subject,trainer_id,room_or_link) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[batch_id,day_of_week,start_time,end_time,sanitize(subject),trainer_id,room_or_link||'']); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/timetable/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM timetable WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// ── FEEDBACK ──────────────────────────────────────────────────────────────────
app.post('/api/v1/feedback', auth, studentOnly, async (req,res)=>{ try{ const {course_id,trainer_id,rating,feedback_text}=req.body; if(rating<1||rating>5)return err(res,'Rating must be 1-5',400); const r=await pool.query('INSERT INTO course_feedback(student_id,course_id,trainer_id,rating,feedback_text) VALUES($1,$2,$3,$4,$5) ON CONFLICT(student_id,course_id) DO UPDATE SET rating=$4,feedback_text=$5 RETURNING *',[req.user.id,course_id,trainer_id,rating,sanitize(feedback_text||'')]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.get('/api/v1/feedback/course/:id', auth, staffOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT f.*,s.name AS student FROM course_feedback f JOIN students s ON f.student_id=s.id WHERE f.course_id=$1 ORDER BY f.submitted_at DESC`,[req.params.id]); const avg=await pool.query('SELECT AVG(rating) AS avg_rating,COUNT(*) AS total FROM course_feedback WHERE course_id=$1',[req.params.id]); ok(res,{feedback:r.rows,avg_rating:parseFloat(avg.rows[0].avg_rating||0).toFixed(1),total:+avg.rows[0].total}); }catch(e){err(res,e.message);}});

// ── TRAINER-SPECIFIC ──────────────────────────────────────────────────────────
app.get('/api/v1/trainer/batches', auth, trainerOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT b.id,b.name,c.name AS course,b.start_date AS start,b.end_date AS "end",b.max_students,b.status FROM batches b LEFT JOIN courses c ON b.course_id=c.id WHERE b.trainer_id=$1 ORDER BY b.id`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.get('/api/v1/trainer/students', auth, trainerOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT s.id,s.name,s.email,s.contact,c.name AS course,b.name AS batch,s.status FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE b.trainer_id=$1 ORDER BY s.name`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── STUDENT-SPECIFIC ──────────────────────────────────────────────────────────
app.get('/api/v1/student/modules', auth, studentOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT m.id,m.name,m.duration,m.order_no,COALESCE(sp.completed,FALSE) AS completed FROM modules m LEFT JOIN student_progress sp ON sp.module_id=m.id AND sp.student_id=$1 WHERE m.course_id=(SELECT course_id FROM students WHERE id=$1) ORDER BY m.order_no`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.get('/api/v1/student/exams', auth, studentOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT e.id,e.name,e.duration,e.pass_percentage,e.total_marks,(SELECT status FROM student_exam_attempts WHERE student_id=$1 AND exam_id=e.id ORDER BY submitted_at DESC LIMIT 1) AS last_status FROM exams e WHERE e.course_id=(SELECT course_id FROM students WHERE id=$1)`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.get('/api/v1/student/materials', auth, studentOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT cm.* FROM course_materials cm JOIN modules m ON cm.module_id=m.id WHERE m.course_id=(SELECT course_id FROM students WHERE id=$1) ORDER BY m.order_no,cm.created_at`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.get('/api/v1/student/timetable', auth, studentOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT t.*,tr.name AS trainer_name FROM timetable t LEFT JOIN trainers tr ON t.trainer_id=tr.id WHERE t.batch_id=(SELECT batch_id FROM students WHERE id=$1) ORDER BY CASE day_of_week WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 ELSE 7 END,t.start_time`,[req.user.id]); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── ANALYTICS OVERVIEW (Admin) ────────────────────────────────────────────────
app.get('/api/v1/analytics/overview', auth, async (req,res)=>{
  try{
    const [ts,tr,tc,tb,rev,certs]=await Promise.all([
      pool.query('SELECT COUNT(*) FROM students'),
      pool.query('SELECT COUNT(*) FROM trainers'),
      pool.query('SELECT COUNT(*) FROM courses'),
      pool.query('SELECT COUNT(*) FROM batches'),
      pool.query("SELECT COALESCE(SUM(amount),0) AS total FROM fee_payments WHERE status='Paid'"),
      pool.query('SELECT COUNT(*) FROM certificates')
    ]);
    ok(res,{students:+ts.rows[0].count,trainers:+tr.rows[0].count,courses:+tc.rows[0].count,batches:+tb.rows[0].count,revenue:+rev.rows[0].total,certificates:+certs.rows[0].count});
  }catch(e){err(res,e.message);}
});

// ── BSCHOOLS LIST ─────────────────────────────────────────────────────────────
app.get('/api/v1/bschools', auth, async (req,res)=>{ try{ const r=await pool.query('SELECT id,name,email,contact,address,status,created_at FROM bschools ORDER BY id'); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.delete('/api/v1/bschools/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM bschools WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// ── DELETE USER (admin shortcut) ──────────────────────────────────────────────
app.delete('/api/v1/users/:id', auth, adminOnly, async (req,res)=>{ try{ const {role}=req.query; if(role==='trainer') await pool.query('DELETE FROM trainers WHERE id=$1',[req.params.id]); else if(role==='bschool') await pool.query('DELETE FROM bschools WHERE id=$1',[req.params.id]); else await pool.query('DELETE FROM students WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// ── CERTIFICATES LIST (Admin) ─────────────────────────────────────────────────
app.get('/api/v1/certificates', auth, adminOnly, async (req,res)=>{ try{ const r=await pool.query(`SELECT cert.*,s.name AS student,s.email AS student_email,c.name AS course FROM certificates cert JOIN students s ON cert.student_id=s.id JOIN courses c ON cert.course_id=c.id ORDER BY cert.created_at DESC`); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── FEES UPDATE ────────────────────────────────────────────────────────────────
app.put('/api/v1/fees/:id', auth, adminOnly, async (req,res)=>{ try{ const {status,payment_date,remarks}=req.body; const r=await pool.query('UPDATE fee_payments SET status=$1,payment_date=$2,remarks=$3 WHERE id=$4 RETURNING *',[status||'Paid',payment_date||new Date().toISOString().slice(0,10),remarks||'',req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});

// ── STUDENT: ENROLLED COURSES ─────────────────────────────────────────────────
app.get('/api/v1/courses/enrolled', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT c.id AS course_id, c.name AS title, c.description, c.thumbnail,
             b.name AS batch_name, b.id AS batch_id, t.name AS trainer_name, s.status,
             COALESCE((SELECT COUNT(*) FROM modules WHERE course_id=c.id),0) AS total_modules,
             COALESCE((SELECT COUNT(*) FROM student_progress sp JOIN modules m ON sp.module_id=m.id WHERE m.course_id=c.id AND sp.student_id=s.id AND sp.completed=TRUE),0) AS completed_modules
      FROM students s
      JOIN courses c ON s.course_id=c.id
      LEFT JOIN batches b ON s.batch_id=b.id
      LEFT JOIN trainers t ON b.trainer_id=t.id
      WHERE s.id=$1
    `,[req.user.id]);
    const rows=r.rows.map(row=>({...row,progress:+row.total_modules>0?Math.round((+row.completed_modules/+row.total_modules)*100):0}));
    ok(res,rows);
  }catch(e){err(res,e.message);}
});

// ── STUDENT: ASSIGNMENTS ──────────────────────────────────────────────────────
app.get('/api/v1/assignments/me', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT a.id, a.title, a.description, c.name AS course_name, b.name AS batch_name,
             a.due_date, a.max_marks,
             asub.submitted_at, asub.marks_obtained, asub.feedback,
             CASE WHEN asub.id IS NOT NULL THEN 'submitted' ELSE 'pending' END AS submission_status
      FROM assignments a
      LEFT JOIN courses c ON a.course_id=c.id
      LEFT JOIN batches b ON a.batch_id=b.id
      LEFT JOIN assignment_submissions asub ON asub.assignment_id=a.id AND asub.student_id=$1
      WHERE a.batch_id=(SELECT batch_id FROM students WHERE id=$1)
      ORDER BY a.due_date ASC NULLS LAST
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ── STUDENT: TIMETABLE ────────────────────────────────────────────────────────
app.get('/api/v1/timetable/me', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT t.*, b.name AS batch_name, tr.name AS trainer_name
      FROM timetable t
      LEFT JOIN batches b ON t.batch_id=b.id
      LEFT JOIN trainers tr ON t.trainer_id=tr.id
      WHERE t.batch_id=(SELECT batch_id FROM students WHERE id=$1)
      ORDER BY CASE day_of_week WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 ELSE 7 END, t.start_time
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ── STUDENT: AVAILABLE EXAMS ──────────────────────────────────────────────────
app.get('/api/v1/exams/available', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT e.id, e.name AS title, c.name AS course_title, e.duration, e.pass_percentage, e.total_marks,
             (SELECT status FROM student_exam_attempts WHERE student_id=$1 AND exam_id=e.id ORDER BY submitted_at DESC LIMIT 1) AS status
      FROM exams e JOIN courses c ON e.course_id=c.id
      WHERE e.course_id=(SELECT course_id FROM students WHERE id=$1)
    `,[req.user.id]);
    ok(res,r.rows.map(e=>({...e,status:e.status||'upcoming'})));
  }catch(e){err(res,e.message);}
});

// ── MATERIALS (student all / trainer / by course) ─────────────────────────────
app.get('/api/v1/materials', auth, async (req,res)=>{
  try{
    let r;
    if(req.user.role==='student'){
      r=await pool.query(`SELECT cm.*,m.name AS module_name,c.name AS course_title FROM course_materials cm JOIN modules m ON cm.module_id=m.id JOIN courses c ON cm.course_id=c.id WHERE m.course_id=(SELECT course_id FROM students WHERE id=$1) ORDER BY m.order_no,cm.created_at`,[req.user.id]);
    } else if(req.user.role==='trainer'){
      r=await pool.query(`SELECT cm.*,m.name AS module_name,c.name AS course_title FROM course_materials cm JOIN modules m ON cm.module_id=m.id JOIN courses c ON cm.course_id=c.id WHERE cm.uploaded_by=$1 ORDER BY cm.created_at DESC`,[req.user.id]);
    } else {
      r=await pool.query(`SELECT cm.*,m.name AS module_name,c.name AS course_title FROM course_materials cm JOIN modules m ON cm.module_id=m.id JOIN courses c ON cm.course_id=c.id ORDER BY cm.created_at DESC`);
    }
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});
app.get('/api/v1/materials/course/:courseId', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT cm.*,m.name AS module_name,c.name AS course_title FROM course_materials cm JOIN modules m ON cm.module_id=m.id JOIN courses c ON cm.course_id=c.id WHERE cm.course_id=$1 ORDER BY m.order_no,cm.created_at`,[req.params.courseId]); ok(res,r.rows); }catch(e){err(res,e.message);}});

// ── NOTIFICATIONS: MARK ALL READ ──────────────────────────────────────────────
app.put('/api/v1/notifications/read', auth, async (req,res)=>{ try{ await pool.query('UPDATE notifications SET is_read=TRUE WHERE user_id=$1 AND role=$2 AND is_read=FALSE',[req.user.id,req.user.role]); ok(res,{},'All notifications marked as read'); }catch(e){err(res,e.message);}});

// ── TRAINER: MY BATCHES ───────────────────────────────────────────────────────
app.get('/api/v1/batches/my', auth, trainerOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT b.id, b.name, c.name AS course_title, c.id AS course_id,
             b.start_date, b.end_date, b.max_students, b.status,
             (SELECT COUNT(*) FROM students WHERE batch_id=b.id) AS student_count
      FROM batches b LEFT JOIN courses c ON b.course_id=c.id
      WHERE b.trainer_id=$1 ORDER BY b.id
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ── TRAINER: ATTENDANCE BATCH SUMMARY ────────────────────────────────────────
app.get('/api/v1/attendance/batch/summary', auth, trainerOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT a.date, b.name AS batch_name,
             COUNT(*) AS total,
             SUM(CASE WHEN a.status='Present' THEN 1 ELSE 0 END) AS present,
             SUM(CASE WHEN a.status='Absent' THEN 1 ELSE 0 END) AS absent
      FROM attendance a
      JOIN batches b ON a.batch_id=b.id
      WHERE b.trainer_id=$1
      GROUP BY a.date, b.name ORDER BY a.date DESC LIMIT 30
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ── TRAINER: TIMETABLE FILTER ─────────────────────────────────────────────────
app.get('/api/v1/timetable', auth, async (req,res)=>{
  try{
    const {trainer,batch_id}=req.query;
    let q=`SELECT t.*,b.name AS batch_name,tr.name AS trainer_name FROM timetable t LEFT JOIN batches b ON t.batch_id=b.id LEFT JOIN trainers tr ON t.trainer_id=tr.id WHERE 1=1`;
    const params=[];
    if(trainer==='me'&&req.user.role==='trainer'){q+=` AND t.trainer_id=${req.user.id}`;}
    if(batch_id){params.push(batch_id);q+=` AND t.batch_id=$${params.length}`;}
    q+=` ORDER BY CASE day_of_week WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6 ELSE 7 END,t.start_time`;
    ok(res,(await pool.query(q,params)).rows);
  }catch(e){err(res,e.message);}
});

// ── ASSIGNMENTS: GRADE ────────────────────────────────────────────────────────
app.put('/api/v1/assignments/grade/:id', auth, requireRole('admin','trainer'), async (req,res)=>{ try{ const {marks_obtained,feedback}=req.body; const r=await pool.query('UPDATE assignment_submissions SET marks_obtained=$1,feedback=$2,graded_by=$3,graded_at=NOW() WHERE id=$4 RETURNING *',[marks_obtained,feedback||'',req.user.id,req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});

// ── EXAM RESULTS (with batch filter for trainer) ──────────────────────────────
app.get('/api/v1/exam/results', auth, async (req,res)=>{
  try{
    const {batch_id}=req.query;
    let q=`SELECT sea.id, s.name AS student_name, e.name AS exam_name, e.name AS exam_title, c.name AS course_title, b.name AS batch_name, sea.score, sea.max_score, sea.max_score AS max_marks, sea.status, sea.submitted_at FROM student_exam_attempts sea JOIN students s ON sea.student_id=s.id JOIN exams e ON sea.exam_id=e.id LEFT JOIN courses c ON e.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE 1=1`;
    const params=[];
    if(batch_id){params.push(batch_id);q+=` AND s.batch_id=$${params.length}`;}
    q+=' ORDER BY sea.submitted_at DESC';
    ok(res,(await pool.query(q,params)).rows);
  }catch(e){err(res,e.message);}
});

// ── SCORM ENDPOINTS ───────────────────────────────────────────────────────────
const scormDir = path.join(uploadsDir, 'scorm');
if (!fs.existsSync(scormDir)) fs.mkdirSync(scormDir, { recursive: true });
app.use('/uploads/scorm', express.static(scormDir));

const scormUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    ext === '.zip' ? cb(null, true) : cb(new Error('Only ZIP files allowed for SCORM'));
  },
  limits: { fileSize: 100 * 1024 * 1024 }
});

// Upload SCORM package
app.post('/api/v1/scorm/upload', auth, requireRole('admin','trainer'), scormUpload.single('scorm'), async (req, res) => {
  try {
    if (!req.file) return err(res, 'No ZIP file uploaded', 400);
    const { module_id, package_name, scorm_version } = req.body;
    const pkgName = sanitize(package_name || req.file.originalname.replace('.zip',''));
    const version = scorm_version || '1.2';
    // Insert DB record to get ID
    const r = await pool.query(
      'INSERT INTO scorm_packages(module_id,package_name,scorm_version,upload_path) VALUES($1,$2,$3,$4) RETURNING id',
      [module_id || null, pkgName, version, '']
    );
    const pkgId = r.rows[0].id;
    // Extract ZIP into uploads/scorm/{id}/
    const extractPath = path.join(scormDir, String(pkgId));
    extractZip(req.file.buffer, extractPath);
    // Find manifest (imsmanifest.xml)
    function findFile(dir, name) {
      for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
        if (f.isDirectory()) { const found = findFile(path.join(dir,f.name),name); if(found) return found; }
        else if (f.name.toLowerCase() === name) return path.join(dir, f.name);
      }
      return null;
    }
    const manifestPath = findFile(extractPath, 'imsmanifest.xml');
    const relManifest = manifestPath ? path.relative(extractPath, manifestPath).replace(/\\/g,'/') : 'imsmanifest.xml';
    // Find launch URL (index_lms.html or index.html or first .html in manifest dir)
    function findLaunch(dir) {
      const candidates = ['index_lms.html','index_lms.htm','index.html','index.htm','story.html','story_html5.html'];
      for (const c of candidates) {
        if (fs.existsSync(path.join(dir,c))) return c;
      }
      // try manifest dir
      if (manifestPath) {
        const mDir = path.dirname(manifestPath);
        for (const c of candidates) {
          if (fs.existsSync(path.join(mDir,c))) return path.relative(extractPath,path.join(mDir,c)).replace(/\\/g,'/');
        }
      }
      return null;
    }
    const launchUrl = findLaunch(extractPath) || relManifest;
    await pool.query('UPDATE scorm_packages SET manifest_path=$1,upload_path=$2 WHERE id=$3',[relManifest, '/uploads/scorm/'+pkgId+'/'+launchUrl, pkgId]);
    await logAudit(req.user.id, req.user.role, 'SCORM_UPLOAD', 'scorm_packages', pkgId, 'Uploaded SCORM package: '+pkgName, req.ip);
    ok(res, { id:pkgId, package_name:pkgName, launch_url:'/uploads/scorm/'+pkgId+'/'+launchUrl, scorm_version:version }, 'SCORM package uploaded successfully');
  } catch(e) { console.error('SCORM upload error:', e); err(res, e.message); }
});

// List SCORM packages
app.get('/api/v1/scorm/packages', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT sp.*,m.name AS module_name,c.name AS course_name FROM scorm_packages sp LEFT JOIN modules m ON sp.module_id=m.id LEFT JOIN courses c ON m.course_id=c.id ORDER BY sp.created_at DESC`);
    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// Get single package
app.get('/api/v1/scorm/packages/:id', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT sp.*,m.name AS module_name,c.name AS course_name FROM scorm_packages sp LEFT JOIN modules m ON sp.module_id=m.id LEFT JOIN courses c ON m.course_id=c.id WHERE sp.id=$1`,[req.params.id]);
    if (!r.rows[0]) return err(res,'Package not found',404);
    ok(res, r.rows[0]);
  } catch(e) { err(res, e.message); }
});

// Delete SCORM package
app.delete('/api/v1/scorm/packages/:id', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT id FROM scorm_packages WHERE id=$1',[req.params.id]);
    if (!r.rows[0]) return err(res,'Package not found',404);
    // Remove extracted files
    const extractPath = path.join(scormDir, req.params.id);
    if (fs.existsSync(extractPath)) fs.rmSync(extractPath, { recursive: true, force: true });
    await pool.query('DELETE FROM scorm_packages WHERE id=$1',[req.params.id]);
    ok(res, {}, 'Package deleted');
  } catch(e) { err(res, e.message); }
});

// Assign SCORM to module
app.put('/api/v1/scorm/packages/:id/assign', auth, adminOnly, async (req, res) => {
  try {
    const { module_id } = req.body;
    const r = await pool.query('UPDATE scorm_packages SET module_id=$1 WHERE id=$2 RETURNING *',[module_id, req.params.id]);
    ok(res, r.rows[0]);
  } catch(e) { err(res, e.message); }
});

// Get tracking data for current student
app.get('/api/v1/scorm/tracking/:packageId', auth, async (req, res) => {
  try {
    const studentId = req.user.role === 'student' ? req.user.id : (req.query.student_id || req.user.id);
    const r = await pool.query('SELECT * FROM scorm_tracking WHERE student_id=$1 AND package_id=$2',[studentId, req.params.packageId]);
    ok(res, r.rows[0] || { completion_status:'not attempted', score_raw:0, score_max:100, suspend_data:'', total_time:'0000:00:00.00' });
  } catch(e) { err(res, e.message); }
});

// Save tracking data (called by SCORM player on LMSCommit/LMSFinish)
app.post('/api/v1/scorm/tracking', auth, async (req, res) => {
  try {
    const { package_id, completion_status, score_raw, score_max, total_time, suspend_data, lesson_location } = req.body;
    const studentId = req.user.role === 'student' ? req.user.id : (req.body.student_id || req.user.id);
    await pool.query(`INSERT INTO scorm_tracking(student_id,package_id,completion_status,score_raw,score_max,total_time,suspend_data,last_accessed)
      VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
      ON CONFLICT(student_id,package_id) DO UPDATE SET
        completion_status=$3,score_raw=$4,score_max=$5,total_time=$6,suspend_data=$7,last_accessed=NOW()`,
      [studentId, package_id, completion_status||'incomplete', score_raw||0, score_max||100, total_time||'0000:00:00.00', suspend_data||'']);
    // Also update student progress if passed
    if (completion_status === 'passed' || completion_status === 'completed') {
      const pkg = await pool.query('SELECT module_id FROM scorm_packages WHERE id=$1',[package_id]);
      if (pkg.rows[0]?.module_id) {
        await pool.query(`INSERT INTO student_progress(student_id,module_id,completed,completed_at) VALUES($1,$2,TRUE,NOW()) ON CONFLICT(student_id,module_id) DO UPDATE SET completed=TRUE,completed_at=NOW()`,[studentId, pkg.rows[0].module_id]);
      }
    }
    ok(res, {}, 'Tracking saved');
  } catch(e) { err(res, e.message); }
});

// Get all tracking records (admin/trainer view)
app.get('/api/v1/scorm/tracking-all', auth, requireRole('admin','trainer'), async (req, res) => {
  try {
    const { package_id } = req.query;
    let q = `SELECT st.*,s.name AS student_name,sp.package_name FROM scorm_tracking st JOIN students s ON st.student_id=s.id JOIN scorm_packages sp ON st.package_id=sp.id WHERE 1=1`;
    const params = [];
    if (package_id) { params.push(package_id); q += ` AND st.package_id=$${params.length}`; }
    q += ' ORDER BY st.last_accessed DESC';
    ok(res, (await pool.query(q, params)).rows);
  } catch(e) { err(res, e.message); }
});

// ── BSCHOOL PORTAL ENDPOINTS ──────────────────────────────────────────────────
const bschoolRole = requireRole('bschool','admin');

app.get('/api/v1/bschool/stats/students', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='Active' OR status='active' THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN status='Inactive' OR status='inactive' THEN 1 ELSE 0 END) AS inactive FROM students`);
    const d=r.rows[0];
    ok(res,{total:+d.total,active:+d.active,inactive:+d.inactive});
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/stats/batches', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN LOWER(status)='active' THEN 1 ELSE 0 END) AS active, SUM(CASE WHEN LOWER(status)='completed' THEN 1 ELSE 0 END) AS completed FROM batches`);
    const d=r.rows[0];
    ok(res,{total:+d.total,active:+d.active,completed:+d.completed});
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/stats/attendance', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='Present' OR status='present' THEN 1 ELSE 0 END) AS present FROM attendance`);
    const {total,present}=r.rows[0];
    const pct=+total>0?Math.round((+present/+total)*100):0;
    ok(res,{total:+total,present:+present,percentage:pct});
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/stats/exams', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN LOWER(status)='passed' THEN 1 ELSE 0 END) AS passed, COALESCE(AVG(CASE WHEN max_score>0 THEN score::float/max_score*100 END),0) AS avg_pct FROM student_exam_attempts`);
    const {total,passed,avg_pct}=r.rows[0];
    const pass_rate=+total>0?Math.round((+passed/+total)*100):0;
    ok(res,{total:+total,passed:+passed,pass_rate,avg_score:Math.round(+avg_pct||0)});
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/students/top', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT s.id,s.name,s.email,b.name AS batch_name,s.status,
        COALESCE((SELECT ROUND(COUNT(CASE WHEN a.status='Present' THEN 1 END)::numeric/NULLIF(COUNT(*),0)*100) FROM attendance a WHERE a.student_id=s.id),0) AS attendance_pct,
        COALESCE((SELECT ROUND(AVG(sea.score::float/NULLIF(sea.max_score,0)*100)) FROM student_exam_attempts sea WHERE sea.student_id=s.id),0) AS avg_score
      FROM students s LEFT JOIN batches b ON s.batch_id=b.id
      ORDER BY avg_score DESC, attendance_pct DESC LIMIT 10`);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/students', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT s.id,s.name,s.email,s.contact,s.status,s.created_at AS enrolled_at,
        b.id AS batch_id,b.name AS batch_name,c.name AS course_name,
        COALESCE((SELECT ROUND(COUNT(CASE WHEN a.status='Present' THEN 1 END)::numeric/NULLIF(COUNT(*),0)*100) FROM attendance a WHERE a.student_id=s.id),0) AS attendance_pct
      FROM students s LEFT JOIN batches b ON s.batch_id=b.id LEFT JOIN courses c ON s.course_id=c.id
      ORDER BY s.name`);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/batches', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT b.id,b.name,b.start_date,b.end_date,b.status,b.max_students,b.trainer_id,
        c.name AS course_name,t.name AS trainer_name,
        (SELECT COUNT(*) FROM students WHERE batch_id=b.id) AS student_count
      FROM batches b LEFT JOIN courses c ON b.course_id=c.id LEFT JOIN trainers t ON b.trainer_id=t.id
      ORDER BY b.start_date DESC`);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/analytics', auth, bschoolRole, async (req,res)=>{
  try{
    const attR=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN status='Present' THEN 1 ELSE 0 END) AS present FROM attendance`);
    const examR=await pool.query(`SELECT COUNT(*) AS total, SUM(CASE WHEN LOWER(status)='passed' THEN 1 ELSE 0 END) AS passed, COALESCE(AVG(CASE WHEN max_score>0 THEN score::float/max_score*100 END),0) AS avg_pct FROM student_exam_attempts`);
    const {total:at,present:ap}=attR.rows[0];
    const {total:et,passed:ep,avg_pct}=examR.rows[0];
    const att_rate=+at>0?Math.round((+ap/+at)*100):0;
    const pass_rate=+et>0?Math.round((+ep/+et)*100):0;
    ok(res,{attendance_rate:att_rate,pass_rate,avg_score:Math.round(+avg_pct||0)});
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/bschool/batches/summary', auth, bschoolRole, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT b.id,b.name,b.status,c.name AS course_name,
        (SELECT COUNT(*) FROM students WHERE batch_id=b.id) AS student_count,
        COALESCE((SELECT ROUND(COUNT(CASE WHEN a.status='Present' THEN 1 END)::numeric/NULLIF(COUNT(*),0)*100) FROM attendance a WHERE a.batch_id=b.id),0) AS attendance_pct,
        COALESCE((SELECT ROUND(AVG(sea.score::float/NULLIF(sea.max_score,0)*100)) FROM student_exam_attempts sea JOIN students s ON sea.student_id=s.id WHERE s.batch_id=b.id),0) AS avg_score,
        COALESCE((SELECT ROUND(COUNT(CASE WHEN LOWER(sea.status)='passed' THEN 1 END)::numeric/NULLIF(COUNT(*),0)*100) FROM student_exam_attempts sea JOIN students s ON sea.student_id=s.id WHERE s.batch_id=b.id),0) AS pass_rate
      FROM batches b LEFT JOIN courses c ON b.course_id=c.id
      ORDER BY b.start_date DESC`);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// POST alias for mark-all-read (bschool dashboard uses POST)
app.post('/api/v1/notifications/mark-all-read', auth, async (req,res)=>{ try{ await pool.query('UPDATE notifications SET is_read=TRUE WHERE user_id=$1 AND role=$2 AND is_read=FALSE',[req.user.id,req.user.role]); ok(res,{},'All notifications marked as read'); }catch(e){err(res,e.message);}});

// ── BACKWARD COMPAT (old API prefix) ─────────────────────────────────────────
app.use('/api/', (req,res,next)=>{
  req.url = '/v1' + req.url;
  next();
});

// ── ERROR HANDLER ─────────────────────────────────────────────────────────────
app.use((error, req, res, next) => {
  console.error(error);
  err(res, error.message || 'Internal server error');
});

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ Smart LMS running on http://localhost:${PORT}`));
});
