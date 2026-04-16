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
// Serve HTML files with no-cache so browser always gets latest version
// Also add proper headers for video streaming inside SCORM packages
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (p.endsWith('.html') || p === '/') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  // SCORM content needs these headers to allow iframe embedding and video playback
  if (p.includes('/uploads/scorm/')) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    // Set correct MIME type for video files
    if (p.endsWith('.mp4'))  res.setHeader('Content-Type', 'video/mp4');
    if (p.endsWith('.webm')) res.setHeader('Content-Type', 'video/webm');
    if (p.endsWith('.mov'))  res.setHeader('Content-Type', 'video/quicktime');
    if (p.endsWith('.m4v'))  res.setHeader('Content-Type', 'video/mp4');
    if (p.endsWith('.ogg'))  res.setHeader('Content-Type', 'video/ogg');
    if (p.endsWith('.ogv'))  res.setHeader('Content-Type', 'video/ogg');
  }
  next();
});

// Static file serving with proper options for video streaming (range requests)
const staticOptions = {
  etag: false,
  lastModified: false,
  setHeaders: (res, filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    // No-cache for HTML files so changes reflect immediately
    if (ext === '.html') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
    }
    // Allow range requests for video files (needed for seek/scrub)
    if (['.mp4','.webm','.mov','.m4v','.ogg','.ogv'].includes(ext)) {
      res.setHeader('Accept-Ranges', 'bytes');
    }
  }
};
app.use(express.static(path.join(__dirname, '..'), staticOptions));

// Serve uploads with video streaming support
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir, staticOptions));

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
        status VARCHAR(50) DEFAULT 'Active', created_at TIMESTAMP DEFAULT NOW(),
        price NUMERIC(10,2) DEFAULT 0,
        demo_video_path VARCHAR(500),
        certificate_validity_days INTEGER DEFAULT 0,
        linked_trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        avg_rating NUMERIC(3,2) DEFAULT 0,
        has_chapters BOOLEAN DEFAULT TRUE,
        has_assignments BOOLEAN DEFAULT FALSE
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
        time_spent_seconds INTEGER DEFAULT 0, last_accessed TIMESTAMP,
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
        scorm_version VARCHAR(20) DEFAULT '1.2', upload_path VARCHAR(500), created_at TIMESTAMP DEFAULT NOW(),
        content_type VARCHAR(20) DEFAULT 'scorm'
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

    // ── NEW TABLES (safe additions) ───────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS course_ratings (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        rating INTEGER CHECK(rating BETWEEN 1 AND 5),
        review TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(course_id, student_id)
      );
      CREATE TABLE IF NOT EXISTS student_queries (
        id SERIAL PRIMARY KEY,
        student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL,
        course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
        question TEXT NOT NULL,
        answer TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        answered_at TIMESTAMP
      );
      ALTER TABLE student_queries ADD COLUMN IF NOT EXISTS target_role VARCHAR(20) DEFAULT 'trainer';
      CREATE TABLE IF NOT EXISTS course_purchases (
        id SERIAL PRIMARY KEY,
        student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        amount NUMERIC(10,2) DEFAULT 0,
        payment_source VARCHAR(50) DEFAULT 'lms',
        payment_ref VARCHAR(255),
        purchased_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(student_id, course_id)
      );
      CREATE TABLE IF NOT EXISTS corporate_clients (
        id SERIAL PRIMARY KEY,
        company_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        plain_password VARCHAR(255),
        contact VARCHAR(50),
        address TEXT,
        status VARCHAR(50) DEFAULT 'Active',
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS corporate_allowed_courses (
        id SERIAL PRIMARY KEY,
        corporate_id INTEGER REFERENCES corporate_clients(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        UNIQUE(corporate_id, course_id)
      );
      CREATE TABLE IF NOT EXISTS corporate_participants (
        id SERIAL PRIMARY KEY,
        corporate_id INTEGER REFERENCES corporate_clients(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        otp_password VARCHAR(255),
        contact VARCHAR(50),
        status VARCHAR(50) DEFAULT 'Pending',
        first_login BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS corporate_course_assignments (
        id SERIAL PRIMARY KEY,
        participant_id INTEGER REFERENCES corporate_participants(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        assigned_by INTEGER REFERENCES corporate_clients(id),
        assigned_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(participant_id, course_id)
      );
      CREATE TABLE IF NOT EXISTS participant_progress (
        id SERIAL PRIMARY KEY,
        participant_id INTEGER REFERENCES corporate_participants(id) ON DELETE CASCADE,
        module_id INTEGER REFERENCES modules(id) ON DELETE CASCADE,
        completed BOOLEAN DEFAULT FALSE, completed_at TIMESTAMP,
        time_spent_seconds INTEGER DEFAULT 0, last_accessed TIMESTAMP,
        UNIQUE(participant_id, module_id)
      );
    `);
    // Add content_type column for existing databases (safe migration)
    await client.query(`ALTER TABLE scorm_packages ADD COLUMN IF NOT EXISTS content_type VARCHAR(20) DEFAULT 'scorm'`).catch(()=>{});
    // Safe column migrations for courses table
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS price NUMERIC(10,2) DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS thumbnail VARCHAR(500)`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS demo_video_path VARCHAR(500)`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS certificate_validity_days INTEGER DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS linked_trainer_id INTEGER REFERENCES trainers(id) ON DELETE SET NULL`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS avg_rating NUMERIC(3,2) DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS has_chapters BOOLEAN DEFAULT TRUE`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS has_assignments BOOLEAN DEFAULT FALSE`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS intro_video VARCHAR(500)`).catch(()=>{});
    await client.query(`ALTER TABLE corporate_clients ADD COLUMN IF NOT EXISTS group_name VARCHAR(255) DEFAULT ''`).catch(()=>{});
    // Course content (video/SCORM) linked directly to course for progress tracking
    await client.query(`CREATE TABLE IF NOT EXISTS course_content (
      id SERIAL PRIMARY KEY,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      module_id INTEGER REFERENCES modules(id) ON DELETE SET NULL,
      content_type VARCHAR(20) DEFAULT 'video',
      file_path VARCHAR(500),
      file_name VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    )`).catch(()=>{});
    await client.query(`ALTER TABLE trainers ADD COLUMN IF NOT EXISTS bio TEXT`).catch(()=>{});
    await client.query(`ALTER TABLE trainers ADD COLUMN IF NOT EXISTS profile_photo VARCHAR(500)`).catch(()=>{});
    await client.query(`ALTER TABLE student_progress ADD COLUMN IF NOT EXISTS time_spent_seconds INTEGER DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE corporate_clients ADD COLUMN IF NOT EXISTS plain_password VARCHAR(255)`).catch(()=>{});
    await client.query(`ALTER TABLE corporate_clients ADD COLUMN IF NOT EXISTS group_name VARCHAR(100)`).catch(()=>{});
    await client.query(`ALTER TABLE corporate_clients ADD COLUMN IF NOT EXISTS logo_path VARCHAR(500) DEFAULT ''`).catch(()=>{});
    await client.query(`CREATE TABLE IF NOT EXISTS corporate_allowed_courses (id SERIAL PRIMARY KEY, corporate_id INTEGER REFERENCES corporate_clients(id) ON DELETE CASCADE, course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE, UNIQUE(corporate_id,course_id))`).catch(()=>{});
    await client.query(`ALTER TABLE student_progress ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMP`).catch(()=>{});
    // Safe column migrations for modules table
    await client.query(`ALTER TABLE modules ADD COLUMN IF NOT EXISTS order_no INTEGER DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE modules ADD COLUMN IF NOT EXISTS duration VARCHAR(100)`).catch(()=>{});
    // Add participant_id to scorm_tracking so participants can have SCORM progress tracked separately from students
    await client.query(`ALTER TABLE scorm_tracking ADD COLUMN IF NOT EXISTS participant_id INTEGER REFERENCES corporate_participants(id) ON DELETE CASCADE`).catch(()=>{});
    // Partial unique index for participant tracking (allows multiple NULL student_id rows per package)
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_scorm_tracking_participant ON scorm_tracking(participant_id, package_id) WHERE participant_id IS NOT NULL`).catch(()=>{});

    // ── NEW: Course type, passing criteria columns ────────────────────────────
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS course_type VARCHAR(30) DEFAULT 'standard'`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS passing_marks INTEGER DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS passing_percentage INTEGER DEFAULT 0`).catch(()=>{});
    await client.query(`ALTER TABLE courses ADD COLUMN IF NOT EXISTS requires_pass BOOLEAN DEFAULT FALSE`).catch(()=>{});

    // ── NEW: Participant quiz attempts table ──────────────────────────────────
    await client.query(`CREATE TABLE IF NOT EXISTS participant_quiz_attempts (
      id SERIAL PRIMARY KEY,
      participant_id INTEGER REFERENCES corporate_participants(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      passed BOOLEAN DEFAULT FALSE,
      answers JSONB,
      attempted_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(participant_id, course_id)
    )`).catch(()=>{});

    // ── NEW: Participant certificates table ───────────────────────────────────
    await client.query(`CREATE TABLE IF NOT EXISTS participant_certificates (
      id SERIAL PRIMARY KEY,
      participant_id INTEGER REFERENCES corporate_participants(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      corporate_id INTEGER REFERENCES corporate_clients(id) ON DELETE SET NULL,
      issued_date DATE DEFAULT CURRENT_DATE,
      certificate_no VARCHAR(100) UNIQUE,
      status VARCHAR(50) DEFAULT 'Issued',
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(participant_id, course_id)
    )`).catch(()=>{});

    // ── Certificate Templates ─────────────────────────────────────────────────
    await client.query(`CREATE TABLE IF NOT EXISTS certificate_templates (
      id SERIAL PRIMARY KEY,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE UNIQUE,
      cert_title VARCHAR(255) DEFAULT 'Certificate of Completion',
      cert_subtitle VARCHAR(255) DEFAULT 'This is to certify that',
      body_text TEXT DEFAULT 'has successfully completed the course',
      signatory_name VARCHAR(255) DEFAULT '',
      signatory_title VARCHAR(255) DEFAULT '',
      footer_text VARCHAR(500) DEFAULT '',
      accent_color VARCHAR(20) DEFAULT '#1a237e',
      org_name VARCHAR(255) DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    )`).catch(()=>{});

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
    else if (role==='corporate') user = (await pool.query('SELECT * FROM corporate_clients WHERE email=$1',[clean])).rows[0];
    else if (role==='participant') user = (await pool.query('SELECT * FROM corporate_participants WHERE email=$1',[clean])).rows[0];
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
  const { name, email, password, contact, phone, course_id, batch_id, role, specialization, expertise } = req.body;
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
        'INSERT INTO students(name,email,password_hash,contact,course_id,batch_id,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,email,status',
        [sanitize(name),sanitize(email.toLowerCase()),hash,contactVal,course_id||null,batch_id||null,'Pending']
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

// ── CORPORATE LOGO UPLOAD ──────────────────────────────────────────────────────
app.post('/api/v1/corporate/settings/logo', auth, requireRole('corporate','admin'), (req, res) => {
  req.uploadFolder = 'logos';
  upload.single('logo')(req, res, async (uploadErr) => {
    if (uploadErr) return err(res, uploadErr.message, 400);
    if (!req.file) return err(res,'No file uploaded',400);
    const logoPath = '/uploads/logos/' + req.file.filename;
    const corpId = req.user.role === 'corporate' ? req.user.id : req.body.corporate_id;
    await pool.query('UPDATE corporate_clients SET logo_path=$1 WHERE id=$2',[logoPath, corpId]);
    ok(res, { logo_path: logoPath });
  });
});

// ── BRANDING (logos for certificate rendering) ─────────────────────────────────
app.get('/api/v1/branding', auth, async (req, res) => {
  try {
    const ss = await pool.query('SELECT logo_path FROM site_settings WHERE id=1');
    const superLogo = ss.rows[0]?.logo_path || '';
    let corpLogo = '';
    if (req.user.role === 'participant') {
      const r = await pool.query(
        'SELECT cc.logo_path FROM corporate_participants cp JOIN corporate_clients cc ON cp.corporate_id=cc.id WHERE cp.id=$1',
        [req.user.id]
      );
      corpLogo = r.rows[0]?.logo_path || '';
    } else if (req.user.role === 'corporate') {
      const r = await pool.query('SELECT logo_path FROM corporate_clients WHERE id=$1',[req.user.id]);
      corpLogo = r.rows[0]?.logo_path || '';
    }
    ok(res, { super_logo: superLogo, corp_logo: corpLogo });
  } catch(e){ err(res, e.message); }
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

// ── LMS → Connectingdot WEBHOOK HELPER ───────────────────────────────────────
async function notifyConnectingdot(event, courseData) {
  const webhookUrl = process.env.CONNECTINGDOT_WEBHOOK_URL;
  const secret     = process.env.LMS_WEBHOOK_SECRET || 'cdpl-lms-secret-2024';
  if (!webhookUrl) return; // skip if not configured
  try {
    const https = require('https');
    const http  = require('http');
    const body  = JSON.stringify({ event, secret, course: courseData });
    const url   = new URL(webhookUrl);
    const lib   = url.protocol === 'https:' ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    };
    await new Promise((resolve) => {
      const req = lib.request(options, (res) => { res.resume(); res.on('end', resolve); });
      req.on('error', (e) => { console.warn('[LMS Webhook] Failed to notify Connectingdot:', e.message); resolve(); });
      req.write(body);
      req.end();
    });
    console.log(`[LMS Webhook] Notified Connectingdot: event=${event}, course_id=${courseData.id}`);
  } catch(e) {
    console.warn('[LMS Webhook] Error:', e.message);
  }
}

// ── PUBLIC endpoint (no auth) — used by Connectingdot to fetch all courses ────
app.get('/api/v1/public/courses', async (req,res)=>{
  try {
    const secret = req.headers['x-lms-secret'] || req.query.secret;
    const expectedSecret = process.env.LMS_WEBHOOK_SECRET || 'cdpl-lms-secret-2024';
    if (secret !== expectedSecret) return err(res, 'Unauthorized', 401);
    const r = await pool.query(`SELECT c.id, c.name, cat.name AS category, c.duration, c.description, c.status FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id WHERE c.status='Active' ORDER BY c.id`);
    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// Courses
app.get('/api/v1/courses', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT c.id, c.name, c.name AS title, cat.name AS category, cat.name AS category_name, c.duration, c.description, c.status, c.price, c.demo_video_path, c.intro_video, c.certificate_validity_days, c.avg_rating, c.has_chapters, c.has_assignments, c.linked_trainer_id, c.course_type, c.passing_marks, c.passing_percentage, c.requires_pass, t.name AS trainer_name, t.expertise AS trainer_expertise, t.bio AS trainer_bio, t.profile_photo AS trainer_photo, (SELECT COUNT(*) FROM students WHERE course_id=c.id) AS student_count FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id LEFT JOIN trainers t ON c.linked_trainer_id=t.id ORDER BY c.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/courses', auth, adminOnly, async (req,res)=>{ try{ const courseName=sanitize(req.body.name||req.body.title||''); if(!courseName) return err(res,'Course name is required',400); const {category,duration,status,description,price,demo_video_path,certificate_validity_days,linked_trainer_id,has_chapters,has_assignments,course_type,passing_marks,passing_percentage,requires_pass}=req.body; const catR=await pool.query('SELECT id FROM categories WHERE LOWER(name)=LOWER($1)',[category||'']); const catId=catR.rows[0]?.id||null; const r=await pool.query('INSERT INTO courses(name,category_id,duration,status,description,price,demo_video_path,certificate_validity_days,linked_trainer_id,has_chapters,has_assignments,course_type,passing_marks,passing_percentage,requires_pass) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id',[courseName,catId,duration||'—',status||'Active',description||'',price||0,demo_video_path||null,certificate_validity_days||0,linked_trainer_id||null,has_chapters!==false,has_assignments===true,course_type||'standard',parseInt(passing_marks)||0,parseInt(passing_percentage)||0,requires_pass===true||requires_pass==='true']); const full=await pool.query('SELECT c.id,c.name,cat.name AS category,c.duration,c.description,c.status,c.price,c.demo_video_path,c.certificate_validity_days,c.avg_rating,c.has_chapters,c.has_assignments,c.course_type,c.passing_marks,c.passing_percentage,c.requires_pass FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id WHERE c.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); notifyConnectingdot('course_created', full.rows[0]).catch(()=>{}); }catch(e){err(res,e.message);}});
app.put('/api/v1/courses/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,category,duration,status,description,price,certificate_validity_days,demo_video_path}=req.body; const catR=await pool.query('SELECT id FROM categories WHERE LOWER(name)=LOWER($1)',[category||'']); const catId=catR.rows[0]?.id||null; const r=await pool.query('UPDATE courses SET name=$1,category_id=$2,duration=$3,status=$4,description=$5,price=$6,certificate_validity_days=$7,demo_video_path=$8 WHERE id=$9 RETURNING id',[sanitize(name),catId,duration||'',status||'Active',description||'',price||0,certificate_validity_days||0,demo_video_path||null,req.params.id]); const full=await pool.query('SELECT c.id,c.name,cat.name AS category_name,c.duration,c.description,c.status,c.price,c.certificate_validity_days,c.demo_video_path,c.avg_rating FROM courses c LEFT JOIN categories cat ON c.category_id=cat.id WHERE c.id=$1',[r.rows[0].id]); ok(res,full.rows[0]); notifyConnectingdot('course_updated', full.rows[0]).catch(()=>{}); }catch(e){err(res,e.message);}});
app.delete('/api/v1/courses/:id', auth, adminOnly, async (req,res)=>{ try{ const before=await pool.query('SELECT id FROM courses WHERE id=$1',[req.params.id]); await pool.query('DELETE FROM courses WHERE id=$1',[req.params.id]); ok(res,{}); if(before.rows[0]) notifyConnectingdot('course_deleted', {id: parseInt(req.params.id)}).catch(()=>{}); }catch(e){err(res,e.message);}});

// Modules
app.get('/api/v1/modules', auth, async (req,res)=>{ try{ const {course_id}=req.query; let q=`SELECT m.id,m.name,c.name AS course,m.duration,m.order_no,m.course_id FROM modules m LEFT JOIN courses c ON m.course_id=c.id WHERE 1=1`; const params=[]; if(course_id){params.push(course_id);q+=` AND m.course_id=$${params.length}`;} q+=' ORDER BY m.course_id,m.order_no'; const r=await pool.query(q,params); ok(res,r.rows); }catch(e){err(res,e.message);}});
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
app.get('/api/v1/trainers', auth, async (req,res)=>{ try{ const r=await pool.query(`SELECT t.id,t.name,t.email,t.contact,t.expertise,t.bio,t.status,t.profile_photo,t.created_at, COALESCE((SELECT string_agg(DISTINCT c.name,', ' ORDER BY c.name) FROM batches b JOIN courses c ON b.course_id=c.id WHERE b.trainer_id=t.id),'') AS courses FROM trainers t ORDER BY t.id`); ok(res,r.rows); }catch(e){err(res,e.message);}});
app.post('/api/v1/trainers', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,expertise,bio,status,password}=req.body; const hash=await bcrypt.hash(password||'trainer@123',12); const r=await pool.query('INSERT INTO trainers(name,email,password_hash,contact,expertise,bio,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,email,contact,expertise,bio,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contact||'',expertise||'',bio||'',status||'Active']); ok(res,r.rows[0]); }catch(e){ if(e.code==='23505')return err(res,'Email already exists',409); err(res,e.message);}});
app.put('/api/v1/trainers/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,expertise,bio,status}=req.body; const r=await pool.query('UPDATE trainers SET name=$1,email=$2,contact=$3,expertise=$4,bio=$5,status=$6 WHERE id=$7 RETURNING id,name,email,contact,expertise,bio,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',expertise||'',bio||'',status,req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
// Patch only bio + expertise (safe — doesn't touch email/contact/password)
app.patch('/api/v1/trainers/:id/bio', auth, adminOnly, async (req,res)=>{ try{ const {bio,expertise}=req.body; const r=await pool.query('UPDATE trainers SET bio=$1,expertise=COALESCE(NULLIF($2,\'\'),expertise) WHERE id=$3 RETURNING id,name,expertise,bio,status',[bio||'',expertise||'',req.params.id]); ok(res,r.rows[0],'Bio updated'); }catch(e){err(res,e.message);}});
app.delete('/api/v1/trainers/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM trainers WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});

// Students
app.get('/api/v1/students', auth, staffOnly, async (req,res)=>{ try{ const {page=1,limit=50,search='',status='',batch_id='',trainer=''}=req.query; const offset=(page-1)*limit; let q=`SELECT s.id,s.name,s.email,s.contact AS phone,s.contact,c.name AS course,c.name AS course_title,b.name AS batch,b.name AS batch_name,b.id AS batch_id,s.status,s.created_at,0 AS progress FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE 1=1`; const params=[]; if(search){params.push('%'+sanitize(search)+'%');q+=` AND (s.name ILIKE $${params.length} OR s.email ILIKE $${params.length})`;} if(status){params.push(status);q+=` AND s.status=$${params.length}`;} if(batch_id){params.push(batch_id);q+=` AND s.batch_id=$${params.length}`;} if(trainer==='me' && req.user.role==='trainer'){params.push(req.user.id);q+=` AND b.trainer_id=$${params.length}`;} q+=` ORDER BY s.id DESC LIMIT ${parseInt(limit)} OFFSET ${offset}`; const r=await pool.query(q,params); const cnt=await pool.query('SELECT COUNT(*) FROM students'); ok(res,{students:r.rows,rows:r.rows,total:+cnt.rows[0].count,page:+page,limit:+limit}); }catch(e){err(res,e.message);}});
app.post('/api/v1/students', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,course,batch,status,password}=req.body; const hash=await bcrypt.hash(password||'student@123',12); const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const batR=await pool.query('SELECT id FROM batches WHERE name=$1',[batch]); const crsId=crsR.rows[0]?.id||null; const batId=batR.rows[0]?.id||null; const r=await pool.query('INSERT INTO students(name,email,password_hash,contact,course_id,batch_id,status) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),hash,contact||'',crsId,batId,status||'Active']); ok(res,r.rows[0]); }catch(e){ if(e.code==='23505')return err(res,'Email already exists',409); err(res,e.message);}});
app.put('/api/v1/students/:id', auth, adminOnly, async (req,res)=>{ try{ const {name,email,contact,course,batch,status}=req.body; const crsR=await pool.query('SELECT id FROM courses WHERE name=$1',[course]); const batR=await pool.query('SELECT id FROM batches WHERE name=$1',[batch]); const crsId=crsR.rows[0]?.id||null; const batId=batR.rows[0]?.id||null; const r=await pool.query('UPDATE students SET name=$1,email=$2,contact=$3,course_id=$4,batch_id=$5,status=$6 WHERE id=$7 RETURNING id,name,email,contact,status',[sanitize(name),sanitize(email.toLowerCase()),contact||'',crsId,batId,status,req.params.id]); ok(res,r.rows[0]); }catch(e){err(res,e.message);}});
app.delete('/api/v1/students/:id', auth, adminOnly, async (req,res)=>{ try{ await pool.query('DELETE FROM students WHERE id=$1',[req.params.id]); ok(res,{}); }catch(e){err(res,e.message);}});
app.put('/api/v1/students/:id/approve', auth, adminOnly, async (req,res)=>{ try{ await pool.query("UPDATE students SET status='Active' WHERE id=$1",[req.params.id]); const s=await pool.query('SELECT name,email FROM students WHERE id=$1',[req.params.id]); if(s.rows[0]) await sendEmail(s.rows[0].email,'Registration Approved - Smart LMS',`<h2>Congratulations ${s.rows[0].name}!</h2><p>Your registration has been approved. You can now log in to the LMS.</p><p>Login: <a href="#">Smart LMS</a></p><small>Connecting Dot Consultancy Pvt. Ltd.</small>`); ok(res,{},'Student approved'); }catch(e){err(res,e.message);}});

// ── ME / PROFILE ──────────────────────────────────────────────────────────────
app.get('/api/v1/me', auth, async (req,res)=>{ try{ const {id,role}=req.user; let row; if(role==='admin') row=(await pool.query('SELECT id,username AS name,username AS email FROM admins WHERE id=$1',[id])).rows[0]; else if(role==='bschool') row=(await pool.query('SELECT id,name,email,contact,address,status FROM bschools WHERE id=$1',[id])).rows[0]; else if(role==='trainer') row=(await pool.query('SELECT id,name,email,contact,expertise,bio,status,profile_photo FROM trainers WHERE id=$1',[id])).rows[0]; else { const r=await pool.query(`SELECT s.id,s.name,s.email,s.contact,s.status,c.name AS course,b.name AS batch,s.course_id,s.batch_id,s.profile_photo FROM students s LEFT JOIN courses c ON s.course_id=c.id LEFT JOIN batches b ON s.batch_id=b.id WHERE s.id=$1`,[id]); row=r.rows[0]; } ok(res,row||{}); }catch(e){err(res,e.message);}});
app.put('/api/v1/me', auth, async (req,res)=>{ try{ const {id,role}=req.user; const {name,email,contact,expertise,address,bio}=req.body; if(role==='trainer'){ const cur=await pool.query('SELECT email FROM trainers WHERE id=$1',[id]); const safeEmail=email?sanitize(email.toLowerCase()):cur.rows[0]?.email||''; const r=await pool.query('UPDATE trainers SET name=$1,email=$2,contact=$3,expertise=$4,bio=$5 WHERE id=$6 RETURNING id,name,email,contact,expertise,bio,status',[sanitize(name||''),safeEmail,contact||'',expertise||'',bio||'',id]); ok(res,r.rows[0]);} else if(role==='bschool'){ const cur=await pool.query('SELECT email FROM bschools WHERE id=$1',[id]); const safeEmail=email?sanitize(email.toLowerCase()):cur.rows[0]?.email||''; const r=await pool.query('UPDATE bschools SET name=$1,email=$2,contact=$3,address=$4 WHERE id=$5 RETURNING id,name,email,contact,address,status',[sanitize(name||''),safeEmail,contact||'',address||'',id]); ok(res,r.rows[0]);} else if(role==='student'){ const cur=await pool.query('SELECT email FROM students WHERE id=$1',[id]); const safeEmail=email?sanitize(email.toLowerCase()):cur.rows[0]?.email||''; const r=await pool.query('UPDATE students SET name=$1,email=$2,contact=$3 WHERE id=$4 RETURNING id,name,email,contact,status',[sanitize(name||''),safeEmail,contact||'',id]); ok(res,r.rows[0]);} else ok(res,{}); }catch(e){err(res,e.message);}});

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

// ── PARTICIPANT CERTIFICATES LIST (Admin) ────────────────────────────────────
app.get('/api/v1/participant-certificates', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT pc.*, cp.name AS participant_name, cp.email AS participant_email,
             c.name AS course_name, co.name AS corporate_name
      FROM participant_certificates pc
      JOIN corporate_participants cp ON pc.participant_id=cp.id
      JOIN courses c ON pc.course_id=c.id
      LEFT JOIN corporate_clients co ON pc.corporate_id=co.id
      ORDER BY pc.created_at DESC
    `);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ── CERTIFICATE TEMPLATES (Admin) ────────────────────────────────────────────
app.get('/api/v1/certificate-templates', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT ct.*, c.name AS course_name FROM certificate_templates ct
      JOIN courses c ON ct.course_id=c.id ORDER BY ct.created_at DESC
    `);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

app.post('/api/v1/certificate-templates', auth, adminOnly, async (req,res)=>{
  try{
    const {course_id,cert_title,cert_subtitle,body_text,signatory_name,signatory_title,footer_text,accent_color,org_name}=req.body;
    if(!course_id) return err(res,'course_id required',400);
    const r=await pool.query(`
      INSERT INTO certificate_templates(course_id,cert_title,cert_subtitle,body_text,signatory_name,signatory_title,footer_text,accent_color,org_name)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT(course_id) DO UPDATE SET
        cert_title=$2,cert_subtitle=$3,body_text=$4,signatory_name=$5,
        signatory_title=$6,footer_text=$7,accent_color=$8,org_name=$9,created_at=NOW()
      RETURNING *
    `,[course_id,cert_title||'Certificate of Completion',cert_subtitle||'This is to certify that',
       body_text||'has successfully completed the course',signatory_name||'',
       signatory_title||'',footer_text||'',accent_color||'#1a237e',org_name||'']);
    ok(res,r.rows[0]);
  }catch(e){err(res,e.message);}
});

app.delete('/api/v1/certificate-templates/:courseId', auth, adminOnly, async (req,res)=>{
  try{
    await pool.query('DELETE FROM certificate_templates WHERE course_id=$1',[req.params.courseId]);
    ok(res,{deleted:true});
  }catch(e){err(res,e.message);}
});

// ── PARTICIPANT: VIEW CERTIFICATE ────────────────────────────────────────────
app.get('/api/v1/participant/certificate/view/:certNo', auth, requireRole('participant','corporate','admin'), async (req,res)=>{
  try{
    const {certNo}=req.params;
    const r=await pool.query(`
      SELECT pc.*, cp.name AS participant_name, c.name AS course_name,
             co.name AS corporate_name,
             COALESCE(ct.cert_title,'Certificate of Completion') AS cert_title,
             COALESCE(ct.cert_subtitle,'This is to certify that') AS cert_subtitle,
             COALESCE(ct.body_text,'has successfully completed the course') AS body_text,
             COALESCE(ct.signatory_name,'') AS signatory_name,
             COALESCE(ct.signatory_title,'') AS signatory_title,
             COALESCE(ct.footer_text,'') AS footer_text,
             COALESCE(ct.accent_color,'#1a237e') AS accent_color,
             COALESCE(ct.org_name,'') AS org_name
      FROM participant_certificates pc
      JOIN corporate_participants cp ON pc.participant_id=cp.id
      JOIN courses c ON pc.course_id=c.id
      LEFT JOIN corporate_clients co ON pc.corporate_id=co.id
      LEFT JOIN certificate_templates ct ON ct.course_id=pc.course_id
      WHERE pc.certificate_no=$1
    `,[certNo]);
    if(!r.rows[0]) return err(res,'Certificate not found',404);
    // Allow access: participant owner, corporate admin of same corp, or admin
    const cert=r.rows[0];
    const user=req.user;
    if(user.role==='participant' && cert.participant_id!==user.id) return err(res,'Access denied',403);
    ok(res,cert);
  }catch(e){err(res,e.message);}
});

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

// ═══════════════════════════════════════════════════════════════
// COURSE CATALOG (public/student) + PRICING
// ═══════════════════════════════════════════════════════════════
app.get('/api/v1/catalog', async (req,res)=>{
  try{
    // Check if request has a corporate token — if so, filter by allowed courses
    let corpId=null;
    const authHeader=req.headers.authorization;
    if(authHeader&&authHeader.startsWith('Bearer ')){
      try{
        const decoded=jwt.verify(authHeader.split(' ')[1],JWT_SECRET);
        if(decoded.role==='corporate') corpId=decoded.id;
      }catch(e){}
    }
    let query;
    if(corpId){
      // Check if any allowed courses exist for this corporate
      const allowed=await pool.query('SELECT course_id FROM corporate_allowed_courses WHERE corporate_id=$1',[corpId]);
      if(allowed.rows.length>0){
        const ids=allowed.rows.map(r=>r.course_id);
        query=await pool.query(`
          SELECT c.id,c.name,c.description,c.duration,c.thumbnail,c.status,c.price,
                 c.demo_video_path,c.intro_video,c.certificate_validity_days,c.avg_rating,c.has_chapters,c.has_assignments,
                 cat.name AS category_name, t.name AS trainer_name, t.expertise AS trainer_expertise, t.bio AS trainer_bio, t.profile_photo AS trainer_photo,
                 (SELECT COUNT(*) FROM course_ratings WHERE course_id=c.id) AS rating_count
          FROM courses c
          LEFT JOIN categories cat ON c.category_id=cat.id
          LEFT JOIN trainers t ON c.linked_trainer_id=t.id
          WHERE c.status='Active' AND c.id=ANY($1)
          ORDER BY c.created_at DESC
        `,[ids]);
      } else {
        // No allowed courses set — return empty (admin has not allowed any courses yet)
        return ok(res,[]);
      }
    } else {
      query=await pool.query(`
        SELECT c.id,c.name,c.description,c.duration,c.thumbnail,c.status,c.price,
               c.demo_video_path,c.intro_video,c.certificate_validity_days,c.avg_rating,c.has_chapters,c.has_assignments,
               cat.name AS category_name, t.name AS trainer_name, t.expertise AS trainer_expertise, t.profile_photo AS trainer_photo,
               (SELECT COUNT(*) FROM course_ratings WHERE course_id=c.id) AS rating_count
        FROM courses c
        LEFT JOIN categories cat ON c.category_id=cat.id
        LEFT JOIN trainers t ON c.linked_trainer_id=t.id
        WHERE c.status='Active'
        ORDER BY c.created_at DESC
      `);
    }
    ok(res,query.rows);
  }catch(e){err(res,e.message);}
});

// Rate a course (student)
app.post('/api/v1/courses/:id/rate', auth, studentOnly, async (req,res)=>{
  try{
    const {rating,review}=req.body;
    if(!rating||rating<1||rating>5) return err(res,'Rating must be 1-5',400);
    await pool.query(`INSERT INTO course_ratings(course_id,student_id,rating,review) VALUES($1,$2,$3,$4) ON CONFLICT(course_id,student_id) DO UPDATE SET rating=$3,review=$4,created_at=NOW()`,
      [req.params.id,req.user.id,rating,review||'']);
    // Recalculate avg
    await pool.query(`UPDATE courses SET avg_rating=(SELECT COALESCE(AVG(rating),0) FROM course_ratings WHERE course_id=$1) WHERE id=$1`,[req.params.id]);
    ok(res,{},'Rating submitted');
  }catch(e){err(res,e.message);}
});

// Purchase a course (student buys directly in LMS)
app.post('/api/v1/courses/:id/purchase', auth, studentOnly, async (req,res)=>{
  try{
    const {payment_ref,payment_source}=req.body;
    const course=await pool.query('SELECT id,price FROM courses WHERE id=$1',[req.params.id]);
    if(!course.rows[0]) return err(res,'Course not found',404);
    // Check already purchased or assigned
    const existing=await pool.query('SELECT id FROM course_purchases WHERE student_id=$1 AND course_id=$2',[req.user.id,req.params.id]);
    if(existing.rows[0]) return err(res,'Course already purchased',409);
    await pool.query('INSERT INTO course_purchases(student_id,course_id,amount,payment_source,payment_ref) VALUES($1,$2,$3,$4,$5)',
      [req.user.id,req.params.id,course.rows[0].price,payment_source||'lms',payment_ref||'']);
    // Auto-assign course to student if not already set
    await pool.query('UPDATE students SET course_id=$1 WHERE id=$2 AND course_id IS NULL',[req.params.id,req.user.id]);
    await notify(req.user.id,'student',`You have enrolled in a new course!`,'success');
    ok(res,{},'Course purchased successfully');
  }catch(e){err(res,e.message);}
});

// Upload intro video for a course (admin only)
const videoUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(uploadsDir, 'course-intro-videos');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, 'intro-' + req.params.id + '-' + Date.now() + ext);
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowed = ['.mp4', '.webm', '.mov', '.m4v', '.ogg', '.ogv', '.avi', '.mkv'];
    const ext = path.extname(file.originalname).toLowerCase();
    allowed.includes(ext) ? cb(null, true) : cb(new Error('Only video files are allowed'));
  },
  limits: { fileSize: 500 * 1024 * 1024 } // 500 MB
});

app.post('/api/v1/courses/:id/intro-video', auth, adminOnly, (req, res) => {
  videoUpload.single('intro_video')(req, res, async (uploadErr) => {
    if (uploadErr) return err(res, uploadErr.message, 400);
    if (!req.file) return err(res, 'No video file uploaded', 400);
    const videoPath = '/uploads/course-intro-videos/' + req.file.filename;
    try {
      await pool.query('UPDATE courses SET intro_video=$1 WHERE id=$2', [videoPath, req.params.id]);
      ok(res, { intro_video: videoPath }, 'Intro video uploaded');
    } catch (e) { err(res, e.message); }
  });
});

// ── COURSE CONTENT UPLOAD (MP4 / SCORM zip / PDF) ────────────────────────────
const courseContentUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = ['.mp4','.webm','.mov','.m4v','.zip','.pdf'];
    allowed.includes(ext) ? cb(null, true) : cb(new Error('Only MP4, SCORM zip, or PDF files allowed'));
  },
  limits: { fileSize: 500 * 1024 * 1024 }
});

app.post('/api/v1/courses/:id/upload-content', auth, adminOnly, courseContentUpload.single('content'), async (req, res) => {
  try {
    if (!req.file) return err(res, 'No file uploaded', 400);
    const courseId = req.params.id;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const isPDF = ext === '.pdf';
    const isZip = ext === '.zip';
    const isVideo = ['.mp4','.webm','.mov','.m4v'].includes(ext);

    // Ensure a default "Course Content" module exists
    let modR = await pool.query(`SELECT id FROM modules WHERE course_id=$1 AND name='Course Content' LIMIT 1`, [courseId]);
    let moduleId;
    if (modR.rows[0]) {
      moduleId = modR.rows[0].id;
    } else {
      const orderR = await pool.query('SELECT COALESCE(MAX(order_no),0)+1 AS next FROM modules WHERE course_id=$1', [courseId]);
      const ins = await pool.query('INSERT INTO modules(name,course_id,duration,order_no) VALUES($1,$2,$3,$4) RETURNING id',
        ['Course Content', courseId, '—', orderR.rows[0].next]);
      moduleId = ins.rows[0].id;
    }

    if (isPDF) {
      // Save PDF to materials folder
      const matDir = path.join(uploadsDir, 'materials');
      if (!fs.existsSync(matDir)) fs.mkdirSync(matDir, { recursive: true });
      const filename = Date.now() + '-' + Math.round(Math.random()*1e6) + ext;
      fs.writeFileSync(path.join(matDir, filename), req.file.buffer);
      const fp = '/uploads/materials/' + filename;
      const r = await pool.query(
        'INSERT INTO course_materials(module_id,course_id,title,type,file_path_or_url,uploaded_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
        [moduleId, courseId, req.file.originalname, 'PDF', fp, req.user.id]
      );
      await logAudit(req.user.id, req.user.role, 'PDF_UPLOAD', 'course_materials', r.rows[0].id, 'Uploaded PDF: '+req.file.originalname, req.ip);
      ok(res, { id: r.rows[0].id, file_path: fp, type: 'pdf' }, 'PDF uploaded successfully');

    } else if (isVideo) {
      // Upload video as scorm_package (content_type=video)
      const pkgName = req.file.originalname.replace(/\.[^/.]+$/, '');
      const pkgR = await pool.query(
        'INSERT INTO scorm_packages(module_id,package_name,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [moduleId, pkgName, '1.2', '', 'video']
      );
      const pkgId = pkgR.rows[0].id;
      const videoDir = path.join(uploadsDir, 'scorm', String(pkgId));
      fs.mkdirSync(videoDir, { recursive: true });
      const filename = 'video' + ext;
      fs.writeFileSync(path.join(videoDir, filename), req.file.buffer);
      const videoPath = '/uploads/scorm/' + pkgId + '/' + filename;
      await pool.query('UPDATE scorm_packages SET upload_path=$1 WHERE id=$2', [videoPath, pkgId]);
      await logAudit(req.user.id, req.user.role, 'COURSE_VIDEO_UPLOAD', 'scorm_packages', pkgId, 'Uploaded course video: '+pkgName, req.ip);
      ok(res, { id: pkgId, launch_url: videoPath, type: 'video', module_id: moduleId }, 'Video uploaded successfully');

    } else if (isZip) {
      // Upload SCORM zip
      const pkgName = req.file.originalname.replace('.zip', '');
      const pkgR = await pool.query(
        'INSERT INTO scorm_packages(module_id,package_name,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [moduleId, pkgName, req.body.scorm_version || '1.2', '', 'scorm']
      );
      const pkgId = pkgR.rows[0].id;
      const extractPath = path.join(uploadsDir, 'scorm', String(pkgId));
      fs.mkdirSync(extractPath, { recursive: true });
      extractZip(req.file.buffer, extractPath);
      // Find manifest
      let manifestPath = '', relManifest = '';
      function findManifest(dir, base) {
        for (const f of fs.readdirSync(dir)) {
          const fp = path.join(dir, f);
          if (fs.statSync(fp).isDirectory()) { findManifest(fp, base); continue; }
          if (f.toLowerCase() === 'imsmanifest.xml' && !manifestPath) {
            manifestPath = fp; relManifest = path.relative(base, fp).replace(/\\/g, '/');
          }
        }
      }
      findManifest(extractPath, extractPath);
      const launchUrl = findLaunch(extractPath, manifestPath) || relManifest;
      await pool.query('UPDATE scorm_packages SET manifest_path=$1,upload_path=$2 WHERE id=$3',
        [relManifest, '/uploads/scorm/'+pkgId+'/'+launchUrl, pkgId]);
      await logAudit(req.user.id, req.user.role, 'SCORM_UPLOAD', 'scorm_packages', pkgId, 'Uploaded SCORM: '+pkgName, req.ip);
      ok(res, { id: pkgId, launch_url: '/uploads/scorm/'+pkgId+'/'+launchUrl, type: 'scorm', module_id: moduleId }, 'SCORM uploaded successfully');
    }
  } catch(e) { console.error('Course content upload error:', e); err(res, e.message); }
});

// ── ADMIN: COURSE PROGRESS REPORT ────────────────────────────────────────────
app.get('/api/v1/admin/courses/:courseId/progress', auth, adminOnly, async (req, res) => {
  try {
    const cid = req.params.courseId;
    const totalMods = await pool.query('SELECT COUNT(*) AS cnt FROM modules WHERE course_id=$1', [cid]);
    const total = parseInt(totalMods.rows[0].cnt) || 0;

    // Students enrolled in this course
    const students = await pool.query(`
      SELECT s.id, s.name, s.email, 'student' AS user_type,
        COALESCE((SELECT COUNT(*) FROM student_progress sp WHERE sp.student_id=s.id AND sp.completed=TRUE
          AND sp.module_id IN (SELECT id FROM modules WHERE course_id=$1)),0) AS completed_modules,
        COALESCE((SELECT MAX(sp.last_accessed) FROM student_progress sp WHERE sp.student_id=s.id
          AND sp.module_id IN (SELECT id FROM modules WHERE course_id=$1)),'—') AS last_accessed
      FROM students s WHERE s.course_id=$1 ORDER BY s.name
    `, [cid]);

    // Corporate participants assigned this course
    const participants = await pool.query(`
      SELECT cp.id, cp.name, cp.email, 'participant' AS user_type,
        cc.company_name AS company,
        COALESCE((SELECT COUNT(*) FROM participant_progress pp WHERE pp.participant_id=cp.id AND pp.completed=TRUE
          AND pp.module_id IN (SELECT id FROM modules WHERE course_id=$1)),0) AS completed_modules,
        COALESCE((SELECT MAX(pp.last_accessed) FROM participant_progress pp WHERE pp.participant_id=cp.id
          AND pp.module_id IN (SELECT id FROM modules WHERE course_id=$1)),'—') AS last_accessed
      FROM corporate_course_assignments cca
      JOIN corporate_participants cp ON cca.participant_id=cp.id
      LEFT JOIN corporate_clients cc ON cp.corporate_id=cc.id
      WHERE cca.course_id=$1 ORDER BY cp.name
    `, [cid]);

    const allUsers = [...students.rows, ...participants.rows].map(u => ({
      ...u,
      total_modules: total,
      progress_pct: total > 0 ? Math.round((parseInt(u.completed_modules) / total) * 100) : 0
    }));
    ok(res, { users: allUsers, total_modules: total, course_id: cid });
  } catch(e) { err(res, e.message); }
});

// ── CORPORATE: COURSE PROGRESS FOR THEIR PARTICIPANTS ─────────────────────────
app.get('/api/v1/corporate/courses/:courseId/progress', auth, requireRole('corporate','admin'), async (req, res) => {
  try {
    const cid = req.params.courseId;
    const corpId = req.user.role === 'corporate' ? req.user.id : req.query.corporate_id;
    const totalMods = await pool.query('SELECT COUNT(*) AS cnt FROM modules WHERE course_id=$1', [cid]);
    const total = parseInt(totalMods.rows[0].cnt) || 0;
    const courseInfo = await pool.query('SELECT passing_percentage, requires_pass, course_type FROM courses WHERE id=$1', [cid]);
    const passPct = parseInt(courseInfo.rows[0]?.passing_percentage) || 0;

    let q = `
      SELECT cp.id, cp.name, cp.email,
        COALESCE((SELECT COUNT(*) FROM participant_progress pp WHERE pp.participant_id=cp.id AND pp.completed=TRUE
          AND pp.module_id IN (SELECT id FROM modules WHERE course_id=$1)),0) AS completed_modules,
        COALESCE((SELECT MAX(pp.last_accessed) FROM participant_progress pp WHERE pp.participant_id=cp.id
          AND pp.module_id IN (SELECT id FROM modules WHERE course_id=$1)), NULL) AS last_accessed,
        COALESCE((SELECT MAX(st.score_raw) FROM scorm_tracking st
          JOIN scorm_packages sp ON st.package_id=sp.id
          JOIN modules m ON sp.module_id=m.id
          WHERE st.participant_id=cp.id AND m.course_id=$1), NULL) AS scorm_score,
        COALESCE((SELECT MAX(st.score_max) FROM scorm_tracking st
          JOIN scorm_packages sp ON st.package_id=sp.id
          JOIN modules m ON sp.module_id=m.id
          WHERE st.participant_id=cp.id AND m.course_id=$1), 100) AS scorm_score_max,
        COALESCE((SELECT MAX(CASE WHEN st.completion_status IN ('completed','passed') THEN 1 ELSE 0 END) FROM scorm_tracking st
          JOIN scorm_packages sp ON st.package_id=sp.id
          JOIN modules m ON sp.module_id=m.id
          WHERE st.participant_id=cp.id AND m.course_id=$1), 0) AS scorm_completed,
        COALESCE((SELECT pqa.passed FROM participant_quiz_attempts pqa
          WHERE pqa.participant_id=cp.id AND pqa.course_id=$1), NULL) AS quiz_passed,
        COALESCE((SELECT pqa.score FROM participant_quiz_attempts pqa
          WHERE pqa.participant_id=cp.id AND pqa.course_id=$1), NULL) AS quiz_score,
        COALESCE((SELECT pqa.total_questions FROM participant_quiz_attempts pqa
          WHERE pqa.participant_id=cp.id AND pqa.course_id=$1), NULL) AS quiz_total,
        (SELECT pc.certificate_no FROM participant_certificates pc
          WHERE pc.participant_id=cp.id AND pc.course_id=$1) AS certificate_no
      FROM corporate_course_assignments cca
      JOIN corporate_participants cp ON cca.participant_id=cp.id
      WHERE cca.course_id=$1`;
    const params = [cid];
    if (corpId) { params.push(corpId); q += ` AND cp.corporate_id=$${params.length}`; }
    q += ' ORDER BY cp.name';
    const r = await pool.query(q, params);
    const users = r.rows.map(u => {
      const completedMods = parseInt(u.completed_modules) || 0;
      const progress_pct = total > 0 ? Math.round((completedMods / total) * 100) : (u.scorm_completed ? 100 : 0);
      const scorm_score_pct = u.scorm_score !== null ? Math.round((parseInt(u.scorm_score) / (parseInt(u.scorm_score_max)||100)) * 100) : null;
      const passing_status = passPct > 0 && scorm_score_pct !== null ? (scorm_score_pct >= passPct ? 'pass' : 'fail') : (u.quiz_passed === true ? 'pass' : u.quiz_passed === false ? 'fail' : null);
      return { ...u, total_modules: total, progress_pct, scorm_score_pct, passing_status, passing_percentage: passPct };
    });
    ok(res, { users, total_modules: total, passing_percentage: passPct });
  } catch(e) { err(res, e.message); }
});

// ── PARTICIPANT: GET COURSE MATERIALS (PDFs) ──────────────────────────────────
app.get('/api/v1/participant/courses/:courseId/materials', auth, requireRole('participant'), async (req, res) => {
  try {
    // Verify participant is assigned to this course
    const check = await pool.query('SELECT id FROM corporate_course_assignments WHERE participant_id=$1 AND course_id=$2', [req.user.id, req.params.courseId]);
    if (!check.rows[0]) return err(res, 'Not enrolled in this course', 403);
    const r = await pool.query(`
      SELECT cm.id, cm.title, cm.type, cm.file_path_or_url, cm.created_at
      FROM course_materials cm
      WHERE cm.course_id=$1
      ORDER BY cm.created_at ASC
    `, [req.params.courseId]);
    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// ── PARTICIPANT: GET QUIZ QUESTIONS (no correct answers exposed) ──────────────
app.get('/api/v1/participant/courses/:courseId/quiz', auth, requireRole('participant'), async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const participantId = req.user.id;
    const access = await pool.query('SELECT id FROM corporate_course_assignments WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
    if (!access.rows[0]) return err(res, 'Access denied', 403);
    const course = await pool.query('SELECT id, name, course_type, passing_percentage, requires_pass FROM courses WHERE id=$1', [courseId]);
    if (!course.rows[0]) return err(res, 'Course not found', 404);
    const questions = await pool.query('SELECT id, question, option_a, option_b, option_c, option_d FROM mcqs WHERE course_id=$1 ORDER BY id', [courseId]);
    const prev = await pool.query('SELECT * FROM participant_quiz_attempts WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
    ok(res, { course: course.rows[0], questions: questions.rows, total: questions.rows.length, previous_attempt: prev.rows[0] || null });
  } catch(e) { err(res, e.message); }
});

// ── PARTICIPANT: SUBMIT QUIZ ANSWERS ──────────────────────────────────────────
app.post('/api/v1/participant/courses/:courseId/quiz/submit', auth, requireRole('participant'), async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const participantId = req.user.id;
    const { answers } = req.body; // { "questionId": "A"|"B"|"C"|"D" }
    if (!answers || typeof answers !== 'object') return err(res, 'Answers are required', 400);
    const access = await pool.query('SELECT id FROM corporate_course_assignments WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
    if (!access.rows[0]) return err(res, 'Access denied', 403);
    const course = await pool.query('SELECT passing_percentage, requires_pass, course_type FROM courses WHERE id=$1', [courseId]);
    if (!course.rows[0]) return err(res, 'Course not found', 404);
    const questions = await pool.query('SELECT id, correct_answer FROM mcqs WHERE course_id=$1', [courseId]);
    const total = questions.rows.length;
    if (total === 0) return err(res, 'No quiz questions found for this course', 400);
    let score = 0;
    for (const q of questions.rows) {
      const given = (answers[String(q.id)] || '').toString().toUpperCase().trim();
      if (given && given === q.correct_answer.toUpperCase()) score++;
    }
    const passingPct = parseInt(course.rows[0].passing_percentage) || 60;
    const scorePct = Math.round((score / total) * 100);
    const passed = scorePct >= passingPct;
    await pool.query(`INSERT INTO participant_quiz_attempts(participant_id,course_id,score,total_questions,passed,answers)
      VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(participant_id,course_id) DO UPDATE SET score=$3,total_questions=$4,passed=$5,answers=$6,attempted_at=NOW()`,
      [participantId, courseId, score, total, passed, JSON.stringify(answers)]);
    // Auto-issue certificate if passed + SCORM/modules complete (only for custom_quiz Option 3)
    let certificate = null;
    if (passed && course.rows[0].course_type === 'custom_quiz') {
      const totalMods = await pool.query('SELECT COUNT(*) FROM modules WHERE course_id=$1', [courseId]);
      const completedMods = await pool.query('SELECT COUNT(*) FROM participant_progress WHERE participant_id=$1 AND completed=TRUE AND module_id IN (SELECT id FROM modules WHERE course_id=$2)', [participantId, courseId]);
      const allModsDone = parseInt(totalMods.rows[0].count) === 0 || parseInt(completedMods.rows[0].count) >= parseInt(totalMods.rows[0].count);
      // Also check SCORM completion as fallback
      const scormCheck = await pool.query(`SELECT COALESCE(MAX(CASE WHEN st.completion_status IN ('completed','passed') THEN 1 ELSE 0 END),0) AS done
        FROM scorm_tracking st JOIN scorm_packages sp ON st.package_id=sp.id JOIN modules m ON sp.module_id=m.id
        WHERE st.participant_id=$1 AND m.course_id=$2`, [participantId, courseId]);
      const scormDone = parseInt(scormCheck.rows[0]?.done) === 1;
      if (allModsDone || scormDone) {
        const certNo = 'CDPL-PART-' + Date.now();
        const cp = await pool.query('SELECT corporate_id FROM corporate_participants WHERE id=$1', [participantId]);
        const certR = await pool.query(`INSERT INTO participant_certificates(participant_id,course_id,corporate_id,certificate_no)
          VALUES($1,$2,$3,$4) ON CONFLICT(participant_id,course_id) DO NOTHING RETURNING *`,
          [participantId, courseId, cp.rows[0]?.corporate_id, certNo]);
        certificate = certR.rows[0] || null;
        if (!certificate) {
          const existing = await pool.query('SELECT * FROM participant_certificates WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
          certificate = existing.rows[0] || null;
        }
      }
    }
    ok(res, { score, total, score_pct: scorePct, passed, passing_pct: passingPct, certificate });
  } catch(e) { err(res, e.message); }
});

// ── PARTICIPANT: GET CERTIFICATE STATUS (auto-issues if eligible) ─────────────
app.get('/api/v1/participant/courses/:courseId/certificate', auth, requireRole('participant'), async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const participantId = req.user.id;
    const access = await pool.query('SELECT id FROM corporate_course_assignments WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
    if (!access.rows[0]) return err(res, 'Access denied', 403);
    const course = await pool.query('SELECT id, name, course_type, passing_percentage, requires_pass FROM courses WHERE id=$1', [courseId]);
    if (!course.rows[0]) return err(res, 'Course not found', 404);
    const totalMods = await pool.query('SELECT COUNT(*) FROM modules WHERE course_id=$1', [courseId]);
    const completedMods = await pool.query('SELECT COUNT(*) FROM participant_progress WHERE participant_id=$1 AND completed=TRUE AND module_id IN (SELECT id FROM modules WHERE course_id=$2)', [participantId, courseId]);
    const totalModsCount = parseInt(totalMods.rows[0].count);
    const completedModsCount = parseInt(completedMods.rows[0].count);
    const allModsDone = totalModsCount === 0 || completedModsCount >= totalModsCount;
    // Only Option 3 (custom_quiz) requires quiz pass for certificate
    const quizRequired = course.rows[0].course_type === 'custom_quiz';
    let quizPassed = !quizRequired;
    let quizAttempt = null;
    if (quizRequired) {
      const qa = await pool.query('SELECT * FROM participant_quiz_attempts WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
      quizAttempt = qa.rows[0] || null;
      quizPassed = qa.rows[0]?.passed || false;
    }
    // For Options 1 & 2 (non-quiz courses), also check SCORM completion as eligibility
    let scormDone = false;
    if (!quizRequired) {
      const scormCheck = await pool.query(`SELECT COALESCE(MAX(CASE WHEN st.completion_status IN ('completed','passed') THEN 1 ELSE 0 END),0) AS done
        FROM scorm_tracking st JOIN scorm_packages sp ON st.package_id=sp.id JOIN modules m ON sp.module_id=m.id
        WHERE st.participant_id=$1 AND m.course_id=$2`, [participantId, courseId]);
      scormDone = parseInt(scormCheck.rows[0]?.done) === 1;
    }
    const effectivelyDone = allModsDone || scormDone;
    const existing = await pool.query('SELECT * FROM participant_certificates WHERE participant_id=$1 AND course_id=$2', [participantId, courseId]);
    let certificate = existing.rows[0] || null;
    if (!certificate && effectivelyDone && quizPassed) {
      const certNo = 'CDPL-PART-' + Date.now();
      const cp = await pool.query('SELECT corporate_id FROM corporate_participants WHERE id=$1', [participantId]);
      const certR = await pool.query(`INSERT INTO participant_certificates(participant_id,course_id,corporate_id,certificate_no)
        VALUES($1,$2,$3,$4) ON CONFLICT(participant_id,course_id) DO NOTHING RETURNING *`,
        [participantId, courseId, cp.rows[0]?.corporate_id, certNo]);
      certificate = certR.rows[0] || null;
      if (!certificate) { const re2 = await pool.query('SELECT * FROM participant_certificates WHERE participant_id=$1 AND course_id=$2',[participantId,courseId]); certificate=re2.rows[0]||null; }
    }
    ok(res, { course_id: parseInt(courseId), total_modules: totalModsCount, completed_modules: completedModsCount,
      modules_complete: effectivelyDone, quiz_required: quizRequired, quiz_passed: quizPassed, quiz_attempt: quizAttempt,
      certificate, eligible: effectivelyDone && quizPassed });
  } catch(e) { err(res, e.message); }
});

// ── CORPORATE: PER-PARTICIPANT PROGRESS (all courses per participant) ─────────
app.get('/api/v1/corporate/progress/by-participant', auth, requireRole('corporate','admin'), async (req, res) => {
  try {
    const corpId = req.user.role === 'corporate' ? req.user.id : req.query.corporate_id;
    if (!corpId) return err(res, 'corporate_id required', 400);

    // Get all participants with their assigned courses + per-course progress
    const r = await pool.query(`
      SELECT
        cp.id, cp.name, cp.email, cp.status,
        json_agg(
          json_build_object(
            'course_id', c.id,
            'course_name', c.name,
            'total_modules', (SELECT COUNT(*) FROM modules WHERE course_id=c.id),
            'completed_modules', COALESCE(
              (SELECT COUNT(*) FROM participant_progress pp
               WHERE pp.participant_id=cp.id AND pp.completed=TRUE
               AND pp.module_id IN (SELECT id FROM modules WHERE course_id=c.id)), 0),
            'last_accessed', (SELECT MAX(pp.last_accessed) FROM participant_progress pp
               WHERE pp.participant_id=cp.id
               AND pp.module_id IN (SELECT id FROM modules WHERE course_id=c.id)),
            'scorm_score', (SELECT MAX(st.score_raw) FROM scorm_tracking st
               JOIN scorm_packages sp ON st.package_id=sp.id
               JOIN modules m ON sp.module_id=m.id
               WHERE st.participant_id=cp.id AND m.course_id=c.id),
            'scorm_score_max', COALESCE((SELECT MAX(st.score_max) FROM scorm_tracking st
               JOIN scorm_packages sp ON st.package_id=sp.id
               JOIN modules m ON sp.module_id=m.id
               WHERE st.participant_id=cp.id AND m.course_id=c.id), 100),
            'certificate_no', (SELECT pc.certificate_no FROM participant_certificates pc
               WHERE pc.participant_id=cp.id AND pc.course_id=c.id)
          ) ORDER BY c.name
        ) AS courses
      FROM corporate_participants cp
      JOIN corporate_course_assignments cca ON cca.participant_id=cp.id
      JOIN courses c ON cca.course_id=c.id
      WHERE cp.corporate_id=$1
      GROUP BY cp.id, cp.name, cp.email, cp.status
      ORDER BY cp.name
    `, [corpId]);

    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// ── CORPORATE ADMIN: GET PARTICIPANT CERTIFICATES ─────────────────────────────
app.get('/api/v1/corporate/participant-certificates', auth, requireRole('corporate','admin'), async (req, res) => {
  try {
    const corpId = req.user.role === 'corporate' ? req.user.id : req.query.corporate_id;
    let q = `SELECT pc.*, cp.name AS participant_name, cp.email AS participant_email, c.name AS course_name
      FROM participant_certificates pc
      JOIN corporate_participants cp ON pc.participant_id=cp.id
      JOIN courses c ON pc.course_id=c.id`;
    const params = [];
    if (corpId) { params.push(corpId); q += ` WHERE cp.corporate_id=$1`; }
    q += ' ORDER BY pc.created_at DESC';
    const r = await pool.query(q, params);
    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// ── ADMIN: GET MCQ QUESTIONS FOR A COURSE (with correct answers) ──────────────
app.get('/api/v1/courses/:courseId/mcqs', auth, requireRole('admin','corporate'), async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM mcqs WHERE course_id=$1 ORDER BY id', [req.params.courseId]);
    ok(res, r.rows);
  } catch(e) { err(res, e.message); }
});

// Participant: Get course modules with SCORM/video content + progress
// Handles ALL cases: modules with content, direct course materials, no-module SCORM
app.get('/api/v1/participant/courses/:courseId/content', auth, requireRole('participant'), async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const participantId = req.user.id;

    // Verify access
    const access = await pool.query(
      'SELECT id FROM corporate_course_assignments WHERE participant_id=$1 AND course_id=$2',
      [participantId, courseId]);
    if (!access.rows[0]) return err(res, 'Access denied', 403);

    // ── 1. All modules for this course ───────────────────────────────────────
    const modsQ = await pool.query(`
      SELECT id, name, COALESCE(order_no,0) AS order_no, duration
      FROM modules WHERE course_id=$1 ORDER BY COALESCE(order_no,0), id
    `, [courseId]);

    // ── 2. All SCORM/video packages linked to this course's modules ──────────
    const pkgsQ = await pool.query(`
      SELECT sp.id, sp.module_id, sp.package_name, sp.content_type, sp.upload_path,
             st.completion_status, st.score_raw, st.total_time
      FROM scorm_packages sp
      JOIN modules m ON sp.module_id = m.id AND m.course_id = $2
      LEFT JOIN scorm_tracking st ON st.package_id = sp.id AND st.participant_id = $1
      ORDER BY sp.module_id, sp.id
    `, [participantId, courseId]);

    // ── 3. All PDF/materials for this course (by course_id) ──────────────────
    const matsQ = await pool.query(`
      SELECT id, module_id, title, type, file_path_or_url
      FROM course_materials WHERE course_id=$1 ORDER BY COALESCE(module_id,0), id
    `, [courseId]);

    // ── 4. course_content table (direct course-level uploads) ────────────────
    const ccQ = await pool.query(`
      SELECT id, module_id, content_type, file_path, file_name FROM course_content WHERE course_id=$1
    `, [courseId]).catch(() => ({ rows: [] }));

    // ── 5. Participant progress per module ───────────────────────────────────
    const progQ = await pool.query(`
      SELECT module_id, completed, time_spent_seconds, last_accessed
      FROM participant_progress
      WHERE participant_id=$1 AND module_id IN (SELECT id FROM modules WHERE course_id=$2)
    `, [participantId, courseId]);

    // ── Build maps ────────────────────────────────────────────────────────────
    const progMap = {};
    progQ.rows.forEach(p => { progMap[p.module_id] = p; });

    const pkgMap = {};   // module_id → [packages]
    pkgsQ.rows.forEach(p => {
      const mid = p.module_id;
      if (!pkgMap[mid]) pkgMap[mid] = [];
      pkgMap[mid].push({
        id: p.id, package_name: p.package_name,
        content_type: p.content_type, upload_path: p.upload_path,
        tracking: p.completion_status ? { completion_status: p.completion_status, score_raw: p.score_raw, total_time: p.total_time } : null
      });
    });

    const matMap = {};  // module_id → [materials], null → []
    const matNoMod = [];
    matsQ.rows.forEach(m => {
      if (m.module_id) { if (!matMap[m.module_id]) matMap[m.module_id] = []; matMap[m.module_id].push(m); }
      else matNoMod.push(m);
    });

    const ccMap = {};   // module_id → [cc items], null → []
    const ccNoMod = [];
    ccQ.rows.forEach(c => {
      const item = { id: 'cc-'+c.id, package_name: c.file_name||'Content', content_type: c.content_type||'scorm', upload_path: c.file_path, tracking: null };
      if (c.module_id) { if (!ccMap[c.module_id]) ccMap[c.module_id] = []; ccMap[c.module_id].push(item); }
      else ccNoMod.push(item);
    });

    // ── Build per-module result ───────────────────────────────────────────────
    let result = modsQ.rows.map(m => ({
      id: m.id, name: m.name, order_no: m.order_no, duration: m.duration,
      progress: progMap[m.id] || null,
      packages: [...(pkgMap[m.id] || []), ...(ccMap[m.id] || [])],
      materials: matMap[m.id] || [],
    }));

    // ── Add "Course Materials" section for content not linked to any module ───
    const extraPkgs = ccNoMod;
    const extraMats = matNoMod;
    if (extraPkgs.length || extraMats.length) {
      result.push({
        id: 'general', name: 'Course Materials', order_no: 9999, duration: null,
        progress: null, packages: extraPkgs, materials: extraMats,
      });
    }

    ok(res, result);
  } catch(e) { err(res, e.message); }
});

// Admin: List all content (SCORM + PDFs) for a course
app.get('/api/v1/admin/courses/:courseId/content-list', auth, adminOnly, async (req, res) => {
  try {
    const courseId = req.params.courseId;
    // SCORM / video packages linked to this course via modules
    const pkgs = await pool.query(`
      SELECT sp.id::text AS id, sp.package_name AS name, sp.content_type AS type, sp.upload_path,
             m.name AS module_name
      FROM scorm_packages sp
      JOIN modules m ON sp.module_id = m.id AND m.course_id = $1
      ORDER BY m.id, sp.id
    `, [courseId]);
    // PDF / materials
    const mats = await pool.query(`
      SELECT cm.id::text AS id, cm.title AS name, LOWER(cm.type) AS type, cm.file_path_or_url AS upload_path,
             m.name AS module_name
      FROM course_materials cm
      LEFT JOIN modules m ON cm.module_id = m.id
      WHERE cm.course_id = $1
      ORDER BY cm.id
    `, [courseId]);
    // course_content table (fallback)
    const cc = await pool.query(`
      SELECT 'cc-'||id AS id, COALESCE(file_name,'Content') AS name, content_type AS type, file_path AS upload_path, NULL AS module_name
      FROM course_content WHERE course_id = $1
    `, [courseId]).catch(() => ({ rows: [] }));

    const all = [...pkgs.rows, ...mats.rows, ...cc.rows];
    ok(res, all);
  } catch(e) { err(res, e.message); }
});

// Admin: Delete a course material (PDF)
app.delete('/api/v1/courses/materials/:id', auth, adminOnly, async (req, res) => {
  try {
    const r = await pool.query('SELECT file_path_or_url FROM course_materials WHERE id=$1', [req.params.id]);
    if (!r.rows[0]) return err(res, 'Material not found', 404);
    // Delete file from disk
    const fp = r.rows[0].file_path_or_url;
    if (fp && !fp.startsWith('http')) {
      const fullPath = path.join(__dirname, '..', fp);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    await pool.query('DELETE FROM course_materials WHERE id=$1', [req.params.id]);
    ok(res, {}, 'Material deleted');
  } catch(e) { err(res, e.message); }
});

// Mark purchase from external website (no double payment)
app.post('/api/v1/courses/:id/mark-purchased', auth, adminOnly, async (req,res)=>{
  try{
    const {student_id,payment_ref,amount}=req.body;
    await pool.query(`INSERT INTO course_purchases(student_id,course_id,amount,payment_source,payment_ref) VALUES($1,$2,$3,'website',$4) ON CONFLICT(student_id,course_id) DO NOTHING`,
      [student_id,req.params.id,amount||0,payment_ref||'website-purchase']);
    ok(res,{},'Purchase recorded');
  }catch(e){err(res,e.message);}
});

// Get student's purchased courses
app.get('/api/v1/student/purchases', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT cp.*,c.name AS course_name,c.description,c.thumbnail,c.duration,c.avg_rating
      FROM course_purchases cp JOIN courses c ON cp.course_id=c.id
      WHERE cp.student_id=$1 ORDER BY cp.purchased_at DESC
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Get student's MY COURSES (admin/trainer assigned only, not purchased ones)
app.get('/api/v1/student/mycourses', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT c.id,c.name,c.description,c.thumbnail,c.duration,c.avg_rating,c.certificate_validity_days,
             cat.name AS category_name, t.name AS trainer_name,
             (SELECT COUNT(*) FROM modules WHERE course_id=c.id) AS total_modules,
             (SELECT COUNT(*) FROM student_progress WHERE student_id=$1 AND module_id IN (SELECT id FROM modules WHERE course_id=c.id) AND completed=TRUE) AS completed_modules,
             COALESCE((SELECT COALESCE(SUM(time_spent_seconds),0) FROM student_progress WHERE student_id=$1 AND module_id IN (SELECT id FROM modules WHERE course_id=c.id)),0) AS time_spent_seconds
      FROM courses c
      LEFT JOIN categories cat ON c.category_id=cat.id
      LEFT JOIN trainers t ON c.linked_trainer_id=t.id
      WHERE c.id=(SELECT course_id FROM students WHERE id=$1)
      ORDER BY c.name
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ═══════════════════════════════════════════════════════════════
// STUDENT QUERIES
// ═══════════════════════════════════════════════════════════════
// Student raises a query
app.post('/api/v1/queries', auth, studentOnly, async (req,res)=>{
  try{
    const {question,course_id,target_role}=req.body;
    if(!question||!question.trim()) return err(res,'Question required',400);
    const role=(target_role==='admin')?'admin':'trainer';
    let trainerId=null;
    if(role==='trainer'){
      const trainerQ=await pool.query(`
        SELECT b.trainer_id FROM students s LEFT JOIN batches b ON s.batch_id=b.id WHERE s.id=$1
      `,[req.user.id]);
      trainerId=trainerQ.rows[0]?.trainer_id||null;
    }
    const r=await pool.query(
      'INSERT INTO student_queries(student_id,trainer_id,course_id,question,target_role) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id,trainerId,course_id||null,sanitize(question),role]
    );
    if(role==='trainer'&&trainerId){
      await notify(trainerId,'trainer',`New query from student: "${question.substring(0,60)}..."`, 'query','/trainer-dashboard.html#queries');
    }
    ok(res,r.rows[0],'Query raised successfully');
  }catch(e){err(res,e.message);}
});

// Student views own queries
app.get('/api/v1/queries/my', auth, studentOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT sq.*,t.name AS trainer_name,c.name AS course_name
      FROM student_queries sq
      LEFT JOIN trainers t ON sq.trainer_id=t.id
      LEFT JOIN courses c ON sq.course_id=c.id
      WHERE sq.student_id=$1 ORDER BY sq.created_at DESC
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Trainer views assigned queries
app.get('/api/v1/queries/trainer', auth, trainerOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT sq.*,s.name AS student_name,s.email AS student_email,c.name AS course_name
      FROM student_queries sq
      JOIN students s ON sq.student_id=s.id
      LEFT JOIN courses c ON sq.course_id=c.id
      WHERE sq.trainer_id=$1 ORDER BY sq.created_at DESC
    `,[req.user.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Trainer responds to a query
app.put('/api/v1/queries/:id/respond', auth, trainerOnly, async (req,res)=>{
  try{
    const {answer}=req.body;
    if(!answer||!answer.trim()) return err(res,'Answer required',400);
    const r=await pool.query(`UPDATE student_queries SET answer=$1,status='answered',answered_at=NOW() WHERE id=$2 AND trainer_id=$3 RETURNING *`,
      [sanitize(answer),req.params.id,req.user.id]);
    if(!r.rows[0]) return err(res,'Query not found',404);
    // Notify student
    await notify(r.rows[0].student_id,'student',`Your query has been answered by the trainer!`,'success','/student-dashboard.html#queries');
    ok(res,r.rows[0],'Response sent');
  }catch(e){err(res,e.message);}
});

// Admin responds to a query (admin-targeted)
app.put('/api/v1/queries/:id/admin-respond', auth, adminOnly, async (req,res)=>{
  try{
    const {answer}=req.body;
    if(!answer||!answer.trim()) return err(res,'Answer required',400);
    const r=await pool.query(
      `UPDATE student_queries SET answer=$1,status='answered',answered_at=NOW() WHERE id=$2 RETURNING *`,
      [sanitize(answer),req.params.id]
    );
    if(!r.rows[0]) return err(res,'Query not found',404);
    await notify(r.rows[0].student_id,'student',`Your query to admin has been answered!`,'success','/student-dashboard.html#queries');
    ok(res,r.rows[0],'Response sent');
  }catch(e){err(res,e.message);}
});

// Admin views all queries
app.get('/api/v1/queries', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT sq.*,s.name AS student_name,t.name AS trainer_name,c.name AS course_name
      FROM student_queries sq
      JOIN students s ON sq.student_id=s.id
      LEFT JOIN trainers t ON sq.trainer_id=t.id
      LEFT JOIN courses c ON sq.course_id=c.id
      ORDER BY sq.created_at DESC
    `);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// ═══════════════════════════════════════════════════════════════
// STUDENT PROGRESS TIME TRACKING
// ═══════════════════════════════════════════════════════════════
app.post('/api/v1/progress/time', auth, studentOnly, async (req,res)=>{
  try{
    const {module_id,seconds_spent,completed}=req.body;
    if(!module_id) return err(res,'module_id required',400);
    await pool.query(`
      INSERT INTO student_progress(student_id,module_id,time_spent_seconds,last_accessed,completed,completed_at)
      VALUES($1,$2,$3,NOW(),$4,CASE WHEN $4=TRUE THEN NOW() ELSE NULL END)
      ON CONFLICT(student_id,module_id) DO UPDATE SET
        time_spent_seconds=student_progress.time_spent_seconds+$3,
        last_accessed=NOW(),
        completed=CASE WHEN $4=TRUE THEN TRUE ELSE student_progress.completed END,
        completed_at=CASE WHEN $4=TRUE AND student_progress.completed=FALSE THEN NOW() ELSE student_progress.completed_at END
    `,[req.user.id,module_id,seconds_spent||0,completed||false]);
    ok(res,{},'Progress saved');
  }catch(e){err(res,e.message);}
});

// Admin/Trainer: get full progress of a student
app.get('/api/v1/progress/student/:studentId', auth, requireRole('admin','trainer'), async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT sp.*,m.name AS module_name,m.order_no,c.name AS course_name,c.id AS course_id
      FROM student_progress sp
      JOIN modules m ON sp.module_id=m.id
      JOIN courses c ON m.course_id=c.id
      WHERE sp.student_id=$1
      ORDER BY c.id,m.order_no
    `,[req.params.studentId]);
    const summary=await pool.query(`
      SELECT s.name AS student_name,s.email,
        COUNT(sp.id) AS modules_touched,
        SUM(CASE WHEN sp.completed THEN 1 ELSE 0 END) AS modules_completed,
        COALESCE(SUM(sp.time_spent_seconds),0) AS total_time_seconds
      FROM students s
      LEFT JOIN student_progress sp ON sp.student_id=s.id
      WHERE s.id=$1 GROUP BY s.id,s.name,s.email
    `,[req.params.studentId]);
    ok(res,{progress:r.rows,summary:summary.rows[0]||{}});
  }catch(e){err(res,e.message);}
});

// Trainer: get all students progress in their batches
app.get('/api/v1/progress/all', auth, requireRole('admin','trainer'), async (req,res)=>{
  try{
    let q=`
      SELECT s.id,s.name,s.email,b.name AS batch_name,c.name AS course_name,
        COUNT(sp.id) AS modules_touched,
        SUM(CASE WHEN sp.completed THEN 1 ELSE 0 END) AS modules_completed,
        (SELECT COUNT(*) FROM modules WHERE course_id=s.course_id) AS total_modules,
        COALESCE(SUM(sp.time_spent_seconds),0) AS total_time_seconds,
        MAX(sp.last_accessed) AS last_active
      FROM students s
      LEFT JOIN batches b ON s.batch_id=b.id
      LEFT JOIN courses c ON s.course_id=c.id
      LEFT JOIN student_progress sp ON sp.student_id=s.id
    `;
    const params=[];
    const conditions=[];
    if(req.user.role==='trainer') conditions.push(`b.trainer_id=$${params.push(req.user.id)}`);
    if(req.query.course_id)       conditions.push(`s.course_id=$${params.push(parseInt(req.query.course_id))}`);
    if(conditions.length) q+=` WHERE `+conditions.join(' AND ');
    q+=` GROUP BY s.id,s.name,s.email,b.name,c.name,s.course_id ORDER BY s.name`;
    ok(res,(await pool.query(q,params)).rows);
  }catch(e){err(res,e.message);}
});

// ═══════════════════════════════════════════════════════════════
// COURSE CLONE
// ═══════════════════════════════════════════════════════════════
app.post('/api/v1/courses/:id/clone', auth, adminOnly, async (req,res)=>{
  try{
    const {new_name, module_ids}=req.body; // module_ids = null means clone all
    const src=await pool.query('SELECT * FROM courses WHERE id=$1',[req.params.id]);
    if(!src.rows[0]) return err(res,'Course not found',404);
    const orig=src.rows[0];
    const cloneName=sanitize(new_name||(orig.name+' (Clone)'));
    const newCourse=await pool.query(`
      INSERT INTO courses(name,category_id,duration,description,thumbnail,status,price,demo_video_path,certificate_validity_days,linked_trainer_id,has_chapters,has_assignments)
      VALUES($1,$2,$3,$4,$5,'Active',$6,$7,$8,$9,$10,$11) RETURNING id
    `,[cloneName,orig.category_id,orig.duration,orig.description,orig.thumbnail,orig.price,orig.demo_video_path,orig.certificate_validity_days,orig.linked_trainer_id,orig.has_chapters,orig.has_assignments]);
    const newCourseId=newCourse.rows[0].id;
    // Clone modules (all or selected)
    let modulesQ=`SELECT * FROM modules WHERE course_id=$1 ORDER BY order_no`;
    const modRows=(await pool.query(modulesQ,[req.params.id])).rows;
    for(const mod of modRows){
      if(module_ids&&!module_ids.includes(mod.id)) continue;
      const newMod=await pool.query('INSERT INTO modules(name,course_id,duration,order_no) VALUES($1,$2,$3,$4) RETURNING id',
        [mod.name,newCourseId,mod.duration,mod.order_no]);
      const newModId=newMod.rows[0].id;
      // Clone SCORM packages for this module
      const pkgs=await pool.query('SELECT * FROM scorm_packages WHERE module_id=$1',[mod.id]);
      for(const pkg of pkgs.rows){
        // Reference same files (or copy if needed)
        await pool.query('INSERT INTO scorm_packages(module_id,package_name,manifest_path,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5,$6)',
          [newModId,pkg.package_name,pkg.manifest_path,pkg.scorm_version,pkg.upload_path,pkg.content_type]);
      }
      // Clone materials
      const mats=await pool.query('SELECT * FROM course_materials WHERE module_id=$1',[mod.id]);
      for(const m of mats.rows){
        await pool.query('INSERT INTO course_materials(module_id,course_id,title,type,file_path_or_url,uploaded_by) VALUES($1,$2,$3,$4,$5,$6)',
          [newModId,newCourseId,m.title,m.type,m.file_path_or_url,req.user.id]);
      }
    }
    // Clone MCQs
    const mcqs=await pool.query('SELECT * FROM mcqs WHERE course_id=$1',[req.params.id]);
    for(const q2 of mcqs.rows){
      await pool.query('INSERT INTO mcqs(question,course_id,option_a,option_b,option_c,option_d,correct_answer) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [q2.question,newCourseId,q2.option_a,q2.option_b,q2.option_c,q2.option_d,q2.correct_answer]);
    }
    // Clone exams
    const exams=await pool.query('SELECT * FROM exams WHERE course_id=$1',[req.params.id]);
    for(const ex of exams.rows){
      await pool.query('INSERT INTO exams(name,course_id,duration,pass_percentage,total_marks) VALUES($1,$2,$3,$4,$5)',
        [ex.name,newCourseId,ex.duration,ex.pass_percentage,ex.total_marks]);
    }
    await logAudit(req.user.id,'admin','CLONE','courses',newCourseId,'Cloned from course '+req.params.id,req.ip);
    ok(res,{id:newCourseId},'Course cloned successfully');
  }catch(e){console.error(e);err(res,e.message);}
});

// SCORM Package Clone
app.post('/api/v1/scorm/packages/:id/clone', auth, requireRole('admin','trainer'), async (req,res)=>{
  try{
    const {target_module_id,new_name}=req.body;
    const src=await pool.query('SELECT * FROM scorm_packages WHERE id=$1',[req.params.id]);
    if(!src.rows[0]) return err(res,'Package not found',404);
    const p=src.rows[0];
    const newPkg=await pool.query('INSERT INTO scorm_packages(module_id,package_name,manifest_path,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
      [target_module_id||p.module_id,new_name||p.package_name+' (Clone)',p.manifest_path,p.scorm_version,p.upload_path,p.content_type]);
    ok(res,{id:newPkg.rows[0].id},'Package cloned successfully');
  }catch(e){err(res,e.message);}
});

// Update course fields (including new ones)
app.put('/api/v1/courses/:id/update', auth, adminOnly, async (req,res)=>{
  try{
    const {name,category_id,duration,description,thumbnail,status,price,demo_video_path,certificate_validity_days,linked_trainer_id,has_chapters,has_assignments}=req.body;
    await pool.query(`UPDATE courses SET name=$1,category_id=$2,duration=$3,description=$4,thumbnail=$5,status=$6,price=$7,demo_video_path=$8,certificate_validity_days=$9,linked_trainer_id=$10,has_chapters=$11,has_assignments=$12 WHERE id=$13`,
      [sanitize(name),category_id||null,sanitize(duration||''),sanitize(description||''),thumbnail||null,status||'Active',price||0,demo_video_path||null,certificate_validity_days||0,linked_trainer_id||null,has_chapters!==false,has_assignments===true,req.params.id]);
    ok(res,{},'Course updated');
  }catch(e){err(res,e.message);}
});

// ═══════════════════════════════════════════════════════════════
// CORPORATE CLIENTS PORTAL
// ═══════════════════════════════════════════════════════════════
const corporateOnly = requireRole('corporate');

// Corporate login uses existing auth but with 'corporate' role
// Add to login handler:
app.post('/api/v1/corporate/register', auth, adminOnly, async (req,res)=>{
  try{
    const {company_name,email,password,contact,address,group_name}=req.body;
    if(!company_name||!email||!password) return err(res,'Missing required fields',400);
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query('INSERT INTO corporate_clients(company_name,email,password_hash,plain_password,contact,address,group_name) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,company_name,email,group_name',
      [sanitize(company_name),sanitize(email.toLowerCase()),hash,password,sanitize(contact||''),sanitize(address||''),sanitize(group_name||'')]);
    ok(res,r.rows[0],'Corporate client created');
  }catch(e){err(res,e.message);}
});

// Corporate: Get my allowed courses (for corporate logged-in user)
app.get('/api/v1/corporate/my-courses', auth, requireRole('corporate'), async (req,res)=>{
  try{
    const corpId=req.user.id;
    const allowed=await pool.query('SELECT course_id FROM corporate_allowed_courses WHERE corporate_id=$1',[corpId]);
    if(!allowed.rows.length) return ok(res,[],'No courses allowed yet');
    const ids=allowed.rows.map(r=>r.course_id);
    // No status filter — show all courses admin has allowed, regardless of status
    const r=await pool.query(`
      SELECT c.id,c.name,c.description,c.duration,c.thumbnail,c.status,c.price,
             c.avg_rating,c.has_chapters,c.has_assignments,
             cat.name AS category_name, t.name AS trainer_name
      FROM courses c
      LEFT JOIN categories cat ON c.category_id=cat.id
      LEFT JOIN trainers t ON c.linked_trainer_id=t.id
      WHERE c.id=ANY($1)
      ORDER BY c.name
    `,[ids]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Admin: Duplicate corporate client (copy allowed courses, participants=0)
app.post('/api/v1/corporate/duplicate', auth, adminOnly, async (req,res)=>{
  try{
    const {source_id,new_name,new_email,new_password,new_group,course_ids}=req.body;
    if(!source_id||!new_name||!new_email||!new_password) return err(res,'Missing required fields',400);
    const src=await pool.query('SELECT * FROM corporate_clients WHERE id=$1',[source_id]);
    if(!src.rows[0]) return err(res,'Source client not found',404);
    const hash=await bcrypt.hash(new_password,12);
    const newClient=await pool.query(
      'INSERT INTO corporate_clients(company_name,email,password_hash,plain_password,contact,address,group_name,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
      [sanitize(new_name),sanitize(new_email.toLowerCase()),hash,new_password,sanitize(src.rows[0].contact||''),sanitize(src.rows[0].address||''),sanitize(new_group||src.rows[0].group_name||''),src.rows[0].status||'Active']
    );
    const newId=newClient.rows[0].id;
    // Assign explicitly selected course IDs
    const selectedIds=Array.isArray(course_ids)?course_ids.map(Number):[];
    for(const cid of selectedIds){
      await pool.query('INSERT INTO corporate_allowed_courses(corporate_id,course_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[newId,cid]);
    }
    ok(res,{id:newId},'Corporate client duplicated successfully');
  }catch(e){err(res,e.message);}
});

// Admin: Copy courses from source client to existing target client
app.post('/api/v1/corporate/:targetId/copy-courses', auth, adminOnly, async (req,res)=>{
  try{
    const targetId=parseInt(req.params.targetId);
    const {course_ids}=req.body;
    if(!targetId) return err(res,'Invalid target client ID',400);
    const target=await pool.query('SELECT id FROM corporate_clients WHERE id=$1',[targetId]);
    if(!target.rows[0]) return err(res,'Target client not found',404);
    const ids=Array.isArray(course_ids)?course_ids.map(Number).filter(Boolean):[];
    for(const cid of ids){
      await pool.query('INSERT INTO corporate_allowed_courses(corporate_id,course_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[targetId,cid]);
    }
    ok(res,{added:ids.length},`${ids.length} course(s) copied to target client`);
  }catch(e){err(res,e.message);}
});

// ── IMPORTANT: Fixed routes must come BEFORE parameterised /:id routes ────────
// Corporate: Get participants list (MUST be before /:id to avoid route conflict)
app.get('/api/v1/corporate/participants', auth, requireRole('corporate','admin'), async (req,res)=>{
  try{
    const corpId=req.user.role==='corporate'?req.user.id:req.query.corporate_id;
    let q=`SELECT cp.id,cp.corporate_id,cp.name,cp.email,cp.contact,cp.status,cp.first_login,cp.created_at,(SELECT json_agg(json_build_object('id',c.id,'name',c.name)) FROM corporate_course_assignments cca JOIN courses c ON cca.course_id=c.id WHERE cca.participant_id=cp.id) AS assigned_courses FROM corporate_participants cp WHERE 1=1`;
    const params=[];
    if(corpId){params.push(corpId);q+=` AND cp.corporate_id=$${params.length}`;}
    q+=' ORDER BY cp.created_at DESC';
    ok(res,(await pool.query(q,params)).rows);
  }catch(e){err(res,e.message);}
});

app.get('/api/v1/corporate/list', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT cc.id,cc.company_name,cc.email,cc.contact,cc.address,cc.status,cc.created_at,cc.plain_password,cc.group_name,(SELECT COUNT(*) FROM corporate_participants WHERE corporate_id=cc.id) AS participant_count,(SELECT COUNT(*) FROM corporate_allowed_courses WHERE corporate_id=cc.id) AS allowed_courses_count,(SELECT COUNT(*) FROM corporate_course_assignments cca JOIN corporate_participants cp ON cca.participant_id=cp.id WHERE cp.corporate_id=cc.id) AS total_courses_taken,(SELECT COALESCE(SUM(c.price),0) FROM corporate_allowed_courses cac JOIN courses c ON cac.course_id=c.id WHERE cac.corporate_id=cc.id) AS total_courses_price FROM corporate_clients cc ORDER BY cc.created_at DESC`);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Admin: Get single corporate client
app.get('/api/v1/corporate/:id', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT cc.*,(SELECT COUNT(*) FROM corporate_participants WHERE corporate_id=cc.id) AS participant_count FROM corporate_clients cc WHERE cc.id=$1`,[req.params.id]);
    if(!r.rows[0]) return err(res,'Not found',404);
    ok(res,r.rows[0]);
  }catch(e){err(res,e.message);}
});

// Admin: Update corporate client (including password reset)
app.put('/api/v1/corporate/:id', auth, adminOnly, async (req,res)=>{
  try{
    const {company_name,email,contact,address,status,new_password,group_name}=req.body;
    const existing=await pool.query('SELECT * FROM corporate_clients WHERE id=$1',[req.params.id]);
    if(!existing.rows[0]) return err(res,'Not found',404);
    const updName=sanitize(company_name||existing.rows[0].company_name);
    const updEmail=sanitize((email||existing.rows[0].email).toLowerCase());
    const updContact=sanitize(contact||existing.rows[0].contact||'');
    const updAddress=sanitize(address||existing.rows[0].address||'');
    const updStatus=status||existing.rows[0].status||'Active';
    const updGroup=sanitize(group_name!==undefined?group_name:existing.rows[0].group_name||'');
    if(new_password){
      const hash=await bcrypt.hash(new_password,12);
      await pool.query('UPDATE corporate_clients SET company_name=$1,email=$2,contact=$3,address=$4,status=$5,password_hash=$6,plain_password=$7,group_name=$8 WHERE id=$9',
        [updName,updEmail,updContact,updAddress,updStatus,hash,new_password,updGroup,req.params.id]);
    } else {
      await pool.query('UPDATE corporate_clients SET company_name=$1,email=$2,contact=$3,address=$4,status=$5,group_name=$6 WHERE id=$7',
        [updName,updEmail,updContact,updAddress,updStatus,updGroup,req.params.id]);
    }
    const updated=await pool.query('SELECT id,company_name,email,contact,address,status,plain_password,group_name FROM corporate_clients WHERE id=$1',[req.params.id]);
    ok(res,updated.rows[0],'Corporate client updated');
  }catch(e){err(res,e.message);}
});

// Admin: Delete corporate client (cascades participants, assignments, allowed courses)
app.delete('/api/v1/corporate/:id', auth, adminOnly, async (req,res)=>{
  try{
    const existing=await pool.query('SELECT id,company_name FROM corporate_clients WHERE id=$1',[req.params.id]);
    if(!existing.rows[0]) return err(res,'Corporate client not found',404);
    await pool.query('DELETE FROM corporate_clients WHERE id=$1',[req.params.id]);
    ok(res,{},'Corporate client deleted successfully');
  }catch(e){err(res,e.message);}
});

// Admin: Get allowed courses for a corporate client
app.get('/api/v1/corporate/:id/allowed-courses', auth, adminOnly, async (req,res)=>{
  try{
    const r=await pool.query(`SELECT cac.course_id,c.name,c.status FROM corporate_allowed_courses cac JOIN courses c ON cac.course_id=c.id WHERE cac.corporate_id=$1 ORDER BY c.name`,[req.params.id]);
    ok(res,r.rows);
  }catch(e){err(res,e.message);}
});

// Admin: Set allowed courses for a corporate client (replaces all)
app.put('/api/v1/corporate/:id/allowed-courses', auth, adminOnly, async (req,res)=>{
  try{
    const {course_ids}=req.body;
    await pool.query('DELETE FROM corporate_allowed_courses WHERE corporate_id=$1',[req.params.id]);
    if(course_ids&&course_ids.length>0){
      for(const cid of course_ids){
        await pool.query('INSERT INTO corporate_allowed_courses(corporate_id,course_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.params.id,cid]);
      }
    }
    ok(res,{},'Allowed courses updated');
  }catch(e){err(res,e.message);}
});

// Corporate client login (add to main auth)
app.post('/api/v1/corporate/login', async (req,res)=>{
  try{
    const {email,password}=req.body;
    if(!email||!password) return err(res,'Missing fields',400);
    const r=await pool.query('SELECT * FROM corporate_clients WHERE email=$1 AND status=$2',[email.toLowerCase().trim(),'Active']);
    if(!r.rows[0]) return err(res,'Invalid credentials',401);
    const valid=await bcrypt.compare(password,r.rows[0].password_hash);
    if(!valid) return err(res,'Invalid credentials',401);
    const token=jwt.sign({id:r.rows[0].id,role:'corporate',name:r.rows[0].company_name,email:r.rows[0].email},JWT_SECRET,{expiresIn:'8h'});
    ok(res,{token,name:r.rows[0].company_name,role:'corporate',id:r.rows[0].id});
  }catch(e){err(res,'Server error');}
});

// Corporate: Add participant manually
app.post('/api/v1/corporate/participants', auth, requireRole('corporate','admin'), async (req,res)=>{
  try{
    const {name,email,contact,course_ids}=req.body;
    if(!name||!email) return err(res,'Name and email required',400);
    const corpId=req.user.role==='corporate'?req.user.id:req.body.corporate_id;
    // Generate OTP password
    const otp=Math.floor(100000+Math.random()*900000).toString();
    const hash=await bcrypt.hash(otp,10);
    const r=await pool.query(`INSERT INTO corporate_participants(corporate_id,name,email,password_hash,otp_password,contact,status) VALUES($1,$2,$3,$4,$5,$6,'Active') ON CONFLICT(email) DO UPDATE SET name=$2,password_hash=$4,otp_password=$5,contact=$6,status='Active',first_login=TRUE RETURNING id`,
      [corpId,sanitize(name),sanitize(email.toLowerCase()),hash,otp,sanitize(contact||'')]);
    const pid=r.rows[0].id;
    // Assign courses
    if(course_ids&&course_ids.length>0){
      for(const cid of course_ids){
        await pool.query(`INSERT INTO corporate_course_assignments(participant_id,course_id,assigned_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,[pid,cid,corpId]);
      }
    }
    // Get company name for email
    const corpR=await pool.query('SELECT company_name FROM corporate_clients WHERE id=$1',[corpId]);
    const companyName=corpR.rows[0]?.company_name||'Your Company';
    // Send welcome email
    const loginUrl=`${process.env.BASE_URL||'http://localhost:3000'}/participant-login.html`;
    const dashUrl=`${process.env.BASE_URL||'http://localhost:3000'}/participant-dashboard.html`;
    await sendEmail(email,'Welcome to Smart LMS – Your Training Portal',`
      <div style="font-family:Arial;padding:20px;max-width:600px;margin:auto;background:#f9f9f9;border-radius:12px;">
        <div style="background:#1a237e;padding:20px;border-radius:8px 8px 0 0;text-align:center;">
          <h2 style="color:#fff;margin:0;">Welcome to Smart LMS</h2>
        </div>
        <div style="background:#fff;padding:24px;border-radius:0 0 8px 8px;">
          <p>Dear <strong>${name}</strong>,</p>
          <p>You have been enrolled in a training program by <strong>${companyName}</strong>.</p>
          <p><strong>Your Login Credentials:</strong></p>
          <div style="background:#f0f4ff;padding:16px;border-radius:8px;margin:16px 0;">
            <p style="margin:4px 0;"><strong>Login URL:</strong> <a href="${loginUrl}">${loginUrl}</a></p>
            <p style="margin:4px 0;"><strong>Email / Login ID:</strong> ${email}</p>
            <p style="margin:4px 0;"><strong>One-Time Password:</strong> <span style="font-size:22px;font-weight:bold;color:#e91e8c;letter-spacing:4px;">${otp}</span></p>
          </div>
          <p style="color:#888;font-size:13px;">Please login and change your password on first login. If you have any issues, contact your HR department.</p>
          <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:16px;">
            <a href="${loginUrl}" style="display:inline-block;background:#1a237e;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;">Login Now</a>
            <a href="${dashUrl}?goto=courses" style="display:inline-block;background:#e91e8c;color:#fff;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:bold;">Go to My Courses</a>
          </div>
          <p style="color:#888;font-size:12px;margin-top:16px;">The "Go to My Courses" link will ask you to login first if you are not already logged in.</p>
        </div>
      </div>
    `);
    ok(res,{id:pid,otp},'Participant added and email sent');
  }catch(e){console.error(e);err(res,e.message);}
});

// Corporate: Bulk upload via XLS/CSV data
app.post('/api/v1/corporate/participants/bulk', auth, requireRole('corporate','admin'), async (req,res)=>{
  try{
    const {participants,course_ids}=req.body; // participants = [{name,email,contact}]
    if(!participants||!Array.isArray(participants)||participants.length===0) return err(res,'No participants data',400);
    const corpId=req.user.role==='corporate'?req.user.id:req.body.corporate_id;
    const results=[];
    for(const p of participants){
      if(!p.name||!p.email) continue;
      // Server-side validation: reject garbled/binary names
      const nameStr = String(p.name).trim();
      const emailStr = String(p.email).trim().toLowerCase();
      if(nameStr.length>100 || nameStr.length<1) continue;
      if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(emailStr)) continue;
      // Count suspicious characters (binary/symbol Unicode outside normal Latin range)
      let badChars=0;
      for(let ci=0;ci<nameStr.length;ci++){
        const cp=nameStr.charCodeAt(ci);
        if(cp<32||(cp>767&&cp!==8217&&cp!==8216&&cp!==8220&&cp!==8221)) badChars++;
      }
      if(badChars/nameStr.length>0.25){
        results.push({name:nameStr.substring(0,30)+'…',email:emailStr,status:'error',error:'Invalid name: contains binary/garbled characters'});
        continue;
      }
      try{
        const otp=Math.floor(100000+Math.random()*900000).toString();
        const hash=await bcrypt.hash(otp,8);
        const r=await pool.query(`INSERT INTO corporate_participants(corporate_id,name,email,password_hash,otp_password,contact,status) VALUES($1,$2,$3,$4,$5,$6,'Active') ON CONFLICT(email) DO UPDATE SET name=$2,status='Active' RETURNING id`,
          [corpId,sanitize(p.name),sanitize(p.email.toLowerCase()),hash,otp,sanitize(p.contact||'')]);
        const pid=r.rows[0].id;
        const cidList=p.course_ids||course_ids||[];
        for(const cid of cidList){
          await pool.query(`INSERT INTO corporate_course_assignments(participant_id,course_id,assigned_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,[pid,cid,corpId]);
        }
        // Send email
        const loginUrl=`${process.env.BASE_URL||'http://localhost:3000'}/participant-login.html`;
        const dashUrl2=`${process.env.BASE_URL||'http://localhost:3000'}/participant-dashboard.html`;
        await sendEmail(p.email,'Your LMS Training Access',`<div style="font-family:Arial;padding:20px;max-width:600px;"><h2 style="color:#1a237e;">Welcome to Smart LMS!</h2><p>Dear ${p.name},</p><p><strong>Login:</strong> ${p.email}<br/><strong>Password:</strong> <span style="font-size:20px;color:#e91e8c;letter-spacing:3px;">${otp}</span></p><p style="margin-top:16px;"><a href="${loginUrl}" style="background:#1a237e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;margin-right:10px;">Login Now</a><a href="${dashUrl2}?goto=courses" style="background:#e91e8c;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">Go to My Courses</a></p><p style="font-size:12px;color:#888;margin-top:12px;">Please change your password after first login.</p></div>`);
        results.push({name:p.name,email:p.email,status:'success',id:pid});
      }catch(e2){results.push({name:p.name,email:p.email,status:'error',error:e2.message});}
    }
    ok(res,{results,success:results.filter(r=>r.status==='success').length,failed:results.filter(r=>r.status==='error').length},'Bulk upload processed');
  }catch(e){err(res,e.message);}
});

// Corporate: Delete participant
app.delete('/api/v1/corporate/participants/:pid', auth, requireRole('corporate','admin'), async (req,res)=>{
  try{
    const corpId=req.user.role==='corporate'?req.user.id:null;
    // Verify participant belongs to this corporate
    const check=await pool.query(`SELECT id FROM corporate_participants WHERE id=$1 AND corporate_id=$2`,[req.params.pid,corpId]);
    if(!check.rows.length) return err(res,'Participant not found or access denied',404);
    await pool.query(`DELETE FROM corporate_participants WHERE id=$1`,[req.params.pid]);
    ok(res,{},'Participant deleted');
  }catch(e){err(res,e.message);}
});

// Corporate: Assign one or more courses to participant
app.post('/api/v1/corporate/participants/:pid/assign-course', auth, requireRole('corporate','admin'), async (req,res)=>{
  try{
    const {course_id, course_ids}=req.body;
    const corpId=req.user.role==='corporate'?req.user.id:req.body.corporate_id;
    // Support both single course_id and array course_ids
    const ids=course_ids&&Array.isArray(course_ids)?course_ids:(course_id?[course_id]:[]);
    if(!ids.length) return err(res,'No course selected',400);
    for(const cid of ids){
      await pool.query(`INSERT INTO corporate_course_assignments(participant_id,course_id,assigned_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,[req.params.pid,cid,corpId]);
    }
    ok(res,{},'Course(s) assigned');
  }catch(e){err(res,e.message);}
});

// ═══════════════════════════════════════════════════════════════
// CORPORATE PARTICIPANT LOGIN + PORTAL
// ═══════════════════════════════════════════════════════════════
// DEV ONLY: return first active participant's credentials for local testing
app.get('/api/v1/participant/test-credentials', async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT cp.email, cp.otp_password, cp.name, cc.company_name AS company
      FROM corporate_participants cp
      LEFT JOIN corporate_clients cc ON cp.corporate_id=cc.id
      WHERE cp.status='Active'
        AND cp.otp_password IS NOT NULL
        AND cp.email ~ '^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
        AND cp.name ~ '^[\x20-\x7E\u00C0-\u024F]{1,100}$'
      ORDER BY cp.id ASC LIMIT 1
    `);
    if(!r.rows[0]) return ok(res,null,'No participants found');
    ok(res,r.rows[0]);
  }catch(e){err(res,e.message);}
});

app.post('/api/v1/participant/login', async (req,res)=>{
  try{
    const {email,password}=req.body;
    if(!email||!password) return err(res,'Missing fields',400);
    const r=await pool.query('SELECT * FROM corporate_participants WHERE email=$1 AND status=$2',[email.toLowerCase().trim(),'Active']);
    if(!r.rows[0]) return err(res,'Invalid credentials',401);
    const valid=await bcrypt.compare(password,r.rows[0].password_hash);
    if(!valid) return err(res,'Invalid credentials',401);
    const token=jwt.sign({id:r.rows[0].id,role:'participant',name:r.rows[0].name,email:r.rows[0].email,corporate_id:r.rows[0].corporate_id,first_login:r.rows[0].first_login},JWT_SECRET,{expiresIn:'8h'});
    ok(res,{token,name:r.rows[0].name,role:'participant',id:r.rows[0].id,first_login:r.rows[0].first_login});
  }catch(e){err(res,'Server error');}
});

// Participant: change password (first login)
app.post('/api/v1/participant/change-password', auth, requireRole('participant'), async (req,res)=>{
  try{
    const {new_password}=req.body;
    if(!new_password||new_password.length<6) return err(res,'Password too short',400);
    const hash=await bcrypt.hash(new_password,12);
    await pool.query('UPDATE corporate_participants SET password_hash=$1,first_login=FALSE WHERE id=$2',[hash,req.user.id]);
    ok(res,{},'Password changed');
  }catch(e){err(res,e.message);}
});

// Participant: get my courses
app.get('/api/v1/participant/mycourses', auth, requireRole('participant'), async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT c.id,c.name,c.description,c.thumbnail,c.duration,c.avg_rating,c.demo_video_path,c.intro_video,
             c.course_type, c.passing_percentage, c.requires_pass,
             cat.name AS category_name, t.name AS trainer_name, t.expertise AS trainer_expertise, t.bio AS trainer_bio,
             (SELECT COUNT(*) FROM modules WHERE course_id=c.id) AS total_modules,
             (SELECT COUNT(*) FROM participant_progress WHERE participant_id=$1 AND module_id IN (SELECT id FROM modules WHERE course_id=c.id) AND completed=TRUE) AS completed_modules,
             COALESCE((SELECT SUM(time_spent_seconds) FROM participant_progress WHERE participant_id=$1 AND module_id IN (SELECT id FROM modules WHERE course_id=c.id)),0) AS time_spent_seconds,
             (SELECT MAX(st.score_raw) FROM scorm_tracking st JOIN scorm_packages sp ON st.package_id=sp.id JOIN modules m ON sp.module_id=m.id WHERE st.participant_id=$1 AND m.course_id=c.id) AS scorm_score,
             (SELECT MAX(st.score_max) FROM scorm_tracking st JOIN scorm_packages sp ON st.package_id=sp.id JOIN modules m ON sp.module_id=m.id WHERE st.participant_id=$1 AND m.course_id=c.id) AS scorm_score_max,
             COALESCE((SELECT MAX(CASE WHEN st.completion_status IN ('completed','passed') THEN 1 ELSE 0 END) FROM scorm_tracking st JOIN scorm_packages sp ON st.package_id=sp.id JOIN modules m ON sp.module_id=m.id WHERE st.participant_id=$1 AND m.course_id=c.id),0) AS scorm_completed,
             cca.assigned_at
      FROM corporate_course_assignments cca
      JOIN courses c ON cca.course_id=c.id
      LEFT JOIN categories cat ON c.category_id=cat.id
      LEFT JOIN trainers t ON c.linked_trainer_id=t.id
      WHERE cca.participant_id=$1
      ORDER BY cca.assigned_at DESC
    `,[req.user.id]);
    ok(res,r.rows);
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
    ['.zip', '.mp4', '.webm', '.mov'].includes(ext) ? cb(null, true) : cb(new Error('Only ZIP or MP4/Video files allowed'));
  },
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB for large videos
});

// Upload SCORM package or Video
app.post('/api/v1/scorm/upload', auth, requireRole('admin','trainer'), scormUpload.single('scorm'), async (req, res) => {
  try {
    if (!req.file) return err(res, 'No file uploaded', 400);
    const { module_id, package_name, scorm_version, content_type } = req.body;
    const ext = path.extname(req.file.originalname).toLowerCase();
    const isVideo = ['.mp4', '.webm', '.mov'].includes(ext);
    const cType = isVideo ? 'video' : (content_type || 'scorm');
    const pkgName = sanitize(package_name || req.file.originalname.replace(/\.[^.]+$/, ''));
    const version = scorm_version || '1.2';

    if (isVideo) {
      // ── VIDEO UPLOAD: save file directly ──────────────────────────────────
      const r = await pool.query(
        'INSERT INTO scorm_packages(module_id,package_name,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [module_id || null, pkgName, version, '', cType]
      );
      const pkgId = r.rows[0].id;
      const videoDir = path.join(scormDir, String(pkgId));
      if (!fs.existsSync(videoDir)) fs.mkdirSync(videoDir, { recursive: true });
      const filename = 'video' + ext;
      fs.writeFileSync(path.join(videoDir, filename), req.file.buffer);
      const videoPath = '/uploads/scorm/' + pkgId + '/' + filename;
      await pool.query('UPDATE scorm_packages SET upload_path=$1 WHERE id=$2', [videoPath, pkgId]);
      await logAudit(req.user.id, req.user.role, 'VIDEO_UPLOAD', 'scorm_packages', pkgId, 'Uploaded video: '+pkgName, req.ip);
      ok(res, { id:pkgId, package_name:pkgName, launch_url:videoPath, content_type:cType }, 'Video uploaded successfully');
    } else {
      // ── SCORM ZIP UPLOAD: extract and find manifest ────────────────────────
      const r = await pool.query(
        'INSERT INTO scorm_packages(module_id,package_name,scorm_version,upload_path,content_type) VALUES($1,$2,$3,$4,$5) RETURNING id',
        [module_id || null, pkgName, version, '', cType]
      );
      const pkgId = r.rows[0].id;
      const extractPath = path.join(scormDir, String(pkgId));
      extractZip(req.file.buffer, extractPath);
      function findFile(dir, name) {
        for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
          if (f.isDirectory()) { const found = findFile(path.join(dir,f.name),name); if(found) return found; }
          else if (f.name.toLowerCase() === name) return path.join(dir, f.name);
        }
        return null;
      }
      const manifestPath = findFile(extractPath, 'imsmanifest.xml');
      const relManifest = manifestPath ? path.relative(extractPath, manifestPath).replace(/\\/g,'/') : 'imsmanifest.xml';

      // ── Smart launch URL detection ──────────────────────────────────────────
      function findLaunch(dir, manifestFile) {
        // Priority 1: known SCORM entry files in root
        const rootCandidates = [
          'index_lms.html','index_lms.htm',
          'story_html5.html','story.html',
          'index.html','index.htm',
          'launch.html','launch.htm',
          'default.html','default.htm',
          'start.html','start.htm',
          'scorm.html','scorm.htm'
        ];
        for (const c of rootCandidates) {
          if (fs.existsSync(path.join(dir, c))) return c;
        }
        // Priority 2: same directory as imsmanifest.xml
        if (manifestFile) {
          const mDir = path.dirname(manifestFile);
          for (const c of rootCandidates) {
            const full = path.join(mDir, c);
            if (fs.existsSync(full)) return path.relative(dir, full).replace(/\\/g, '/');
          }
        }
        // Priority 3: parse imsmanifest.xml to get href of first resource
        if (manifestFile && fs.existsSync(manifestFile)) {
          try {
            const xml = fs.readFileSync(manifestFile, 'utf8');
            // Find first resource href that ends in .html/.htm
            const match = xml.match(/href=["']([^"']*\.html?)['"]/i);
            if (match) {
              const mDir = path.dirname(manifestFile);
              const full = path.join(mDir, match[1]);
              if (fs.existsSync(full)) return path.relative(dir, full).replace(/\\/g, '/');
              // Try from extractPath root
              const fromRoot = path.join(dir, match[1]);
              if (fs.existsSync(fromRoot)) return match[1].replace(/\\/g, '/');
            }
          } catch(e) { /* ignore */ }
        }
        // Priority 4: find any .html file recursively
        function findAnyHtml(searchDir, depth = 0) {
          if (depth > 4) return null;
          const entries = fs.readdirSync(searchDir, { withFileTypes: true });
          for (const f of entries) {
            if (f.isFile() && /\.(html?|htm)$/i.test(f.name)) {
              return path.relative(dir, path.join(searchDir, f.name)).replace(/\\/g, '/');
            }
          }
          for (const f of entries) {
            if (f.isDirectory()) {
              const found = findAnyHtml(path.join(searchDir, f.name), depth + 1);
              if (found) return found;
            }
          }
          return null;
        }
        return findAnyHtml(dir);
      }

      const launchUrl = findLaunch(extractPath, manifestPath) || relManifest;
      console.log(`[SCORM] Package ${pkgId} launch URL: ${launchUrl}`);
      await pool.query('UPDATE scorm_packages SET manifest_path=$1,upload_path=$2 WHERE id=$3',[relManifest, '/uploads/scorm/'+pkgId+'/'+launchUrl, pkgId]);
      await logAudit(req.user.id, req.user.role, 'SCORM_UPLOAD', 'scorm_packages', pkgId, 'Uploaded SCORM package: '+pkgName, req.ip);
      ok(res, { id:pkgId, package_name:pkgName, launch_url:'/uploads/scorm/'+pkgId+'/'+launchUrl, scorm_version:version, content_type:cType }, 'SCORM package uploaded successfully');
    }
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

// Re-scan SCORM package to fix launch URL
app.post('/api/v1/scorm/packages/:id/rescan', auth, adminOnly, async (req, res) => {
  try {
    const { id } = req.params;
    const r = await pool.query('SELECT * FROM scorm_packages WHERE id=$1', [id]);
    if (!r.rows[0]) return err(res, 'Package not found', 404);
    const pkg = r.rows[0];
    if (pkg.content_type === 'video') return err(res, 'Cannot rescan a video package', 400);
    const extractPath = path.join(scormDir, String(id));
    if (!fs.existsSync(extractPath)) return err(res, 'Extracted files not found on disk', 404);

    // Find imsmanifest.xml
    function findFile(dir, name) {
      const direct = path.join(dir, name);
      if (fs.existsSync(direct)) return direct;
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory()) {
          const found = findFile(path.join(dir, e.name), name);
          if (found) return found;
        }
      }
      return null;
    }
    const manifestPath = findFile(extractPath, 'imsmanifest.xml');
    const relManifest = manifestPath ? path.relative(extractPath, manifestPath).replace(/\\/g, '/') : 'imsmanifest.xml';

    // Smart launch URL detection (same logic as upload)
    function findLaunch(dir, mFile) {
      const candidates = [
        'index_lms.html','index_lms.htm',
        'story_html5.html','story.html',
        'index.html','index.htm',
        'launch.html','launch.htm',
        'default.html','default.htm',
        'start.html','start.htm',
        'scorm.html','scorm.htm'
      ];
      for (const c of candidates) {
        if (fs.existsSync(path.join(dir, c))) return c;
      }
      if (mFile) {
        const mDir = path.dirname(mFile);
        for (const c of candidates) {
          const full = path.join(mDir, c);
          if (fs.existsSync(full)) return path.relative(dir, full).replace(/\\/g, '/');
        }
      }
      if (mFile && fs.existsSync(mFile)) {
        try {
          const xml = fs.readFileSync(mFile, 'utf8');
          const match = xml.match(/href=["']([^"']*\.html?)['"]/i);
          if (match) {
            const mDir = path.dirname(mFile);
            const full = path.join(mDir, match[1]);
            if (fs.existsSync(full)) return path.relative(dir, full).replace(/\\/g, '/');
            const fromRoot = path.join(dir, match[1]);
            if (fs.existsSync(fromRoot)) return match[1].replace(/\\/g, '/');
          }
        } catch(e) { /* ignore */ }
      }
      function findAnyHtml(searchDir, depth = 0) {
        if (depth > 4) return null;
        const entries = fs.readdirSync(searchDir, { withFileTypes: true });
        for (const f of entries) {
          if (f.isFile() && /\.(html?|htm)$/i.test(f.name)) {
            return path.relative(dir, path.join(searchDir, f.name)).replace(/\\/g, '/');
          }
        }
        for (const f of entries) {
          if (f.isDirectory()) {
            const found = findAnyHtml(path.join(searchDir, f.name), depth + 1);
            if (found) return found;
          }
        }
        return null;
      }
      return findAnyHtml(dir);
    }

    const launchUrl = findLaunch(extractPath, manifestPath) || relManifest;
    const newUploadPath = '/uploads/scorm/' + id + '/' + launchUrl;
    console.log(`[RESCAN] Package ${id} -> launch URL: ${launchUrl}`);
    await pool.query('UPDATE scorm_packages SET manifest_path=$1, upload_path=$2 WHERE id=$3', [relManifest, newUploadPath, id]);
    ok(res, { id, launch_url: newUploadPath }, 'Package rescanned successfully. New launch URL: ' + newUploadPath);
  } catch(e) { console.error('Rescan error:', e); err(res, e.message); }
});

// Assign SCORM to module
app.put('/api/v1/scorm/packages/:id/assign', auth, adminOnly, async (req, res) => {
  try {
    const { module_id } = req.body;
    const r = await pool.query('UPDATE scorm_packages SET module_id=$1 WHERE id=$2 RETURNING *',[module_id, req.params.id]);
    ok(res, r.rows[0]);
  } catch(e) { err(res, e.message); }
});

// Get tracking data for current user (student or participant)
app.get('/api/v1/scorm/tracking/:packageId', auth, async (req, res) => {
  try {
    let r;
    if (req.user.role === 'participant') {
      r = await pool.query('SELECT * FROM scorm_tracking WHERE participant_id=$1 AND package_id=$2', [req.user.id, req.params.packageId]);
    } else {
      const studentId = req.user.role === 'student' ? req.user.id : (req.query.student_id || req.user.id);
      r = await pool.query('SELECT * FROM scorm_tracking WHERE student_id=$1 AND package_id=$2', [studentId, req.params.packageId]);
    }
    ok(res, r.rows[0] || { completion_status:'not attempted', score_raw:0, score_max:100, suspend_data:'', total_time:'0000:00:00.00' });
  } catch(e) { err(res, e.message); }
});

// Save tracking data (called by SCORM player on LMSCommit/LMSFinish)
app.post('/api/v1/scorm/tracking', auth, async (req, res) => {
  try {
    const { package_id, completion_status, score_raw, score_max, total_time, suspend_data } = req.body;
    const isCompleted = completion_status === 'passed' || completion_status === 'completed';

    if (req.user.role === 'participant') {
      // ── PARTICIPANT tracking ──────────────────────────────────────────────────
      await pool.query(`INSERT INTO scorm_tracking(participant_id,package_id,completion_status,score_raw,score_max,total_time,suspend_data,last_accessed)
        VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
        ON CONFLICT (participant_id,package_id) WHERE participant_id IS NOT NULL DO UPDATE SET
          completion_status=$3,score_raw=$4,score_max=$5,total_time=$6,suspend_data=$7,last_accessed=NOW()`,
        [req.user.id, package_id, completion_status||'incomplete', score_raw||0, score_max||100, total_time||'0000:00:00.00', suspend_data||'']);

      // Parse CMI total_time (e.g. "0001:23:45.00") into seconds for participant_progress
      const tStr = total_time || '0000:00:00.00';
      const tMatch = tStr.match(/(\d+):(\d+):(\d+)/);
      const timeSeconds = tMatch ? parseInt(tMatch[1])*3600 + parseInt(tMatch[2])*60 + parseInt(tMatch[3]) : 0;

      // Update participant_progress (module-level progress)
      const pkg = await pool.query('SELECT module_id FROM scorm_packages WHERE id=$1',[package_id]);
      if (pkg.rows[0]?.module_id) {
        await pool.query(`
          INSERT INTO participant_progress(participant_id,module_id,completed,completed_at,time_spent_seconds,last_accessed)
          VALUES($1,$2,$3,$4,$5,NOW())
          ON CONFLICT(participant_id,module_id) DO UPDATE SET
            completed = CASE WHEN $3=TRUE THEN TRUE ELSE participant_progress.completed END,
            completed_at = CASE WHEN $3=TRUE AND participant_progress.completed_at IS NULL THEN NOW() ELSE participant_progress.completed_at END,
            time_spent_seconds = GREATEST(participant_progress.time_spent_seconds, $5),
            last_accessed = NOW()`,
          [req.user.id, pkg.rows[0].module_id, isCompleted, isCompleted ? new Date() : null, timeSeconds]);
      }
    } else {
      // ── STUDENT / other tracking ─────────────────────────────────────────────
      const studentId = req.user.role === 'student' ? req.user.id : (req.body.student_id || req.user.id);
      await pool.query(`INSERT INTO scorm_tracking(student_id,package_id,completion_status,score_raw,score_max,total_time,suspend_data,last_accessed)
        VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
        ON CONFLICT(student_id,package_id) DO UPDATE SET
          completion_status=$3,score_raw=$4,score_max=$5,total_time=$6,suspend_data=$7,last_accessed=NOW()`,
        [studentId, package_id, completion_status||'incomplete', score_raw||0, score_max||100, total_time||'0000:00:00.00', suspend_data||'']);
      // Update student_progress on completion
      if (isCompleted) {
        const pkg = await pool.query('SELECT module_id FROM scorm_packages WHERE id=$1',[package_id]);
        if (pkg.rows[0]?.module_id) {
          await pool.query(`INSERT INTO student_progress(student_id,module_id,completed,completed_at) VALUES($1,$2,TRUE,NOW()) ON CONFLICT(student_id,module_id) DO UPDATE SET completed=TRUE,completed_at=NOW()`,[studentId, pkg.rows[0].module_id]);
        }
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
