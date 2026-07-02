require('dotenv').config();
const express      = require('express');
const nodemailer   = require('nodemailer');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const admin        = require('firebase-admin');
const rateLimit    = require('express-rate-limit');
const helmet       = require('helmet');
const validator    = require('validator');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ───────────────────────────────────────

// Secure HTTP headers (XSS protection, clickjacking, MIME sniffing, etc.)
app.use(helmet({ contentSecurityPolicy: false }));

// Hide server fingerprint
app.disable('x-powered-by');

// Rate limiter for public submission endpoints
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limiter for login (brute-force protection)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Middleware ────────────────────────────────────────────────
app.use(express.static('public'));
app.use('/images', express.static('images')); // serve root-level images folder
app.use(express.json({ limit: '10kb' })); // Reject oversized bodies

// ═══════════════════════════════════════════════════════════════
//  FIREBASE SETUP

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  // Option B: env variable (JSON string)
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  // Option A: local JSON file
  try {
    serviceAccount = require('./firebase-service-account.json');
  } catch {
    console.error('❌ Firebase service account not found!');
    console.error('   Create firebase-service-account.json or set FIREBASE_SERVICE_ACCOUNT env var.');
    process.exit(1);
  }
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // If using Firebase Storage or Realtime DB, also add:
  // databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`
});

const db = admin.firestore();
console.log('✅ Firebase / Firestore connected');

// ─── Init default admin in Firestore ──────────────────────────
// Runs once on startup; creates admin doc if none exists
async function initAdminUser() {
  const snapshot = await db.collection('admins').limit(1).get();
  if (snapshot.empty) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
    await db.collection('admins').add({
      username:  process.env.ADMIN_USERNAME || 'admin',
      passwordHash: hash,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log('✅ Default admin created — username: admin | password: admin123');
    console.log('   Change ADMIN_USERNAME / ADMIN_PASSWORD in your .env file!');
  }
}

// ─── Gmail Transporter ────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// ─── JWT Middleware ───────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  try {
    const token = header.split(' ')[1];
    req.admin = jwt.verify(token, process.env.JWT_SECRET || 'change_this_secret');
    next();
  } catch {
    res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ═══════════════════════════════════════════════════════════════

// ─── Contact Form ─────────────────────────────────────────────
app.post('/send-message', publicLimiter, async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !subject || !message)
    return res.status(400).json({ success: false, error: 'All fields are required.' });

  // Validate and sanitize inputs
  if (!validator.isEmail(String(email)))
    return res.status(400).json({ success: false, error: 'Invalid email address.' });
  if (String(name).length > 100 || String(subject).length > 200 || String(message).length > 5000)
    return res.status(400).json({ success: false, error: 'Input exceeds allowed length.' });
  const safeName    = validator.escape(String(name).trim());
  const safeSubject = validator.escape(String(subject).trim());
  const safeMessage = validator.escape(String(message).trim());

  try {
    // Save contact message to Firestore
    await db.collection('contacts').add({
      name:    safeName,
      email:   validator.normalizeEmail(String(email)) || String(email).toLowerCase().trim(),
      subject: safeSubject,
      message: safeMessage,
      read: false,
      received_at: admin.firestore.FieldValue.serverTimestamp(),
    });

    await transporter.sendMail({
      from:    `"${name}" <${process.env.GMAIL_USER}>`,
      to:      process.env.GMAIL_USER,
      replyTo: email,
      subject: `[Blog Contact] ${subject}`,
      html: `
        <div style="font-family:sans-serif;max-width:560px;">
          <h2 style="color:#4f46e5;">New message from your blog</h2>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:8px;font-weight:bold;width:90px;">Name</td><td style="padding:8px;">${name}</td></tr>
            <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Email</td><td style="padding:8px;"><a href="mailto:${email}">${email}</a></td></tr>
            <tr><td style="padding:8px;font-weight:bold;">Subject</td><td style="padding:8px;">${subject}</td></tr>
          </table>
          <div style="margin-top:20px;padding:16px;background:#f9f9f9;border-left:4px solid #4f46e5;border-radius:4px;">
            <p style="margin:0;white-space:pre-wrap;">${message}</p>
          </div>
          <p style="margin-top:24px;font-size:12px;color:#999;">Sent via your personal blog contact form.</p>
        </div>
      `,
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Contact email error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to send email.' });
  }
});

// ─── Get Contact Messages (admin) ─────────────────────────────
app.get('/admin/contacts', authMiddleware, async (req, res) => {
  try {
    const snap = await db.collection('contacts')
      .orderBy('received_at', 'desc')
      .get();
    const contacts = snap.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      received_at: doc.data().received_at?.toDate().toISOString() || null,
    }));
    res.json({ success: true, contacts, total: contacts.length, unread: contacts.filter(c => !c.read).length });
  } catch (err) {
    console.error('Get contacts error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch contacts.' });
  }
});

// ─── Mark Contact as Read ──────────────────────────────────────
app.patch('/admin/contacts/:id/read', authMiddleware, async (req, res) => {
  try {
    await db.collection('contacts').doc(req.params.id).update({ read: true });
    res.json({ success: true });
  } catch (err) {
    console.error('Mark read error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to update.' });
  }
});

// ─── Delete Contact Message ────────────────────────────────────
// Archives into 'removed_contacts' first so deleted messages are never silently lost.
app.delete('/admin/contacts/:id', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('contacts').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists)
      return res.status(404).json({ success: false, error: 'Message not found.' });

    const data = doc.data();
    await db.collection('removed_contacts').add({
      name:        data.name,
      email:       data.email,
      subject:     data.subject,
      message:     data.message,
      read:        data.read || false,
      received_at: data.received_at || null,
      removedAt:   admin.firestore.FieldValue.serverTimestamp(),
      removedBy:   req.admin?.username || 'admin',
      originalId:  doc.id,
    });

    await docRef.delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete contact error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete.' });
  }
});

// ─── Get Removed Messages (admin) ─────────────────────────────
app.get('/admin/removed-contacts', authMiddleware, async (req, res) => {
  try {
    const snap = await db.collection('removed_contacts')
      .orderBy('removedAt', 'desc')
      .get();
    const removedContacts = snap.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      received_at: doc.data().received_at?.toDate ? doc.data().received_at.toDate().toISOString() : null,
      removed_at:  doc.data().removedAt?.toDate ? doc.data().removedAt.toDate().toISOString() : new Date().toISOString(),
    }));
    res.json({ success: true, removedContacts, total: removedContacts.length });
  } catch (err) {
    console.error('Get removed contacts error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch removed messages.' });
  }
});

// ─── Restore Removed Message (admin) ──────────────────────────
app.post('/admin/removed-contacts/:id/restore', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('removed_contacts').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists)
      return res.status(404).json({ success: false, error: 'Removed message not found.' });

    const data = doc.data();
    await db.collection('contacts').add({
      name:        data.name,
      email:       data.email,
      subject:     data.subject,
      message:     data.message,
      read:        data.read || false,
      received_at: data.received_at || admin.firestore.FieldValue.serverTimestamp(),
    });

    await docRef.delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Restore contact error:', err.message);
    res.status(500).json({ success: false, error: 'Restore failed.' });
  }
});

// ─── Permanently Delete Removed Message (admin) ───────────────
app.delete('/admin/removed-contacts/:id', authMiddleware, async (req, res) => {
  try {
    await db.collection('removed_contacts').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Permanent delete error:', err.message);
    res.status(500).json({ success: false, error: 'Delete failed.' });
  }
});

// ─── Subscribe ────────────────────────────────────────────────
app.post('/subscribe', publicLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !validator.isEmail(String(email)))
    return res.status(400).json({ success: false, error: 'Valid email required.' });

  const normalizedEmail = email.toLowerCase().trim();

  try {
    // Check for duplicate
    const existing = await db.collection('subscribers')
      .where('email', '==', normalizedEmail)
      .limit(1)
      .get();

    if (!existing.empty) {
      // Already subscribed — return success silently
      return res.json({ success: true });
    }

    // Save to Firestore
    await db.collection('subscribers').add({
      email:        normalizedEmail,
      subscribedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Respond immediately
    res.json({ success: true });

    // Background emails (non-blocking)
    if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
      transporter.sendMail({
        from:    `"Chanuka Nimsara" <${process.env.GMAIL_USER}>`,
        to:      normalizedEmail,
        subject: '🎉 Welcome to the Sunday Letter!',
        html:    buildWelcomeEmail(normalizedEmail),
      }).catch(err => console.error('Welcome email failed:', err.message));

      transporter.sendMail({
        from:    process.env.GMAIL_USER,
        to:      process.env.GMAIL_USER,
        subject: '📬 New Newsletter Subscriber',
        text:    `New subscriber: ${normalizedEmail}`,
      }).catch(err => console.error('Admin notify email failed:', err.message));
    } else {
      console.log(`ℹ️  New subscriber saved: ${normalizedEmail} (email not sent — GMAIL_USER/GMAIL_PASS not configured)`);
    }

  } catch (err) {
    console.error('Subscribe error:', err.message);
    res.status(500).json({ success: false, error: 'Subscription failed.' });
  }
});

// ═══════════════════════════════════════════════════════════════
//  ADMIN AUTH ROUTES
// ═══════════════════════════════════════════════════════════════

app.post('/admin/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password ||
      typeof username !== 'string' || typeof password !== 'string' ||
      username.length > 64 || password.length > 128)
    return res.status(400).json({ success: false, error: 'Username and password required.' });
  const safeUsername = validator.escape(username.trim());

  try {
    const snapshot = await db.collection('admins')
      .where('username', '==', safeUsername)
      .limit(1)
      .get();

    if (snapshot.empty)
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });

    const adminDoc  = snapshot.docs[0];
    const adminData = adminDoc.data();
    const valid     = await bcrypt.compare(password, adminData.passwordHash);

    if (!valid)
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });

    const token = jwt.sign(
      { id: adminDoc.id, username: adminData.username },
      process.env.JWT_SECRET || 'change_this_secret',
      { expiresIn: '8h' }
    );
    res.json({ success: true, token });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
});

// ═══════════════════════════════════════════════════════════════
//  ADMIN PROTECTED ROUTES
// ═══════════════════════════════════════════════════════════════

// Get all subscribers
app.get('/admin/subscribers', authMiddleware, async (req, res) => {
  try {
    const snapshot = await db.collection('subscribers')
      .orderBy('subscribedAt', 'desc')
      .get();

    const subscribers = snapshot.docs.map(doc => ({
      id:           doc.id,
      email:        doc.data().email,
      // Convert Firestore Timestamp → ISO string for frontend compatibility
      subscribed_at: doc.data().subscribedAt
        ? doc.data().subscribedAt.toDate().toISOString()
        : new Date().toISOString(),
    }));

    res.json({ success: true, total: subscribers.length, subscribers });
  } catch (err) {
    console.error('Get subscribers error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch subscribers.' });
  }
});

// Delete subscriber by Firestore document ID — archives them into
// 'removed_subscribers' first so removed users are never silently lost.
app.delete('/admin/subscribers/:id', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('subscribers').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists)
      return res.status(404).json({ success: false, error: 'Subscriber not found.' });

    const data = doc.data();
    await db.collection('removed_subscribers').add({
      email:          data.email,
      subscribedAt:   data.subscribedAt || null,
      removedAt:      admin.firestore.FieldValue.serverTimestamp(),
      removedBy:      req.admin?.username || 'admin',
      originalId:     doc.id,
    });

    await docRef.delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete error:', err.message);
    res.status(500).json({ success: false, error: 'Delete failed.' });
  }
});

// Get all removed subscribers
app.get('/admin/removed-subscribers', authMiddleware, async (req, res) => {
  try {
    const snapshot = await db.collection('removed_subscribers')
      .orderBy('removedAt', 'desc')
      .get();

    const removedSubscribers = snapshot.docs.map(doc => ({
      id:            doc.id,
      email:         doc.data().email,
      subscribed_at: doc.data().subscribedAt ? doc.data().subscribedAt.toDate().toISOString() : null,
      removed_at:    doc.data().removedAt ? doc.data().removedAt.toDate().toISOString() : new Date().toISOString(),
      removed_by:    doc.data().removedBy || 'admin',
    }));

    res.json({ success: true, total: removedSubscribers.length, removedSubscribers });
  } catch (err) {
    console.error('Get removed subscribers error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch removed subscribers.' });
  }
});

// Restore a removed subscriber back into 'subscribers'
app.post('/admin/removed-subscribers/:id/restore', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('removed_subscribers').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists)
      return res.status(404).json({ success: false, error: 'Removed subscriber not found.' });

    const data = doc.data();

    // Don't restore a duplicate if this email already re-subscribed on its own.
    const existing = await db.collection('subscribers')
      .where('email', '==', data.email)
      .limit(1)
      .get();

    if (existing.empty) {
      await db.collection('subscribers').add({
        email:        data.email,
        subscribedAt: data.subscribedAt || admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    await docRef.delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Restore subscriber error:', err.message);
    res.status(500).json({ success: false, error: 'Restore failed.' });
  }
});

// Permanently delete a removed subscriber record
app.delete('/admin/removed-subscribers/:id', authMiddleware, async (req, res) => {
  try {
    await db.collection('removed_subscribers').doc(req.params.id).delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Permanent delete error:', err.message);
    res.status(500).json({ success: false, error: 'Delete failed.' });
  }
});

// Send newsletter to all subscribers
app.post('/admin/send-newsletter', authMiddleware, async (req, res) => {
  const { subject, previewText, heading, body, ctaText, ctaUrl } = req.body;
  if (!subject || !heading || !body)
    return res.status(400).json({ success: false, error: 'subject, heading, and body are required.' });

  try {
    const snapshot = await db.collection('subscribers').get();
    if (snapshot.empty)
      return res.json({ success: false, error: 'No subscribers yet.' });

    const emails = snapshot.docs.map(doc => doc.data().email);
    const html   = buildNewsletterHTML({ subject, previewText, heading, body, ctaText, ctaUrl });

    const BATCH = 50;
    let sent = 0;
    for (let i = 0; i < emails.length; i += BATCH) {
      const batch = emails.slice(i, i + BATCH);
      await transporter.sendMail({
        from:    `"Chanuka Nimsara" <${process.env.GMAIL_USER}>`,
        bcc:     batch,
        subject,
        html,
      });
      sent += batch.length;
    }

    // ── Save newsletter record to Firestore ──────────────────────
    await db.collection('newsletters').add({
      subject,
      preview_text:  previewText  || '',
      heading,
      body,
      cta_text:      ctaText      || '',
      cta_url:       ctaUrl       || '',
      total_recipients: emails.length,
      sent_count:    sent,
      sent_by:       req.admin?.username || 'admin',
      sent_at:       admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, sent });
  } catch (err) {
    console.error('Newsletter error:', err.message);
    res.status(500).json({ success: false, error: 'Newsletter send failed.' });
  }
});

// ─── Get Newsletter History (admin) ───────────────────────────
app.get('/admin/newsletters', authMiddleware, async (req, res) => {
  try {
    const snap = await db.collection('newsletters')
      .orderBy('sent_at', 'desc')
      .get();
    const newsletters = snap.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      sent_at: doc.data().sent_at?.toDate().toISOString() || null,
    }));
    res.json({ success: true, newsletters, total: newsletters.length });
  } catch (err) {
    console.error('Get newsletters error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch newsletter history.' });
  }
});

// ─── Edit Newsletter (admin) ───────────────────────────────────
app.put('/admin/newsletters/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { subject, previewText, heading, body, ctaText, ctaUrl } = req.body;
  if (!subject || !heading || !body)
    return res.status(400).json({ success: false, error: 'subject, heading, and body are required.' });
  try {
    await db.collection('newsletters').doc(id).update({
      subject,
      preview_text: previewText || '',
      heading,
      body,
      cta_text:     ctaText    || '',
      cta_url:      ctaUrl     || '',
      updated_at:   admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Edit newsletter error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to update newsletter.' });
  }
});

// ─── Delete Newsletter (admin) ─────────────────────────────────
app.delete('/admin/newsletters/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    await db.collection('newsletters').doc(id).delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete newsletter error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to delete newsletter.' });
  }
});

// ─── Resend Newsletter (admin) ─────────────────────────────────
app.post('/admin/newsletters/:id/resend', authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const doc = await db.collection('newsletters').doc(id).get();
    if (!doc.exists)
      return res.status(404).json({ success: false, error: 'Newsletter not found.' });
    const n = doc.data();

    const snapshot = await db.collection('subscribers').get();
    if (snapshot.empty)
      return res.json({ success: false, error: 'No subscribers yet.' });

    const emails = snapshot.docs.map(d => d.data().email);
    const html   = buildNewsletterHTML({
      subject:     n.subject,
      previewText: n.preview_text,
      heading:     n.heading,
      body:        n.body,
      ctaText:     n.cta_text,
      ctaUrl:      n.cta_url,
    });

    const BATCH = 50;
    let sent = 0;
    for (let i = 0; i < emails.length; i += BATCH) {
      await transporter.sendMail({
        from:    `"Chanuka Nimsara" <${process.env.GMAIL_USER}>`,
        bcc:     emails.slice(i, i + BATCH),
        subject: n.subject,
        html,
      });
      sent += BATCH < emails.length - i ? BATCH : emails.length - i;
    }

    // Update the resend count and timestamp on the record
    await db.collection('newsletters').doc(id).update({
      sent_count:  admin.firestore.FieldValue.increment(sent),
      last_resent: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ success: true, sent });
  } catch (err) {
    console.error('Resend newsletter error:', err.message);
    res.status(500).json({ success: false, error: 'Newsletter resend failed.' });
  }
});

// ═══════════════════════════════════════════════════════════════
//  EMAIL TEMPLATES
// ═══════════════════════════════════════════════════════════════

function buildWelcomeEmail(email) {
  return `
<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome!</title></head>
<body style="margin:0;padding:0;background:#eef1f5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;padding:40px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="background:#1a1a2e;border-radius:16px 16px 0 0;padding:36px 48px;text-align:center;">
          <h1 style="margin:0;color:#fff;font-size:28px;letter-spacing:2px;">CHANUKA NIMSARA</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,.5);font-size:13px;">The Sunday Letter</p>
        </td></tr>
        <tr><td style="background:#fff;padding:48px;border-radius:0 0 16px 16px;">
          <div style="text-align:center;margin-bottom:32px;">
            <div style="display:inline-block;background:#fde8ee;border-radius:50%;width:72px;height:72px;line-height:72px;font-size:32px;">🎉</div>
          </div>
          <h2 style="margin:0 0 16px;color:#1a1a2e;font-size:24px;font-weight:700;">You're officially in!</h2>
          <p style="margin:0 0 16px;color:#6b7280;font-size:15px;line-height:1.75;">
            Welcome to the Sunday Letter — I'm genuinely thrilled to have you here.
            Every week I share personal stories, links I've been loving, and a glimpse
            behind the lens. No spam, no noise. Just honest words.
          </p>
          <p style="margin:0 0 32px;color:#6b7280;font-size:15px;line-height:1.75;">
            Your first letter arrives this Sunday. Stay curious. ✨
          </p>
          <div style="text-align:center;">
            <a href="${process.env.SITE_URL || 'http://localhost:3000'}"
               style="display:inline-block;background:#e8154a;color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:600;">
              Visit the Blog →
            </a>
          </div>
          <hr style="border:none;border-top:1px solid #f0f0f0;margin:40px 0 24px;">
          <p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;">
            You subscribed with <strong>${email}</strong>.
          </p>
        </td></tr>
      </table>
      <p style="margin:24px 0 0;color:#9ca3af;font-size:12px;text-align:center;">
        © 2026 Chanuka Nimsara · Made with ♥ and a lot of coffee.
      </p>
    </td></tr>
  </table>
</body></html>`;
}

function buildNewsletterHTML({ subject, previewText = '', heading, body, ctaText, ctaUrl }) {
  const escapedBody = body.replace(/\n/g, '<br>');
  const ctaBlock = ctaText && ctaUrl ? `
    <div style="text-align:center;margin:36px 0;">
      <a href="${ctaUrl}"
         style="display:inline-block;background:#e8154a;color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:600;">
        ${ctaText} →
      </a>
    </div>` : '';

  return `
<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${subject}</title>
${previewText ? `<div style="display:none;max-height:0;overflow:hidden;">${previewText}&nbsp;&zwnj;&nbsp;&zwnj;</div>` : ''}
</head>
<body style="margin:0;padding:0;background:#eef1f5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;padding:40px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
        <tr><td style="background:#1a1a2e;border-radius:16px 16px 0 0;padding:36px 48px;">
          <table width="100%"><tr>
            <td><h1 style="margin:0;color:#fff;font-size:22px;letter-spacing:2px;">CHANUKA NIMSARA</h1>
                <p style="margin:4px 0 0;color:rgba(255,255,255,.5);font-size:12px;">The Sunday Letter</p></td>
            <td align="right"><span style="color:rgba(255,255,255,.4);font-size:12px;">${new Date().toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'})}</span></td>
          </tr></table>
        </td></tr>
        <tr><td style="background:#fff;padding:48px;border-radius:0 0 16px 16px;">
          <h2 style="margin:0 0 24px;color:#1a1a2e;font-size:26px;font-weight:700;line-height:1.3;">${heading}</h2>
          <div style="color:#6b7280;font-size:15px;line-height:1.8;">${escapedBody}</div>
          ${ctaBlock}
          <hr style="border:none;border-top:1px solid #f0f0f0;margin:40px 0 24px;">
          <p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;">
            You're receiving this because you subscribed at chanukanimsara.com.
          </p>
        </td></tr>
      </table>
      <p style="margin:24px 0 0;color:#9ca3af;font-size:12px;text-align:center;">
        © 2026 Chanuka Nimsara · Made with ♥ and a lot of coffee.
      </p>
    </td></tr>
  </table>
</body></html>`;
}

// ─── Site Context for Chatbot ─────────────────────────────────────────────────
// Returns live blog posts, gallery items and author info so the AI can answer
// questions about real content on the site.
app.get('/api/site-context', async (req, res) => {
  try {
    // Fetch blog posts
    const postsSnap = await db.collection('blog_posts')
      .orderBy('date', 'desc')
      .limit(20)
      .get();

    const posts = postsSnap.docs.map(doc => {
      const d = doc.data();
      return {
        title:   d.title   || '',
        tag:     d.tag     || '',
        date:    d.date    || '',
        read:    d.read    || '',
        excerpt: d.excerpt || '',
        author:  d.author  || 'Chanuka Nimsara',
      };
    });

    // Fetch gallery items
    const gallerySnap = await db.collection('gallery_items')
      .orderBy('createdAt', 'desc')
      .limit(30)
      .get();

    const gallery = gallerySnap.docs.map(doc => {
      const d = doc.data();
      return {
        title:       d.title       || '',
        category:    d.category    || '',
        description: d.description || '',
      };
    });

    // Fetch author / about info
    const authorSnap = await db.collection('site_info').doc('author').get();
    const author = authorSnap.exists ? authorSnap.data() : {};

    res.json({ success: true, posts, gallery, author });
  } catch (err) {
    console.error('Site context error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load site context.' });
  }
});

// ─── Chatbot — secure server-side proxy (key never leaves the server) ────────
app.post('/api/chat', publicLimiter, async (req, res) => {
  const key = process.env.GROQ_API_KEY || '';
  if (!key)
    return res.status(500).json({ error: 'Chatbot not configured. Set GROQ_API_KEY in .env' });

  const { messages } = req.body;
  if (!Array.isArray(messages) || messages.length === 0)
    return res.status(400).json({ error: 'messages array is required.' });

  try {
    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': 'Bearer ' + key,
      },
      body: JSON.stringify({
        model:      'llama-3.1-8b-instant',
        max_tokens: 512,
        messages,
      }),
    });

    if (!groqRes.ok) {
      const err = await groqRes.text();
      console.error('Groq API error:', groqRes.status, err);
      return res.status(502).json({ error: 'AI service error. Please try again.' });
    }

    const data = await groqRes.json();
    res.json(data);
  } catch (err) {
    console.error('Chat proxy error:', err.message);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// ─── Start Server ─────────────────────────────────────────────
initAdminUser()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Server running at http://localhost:${PORT}`);
      console.log(`🔐 Admin dashboard: http://localhost:${PORT}/admin-login.html`);
    });
  })
  .catch(err => {
    console.error('❌ Startup error:', err.message);
    process.exit(1);
  });