require('dotenv').config();
const dns = require('dns');
if (dns.setDefaultResultOrder) {
  dns.setDefaultResultOrder('ipv4first');
}
try {
  require('win-ca');
} catch (e) {
  // non-Windows fallback
}
const express      = require('express');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const admin        = require('firebase-admin');
const rateLimit    = require('express-rate-limit');
const helmet       = require('helmet');
const validator    = require('validator');
const multer       = require('multer');
const crypto       = require('crypto');
const fs           = require('fs');
const fsPromises   = require('fs').promises;
const path         = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// Render sits behind a reverse proxy that sets X-Forwarded-For; trust it so
// express-rate-limit (and req.ip) see the real client IP instead of Render's.
app.set('trust proxy', 1);

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
app.use('/images', express.static('images')); // still serves any pre-migration local images
app.use(express.json({ limit: '10kb' })); // Reject oversized bodies

// ═══════════════════════════════════════════════════════════════
//  IMAGE UPLOADS
//  Files are received into memory (not written to local disk) and then
//  uploaded straight to Firebase Storage — see uploadBufferToStorage() below,
//  defined after the Firebase Admin SDK is initialized.
//
//  UPLOAD_DIRS / the /images static route are kept only so any images saved
//  to local disk *before* this migration keep working; nothing new is
//  written there.
const UPLOAD_DIRS = {
  gallery: path.join(__dirname, 'images', 'uploads', 'gallery'),
  blog:    path.join(__dirname, 'images', 'uploads', 'blog'),
};
Object.values(UPLOAD_DIRS).forEach(dir => fs.mkdirSync(dir, { recursive: true }));

const imageFileFilter = (req, file, cb) => {
  if (/^image\/(jpeg|jpg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
  else cb(new Error('Only JPG, PNG, WEBP, or GIF images are allowed.'));
};

// Photo posts: up to 10 images per post + 1 cover image
const galleryUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024, files: 12 },
  fileFilter: imageFileFilter,
});
// Blog posts: single cover image
const blogUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024, files: 1 },
  fileFilter: imageFileFilter,
});

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

// Set FIREBASE_STORAGE_BUCKET in your .env to the exact bucket name shown at
// the top of Firebase Console → Storage (usually <project-id>.appspot.com or
// <project-id>.firebasestorage.app). Falls back to the .appspot.com pattern
// if not set, which is correct for most existing projects.
const storageBucket = process.env.FIREBASE_STORAGE_BUCKET || `${serviceAccount.project_id}.appspot.com`;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket,
});

const db     = admin.firestore();
db.settings({ preferRest: true });
const bucket = admin.storage().bucket();
console.log('✅ Firebase / Firestore connected');
console.log(`✅ Firebase Storage bucket: ${storageBucket}`);

// Uploads a file buffer to Firebase Storage and returns a public download URL
// (the same style of URL Firebase's client SDK getDownloadURL() produces).
// This works even with default/locked-down Storage Security Rules, because
// the Admin SDK write bypasses rules, and the token in the URL is verified
// by Firebase's serving layer rather than by the rules themselves.
async function uploadBufferToStorage(buffer, storagePath, contentType) {
  const token = crypto.randomUUID();
  const file  = bucket.file(storagePath);
  await file.save(buffer, {
    contentType,
    resumable: false,
    metadata: { metadata: { firebaseStorageDownloadTokens: token } },
  });
  return `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(storagePath)}?alt=media&token=${token}`;
}

// Deletes an image asset given whatever was stored as its "filename":
//   - a Firebase Storage path (contains a "/", e.g. "gallery/172939...-4821.jpg") → delete from the bucket
//   - a bare local filename (pre-migration data, e.g. "gallery-172939...-4821.jpg") → delete from local disk
// Errors (already-deleted, not-found, etc.) are swallowed — deletion is best-effort cleanup.
async function deleteImageAsset(storedFilename) {
  if (!storedFilename) return;
  if (storedFilename.includes('/')) {
    await bucket.file(storedFilename).delete().catch(() => {});
  } else {
    await fsPromises.unlink(path.join(UPLOAD_DIRS.gallery, storedFilename)).catch(() => {});
    await fsPromises.unlink(path.join(UPLOAD_DIRS.blog, storedFilename)).catch(() => {});
  }
}

// ═══════════════════════════════════════════════════════════════
//  PHOTO / BLOG POST SHARED CONFIG

// How many published posts show on the live site before the oldest rolls off.
// (Older posts stay saved in the admin panel — they're just hidden from the public site.)
const GALLERY_DISPLAY_LIMIT = 8;
const BLOG_DISPLAY_LIMIT    = 4;

// Fixed gallery categories (must match the filter buttons in index.html)
const GALLERY_CATEGORY_META = {
  Travel:   { icon: 'fa-plane',  bg: 'linear-gradient(135deg,#e8e4c4,#c9c38d)' },
  Nature:   { icon: 'fa-leaf',   bg: 'linear-gradient(135deg,#c4e8e4,#8dc9c3)' },
  Portrait: { icon: 'fa-user',   bg: 'linear-gradient(135deg,#c4d8e8,#8dafc9)' },
  Urban:    { icon: 'fa-city',   bg: 'linear-gradient(135deg,#d4e8c4,#9dc98d)' },
};
const BLOG_ICON_POOL = ['fa-pen-nib', 'fa-camera', 'fa-book-open', 'fa-lightbulb', 'fa-feather-pointed'];
const BLOG_BG_POOL = [
  'linear-gradient(135deg,#f5e6d3,#e8c9a0)',
  'linear-gradient(135deg,#d3e6f5,#a0c9e8)',
  'linear-gradient(135deg,#e6d3f5,#c9a0e8)',
  'linear-gradient(135deg,#d3f5e0,#a0e8c0)',
];

function tsToIso(ts) {
  if (!ts) return null;
  return ts.toDate ? ts.toDate().toISOString() : ts;
}

function pickRandom(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

// In-memory cache for public gallery items and blog posts
let cacheGalleryItems = null;
let cacheBlogPosts = null;
let cacheAdminGalleryItems = null;
let cacheAdminBlogPosts = null;

async function getCachedGalleryItems() {
  if (cacheGalleryItems) return cacheGalleryItems;
  const snap = await db.collection('gallery_items')
    .where('status', '==', 'published')
    .get();
  const items = snap.docs.map(doc => {
    const d = doc.data();
    const meta = GALLERY_CATEGORY_META[d.category] || GALLERY_CATEGORY_META.Travel;
    const created = d.createdAt?.toDate ? d.createdAt.toDate() : new Date();
    return {
      id: doc.id,
      title: d.title,
      category: d.category,
      filterKey: (d.category || 'Travel').toLowerCase(),
      layout: d.layout || 'normal',
      images: (d.images || []).map(im => im.url),
      pinterestUrl: d.pinterestUrl || '',
      icon: meta.icon,
      bg: meta.bg,
      createdTime: created.getTime(),
      views: d.views || 0,
      likes: d.likes || 0,
      coverImage: d.coverImage || '',
    };
  });
  items.sort((a, b) => b.createdTime - a.createdTime);
  cacheGalleryItems = items.slice(0, GALLERY_DISPLAY_LIMIT);
  return cacheGalleryItems;
}

async function getCachedBlogPosts() {
  if (cacheBlogPosts) return cacheBlogPosts;
  const snap = await db.collection('blog_posts')
    .where('status', '==', 'published')
    .get();
  const posts = snap.docs.map(doc => {
    const d = doc.data();
    const created = d.createdAt?.toDate ? d.createdAt.toDate() : new Date();
    return {
      id: doc.id,
      title: d.title,
      tag: d.tag,
      excerpt: d.excerpt,
      content: d.content,
      read: d.read,
      coverImage: d.coverImage || '',
      icon: d.icon || 'fa-pen-nib',
      bg: d.bg || BLOG_BG_POOL[0],
      date: created.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
      createdTime: created.getTime(),
      views: d.views || 0,
      likes: d.likes || 0,
    };
  });
  posts.sort((a, b) => b.createdTime - a.createdTime);
  const limitedPosts = posts.slice(0, BLOG_DISPLAY_LIMIT);
  limitedPosts.forEach((p, i) => {
    p.featured = (i === 0);
  });
  cacheBlogPosts = limitedPosts;
  return cacheBlogPosts;
}

function invalidateGalleryCache() {
  cacheGalleryItems = null;
  cacheAdminGalleryItems = null;
}

function invalidateBlogCache() {
  cacheBlogPosts = null;
  cacheAdminBlogPosts = null;
}

// A "photo" on a Photo Post can come from local disk (uploaded file) OR be a
// direct link to an image hosted on Pinterest. This validates the latter so
// only genuine Pinterest-hosted image URLs are accepted (not just any link).
function isPinterestImageUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol)) return false;
    return /(^|\.)pinimg\.com$/i.test(u.hostname) || /(^|\.)pinterest\.[a-z.]+$/i.test(u.hostname);
  } catch {
    return false;
  }
}

// Records who did what and when — powers the Activity Log tab in the admin panel.
async function logActivity(action, entityType, entityId, entityTitle, actor, details = '') {
  try {
    await db.collection('activity_logs').add({
      action, entityType, entityId, entityTitle,
      actor: actor || 'admin',
      details,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (err) {
    console.error('Activity log error:', err.message);
  }
}

// Flips 'scheduled' posts to 'published' once their publishAt time has passed.
async function publishDuePosts() {
  const now = admin.firestore.Timestamp.now();
  for (const [col, entityType] of [['gallery_items', 'gallery_item'], ['blog_posts', 'blog_post']]) {
    try {
      const snap = await db.collection(col)
        .where('status', '==', 'scheduled')
        .get();
      for (const doc of snap.docs) {
        const data = doc.data();
        if (data.publishAt && data.publishAt.toMillis() <= now.toMillis()) {
          await doc.ref.update({ status: 'published', updatedAt: admin.firestore.FieldValue.serverTimestamp() });
          await logActivity('publish', entityType, doc.id, data.title, 'system', 'Auto-published on schedule');
          if (entityType === 'gallery_item') invalidateGalleryCache();
          if (entityType === 'blog_post') invalidateBlogCache();
          const updatedData = { ...data, status: 'published' };
          triggerAutomaticPostNewsletter(entityType, doc.id, updatedData);
        }
      }
    } catch (err) {
      console.error(`Scheduled publish check failed for ${col}:`, err.message);
    }
  }
}
setInterval(publishDuePosts, 60 * 1000);

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

// ─── Email sending (Resend HTTP API) ───────────────────────────
// Render's free tier blocks outbound SMTP ports (25/465/587), so email is
// sent over Resend's HTTPS API instead of raw SMTP — HTTPS is never blocked.
// Set RESEND_API_KEY (from resend.com) and RESEND_FROM_EMAIL (an address on
// a domain you've verified with Resend) in your environment.
const EMAIL_ENABLED  = !!process.env.RESEND_API_KEY;
const RESEND_FROM    = process.env.RESEND_FROM_EMAIL || 'onboarding@resend.dev';
const OWNER_INBOX    = process.env.OWNER_EMAIL || process.env.GMAIL_USER;

async function sendEmail({ from, to, bcc, replyTo, subject, html, text }) {
  const payload = { from: from || RESEND_FROM, subject };
  if (to)      payload.to       = Array.isArray(to)  ? to  : [to];
  if (bcc)     payload.bcc      = Array.isArray(bcc) ? bcc : [bcc];
  if (replyTo) payload.reply_to = replyTo;
  if (html)    payload.html     = html;
  if (text)    payload.text     = text;

  const resp = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    throw new Error(`Resend API error (${resp.status}): ${errText}`);
  }
  return resp.json();
}

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

    // Send email notification in the background (non-blocking) so that email delivery
    // failures do not block or crash the contact form submission.
    if (EMAIL_ENABLED) {
      sendEmail({
        from:    `"${name} via Blog" <${RESEND_FROM}>`,
        to:      OWNER_INBOX,
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
      }).catch(err => console.error('Contact email notification error (non-blocking):', err.message));
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Contact message database save error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to send message.' });
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
    if (EMAIL_ENABLED) {
      sendEmail({
        from:    `"Chanuka Nimsara" <${RESEND_FROM}>`,
        to:      normalizedEmail,
        subject: '🎉 Welcome to the Sunday Letter!',
        html:    buildWelcomeEmail(normalizedEmail),
      }).catch(err => console.error('Welcome email failed:', err.message));

      sendEmail({
        from:    RESEND_FROM,
        to:      OWNER_INBOX,
        subject: '📬 New Newsletter Subscriber',
        text:    `New subscriber: ${normalizedEmail}`,
      }).catch(err => console.error('Admin notify email failed:', err.message));
    } else {
      console.log(`ℹ️  New subscriber saved: ${normalizedEmail} (email not sent — RESEND_API_KEY not configured)`);
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
      await sendEmail({
        from:    `"Chanuka Nimsara" <${RESEND_FROM}>`,
        to:      OWNER_INBOX,
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
      await sendEmail({
        from:    `"Chanuka Nimsara" <${RESEND_FROM}>`,
        to:      OWNER_INBOX,
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

async function triggerAutomaticPostNewsletter(entityType, docId, data) {
  if (data.status !== 'published') return;
  if (data.newsletterSent) return;

  const docRef = db.collection(entityType === 'blog_post' ? 'blog_posts' : 'gallery_items').doc(docId);
  const doc = await docRef.get();
  if (!doc.exists || doc.data().newsletterSent) return;

  try {
    const snapshot = await db.collection('subscribers').get();
    if (snapshot.empty) {
      await docRef.update({ newsletterSent: true });
      return;
    }

    const emails = snapshot.docs.map(doc => doc.data().email);
    
    let subject = '';
    let previewText = '';
    let heading = '';
    let body = '';
    let ctaText = '';
    let ctaUrl = '';

    if (entityType === 'blog_post') {
      subject = `New Blog Post: ${data.title}`;
      previewText = `Read my latest blog post: "${data.title}"`;
      heading = `New Blog Post Published!`;
      body = `${data.excerpt || (data.content ? data.content.slice(0, 150) + '...' : '')}`;
      ctaText = `Read Post`;
      ctaUrl = `http://localhost:3000/#blog`;
    } else {
      subject = `New Photo Post: ${data.title}`;
      previewText = `Check out my new photo post: "${data.title}"`;
      heading = `New Photos Uploaded!`;
      body = `Category: ${data.category || 'Travel'}.\n\n${data.description || 'Take a look at my new photos on the website.'}`;
      ctaText = `View Gallery`;
      ctaUrl = `http://localhost:3000/#gallery`;
    }

    const html = buildNewsletterHTML({ subject, previewText, heading, body, ctaText, ctaUrl });

    const BATCH = 50;
    let sent = 0;
    for (let i = 0; i < emails.length; i += BATCH) {
      const batch = emails.slice(i, i + BATCH);
      await sendEmail({
        from:    `"Chanuka Nimsara" <${RESEND_FROM}>`,
        to:      OWNER_INBOX,
        bcc:     batch,
        subject,
        html,
      });
      sent += batch.length;
    }

    // Save newsletter history
    await db.collection('newsletters').add({
      subject,
      preview_text:  previewText,
      heading,
      body,
      cta_text:      ctaText,
      cta_url:       ctaUrl,
      total_recipients: emails.length,
      sent_count:    sent,
      sent_by:       'system',
      sent_at:       admin.firestore.Timestamp.now(),
    });

    // Mark as sent
    await docRef.update({ newsletterSent: true });
    console.log(`Automatic newsletter sent for ${entityType} ${docId}`);
  } catch (err) {
    console.error(`Automatic newsletter send failed for ${entityType} ${docId}:`, err.message);
  }
}

// ═══════════════════════════════════════════════════════════════
//  PHOTO POSTS  (gallery_items)
// ═══════════════════════════════════════════════════════════════

function serializeGalleryItem(doc) {
  const d = doc.data();
  return {
    id: doc.id,
    title: d.title || '',
    category: d.category || 'Travel',
    layout: d.layout || 'normal',
    // Normalize older records (saved before mixed sources existed) to source: 'upload'
    images: (d.images || []).map(im => ({
      url: im.url,
      filename: im.filename || null,
      source: im.source || 'upload',
    })),
    description: d.description || '',
    tags: d.tags || [],
    pinterestUrl: d.pinterestUrl || '',
    status: d.status || 'draft',
    publishAt: tsToIso(d.publishAt),
    createdAt: tsToIso(d.createdAt),
    updatedAt: tsToIso(d.updatedAt),
    views: d.views || 0,
    coverImage: d.coverImage || '',
    coverImagePath: d.coverImagePath || '',
    createdBy: d.createdBy || 'admin',
    updatedBy: d.updatedBy || d.createdBy || 'admin',
  };
}

async function getCachedAdminGalleryItems() {
  if (cacheAdminGalleryItems) return cacheAdminGalleryItems;
  const snap = await db.collection('gallery_items').orderBy('createdAt', 'desc').get();
  cacheAdminGalleryItems = snap.docs.map(serializeGalleryItem);
  return cacheAdminGalleryItems;
}

// List ALL photo posts (any status) for the admin panel. Search/filter/sort
// happens client-side in admin.html against this full list.
app.get('/admin/gallery-items', authMiddleware, async (req, res) => {
  try {
    const items = await getCachedAdminGalleryItems();
    res.json({ success: true, items, total: items.length });
  } catch (err) {
    console.error('List gallery items error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load photo posts.' });
  }
});

// Create a photo post — multipart form. Photos can be uploaded files and/or
// direct Pinterest image links, mixed freely, up to 10 total. `imageOrder`
// describes the final ordering the admin composed in the UI.
app.post('/admin/gallery-items', authMiddleware, galleryUpload.fields([{ name: 'images', maxCount: 10 }, { name: 'coverImage', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, category, layout, description, tags, pinterestUrl, status, publishAt, imageOrder } = req.body;
    if (!title || !title.trim())
      return res.status(400).json({ success: false, error: 'Title is required.' });

    const imageFiles = req.files && req.files['images'] ? req.files['images'] : [];
    const coverFile = req.files && req.files['coverImage'] ? req.files['coverImage'][0] : null;

    const uploadedFiles = [];
    for (const f of imageFiles) {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(f.originalname).toLowerCase() || '.jpg';
      const storagePath = `gallery/${unique}${ext}`;
      const url = await uploadBufferToStorage(f.buffer, storagePath, f.mimetype);
      uploadedFiles.push({ url, filename: storagePath, source: 'upload' });
    }

    let images = [];
    if (imageOrder) {
      let order = [];
      try { order = JSON.parse(imageOrder); } catch { order = []; }
      let uploadIdx = 0;
      for (const token of order) {
        if (!token) continue;
        if (token.type === 'new') {
          if (uploadedFiles[uploadIdx]) images.push(uploadedFiles[uploadIdx]);
          uploadIdx++;
        } else if (token.type === 'pinterest' && isPinterestImageUrl(token.url)) {
          images.push({ url: token.url, filename: null, source: 'pinterest' });
        }
      }
      if (uploadIdx < uploadedFiles.length) images = images.concat(uploadedFiles.slice(uploadIdx));
    } else {
      images = uploadedFiles;
    }

    let coverImage = '';
    let coverImagePath = '';
    if (coverFile) {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(coverFile.originalname).toLowerCase() || '.jpg';
      coverImagePath = `gallery/${unique}_cover${ext}`;
      coverImage = await uploadBufferToStorage(coverFile.buffer, coverImagePath, coverFile.mimetype);
    } else if (images.length > 0) {
      coverImage = images[0].url;
      coverImagePath = images[0].filename || '';
    }

    if (images.length === 0 && !coverImage)
      return res.status(400).json({ success: false, error: 'At least one photo or cover photo is required.' });
    if (images.length > 10)
      return res.status(400).json({ success: false, error: 'Max 10 images per photo post.' });

    const finalStatus = status === 'scheduled' && publishAt ? 'scheduled' : (status === 'published' ? 'published' : 'draft');
    const actor = req.admin?.username || 'admin';

    const docRef = await db.collection('gallery_items').add({
      title: title.trim(),
      category: GALLERY_CATEGORY_META[category] ? category : 'Travel',
      layout: ['normal', 'tall', 'wide'].includes(layout) ? layout : 'normal',
      images,
      coverImage,
      coverImagePath,
      description: (description || '').trim(),
      tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      pinterestUrl: pinterestUrl || '',
      status: finalStatus,
      publishAt: finalStatus === 'scheduled' && publishAt ? admin.firestore.Timestamp.fromDate(new Date(publishAt)) : null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      views: 0,
      likes: 0,
      createdBy: actor,
      updatedBy: actor,
    });

    await logActivity('create', 'gallery_item', docRef.id, title.trim(), actor, `Created as ${finalStatus}`);
    invalidateGalleryCache();
    if (finalStatus === 'published') {
      const createdItem = {
        title: title.trim(),
        category,
        description: (description || '').trim(),
        status: finalStatus
      };
      triggerAutomaticPostNewsletter('gallery_item', docRef.id, createdItem);
    }
    res.json({ success: true, id: docRef.id });
  } catch (err) {
    console.error('Create gallery item error:', err.message);
    res.status(500).json({ success: false, error: err.message || 'Failed to create photo post.' });
  }
});

// Edit a photo post — photos can be a mix of uploaded files and Pinterest
// image links. `imageOrder` describes the final composition.
app.put('/admin/gallery-items/:id', authMiddleware, galleryUpload.fields([{ name: 'images', maxCount: 10 }, { name: 'coverImage', maxCount: 1 }]), async (req, res) => {
  try {
    const docRef = db.collection('gallery_items').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'Photo post not found.' });
    const existing = doc.data();
    const actor = req.admin?.username || 'admin';

    const { title, category, layout, description, tags, pinterestUrl, status, publishAt, imageOrder, removeImages, removeCoverImage } = req.body;

    const imageFiles = req.files && req.files['images'] ? req.files['images'] : [];
    const coverFile = req.files && req.files['coverImage'] ? req.files['coverImage'][0] : null;

    const existingImages = existing.images || [];
    const uploadedFiles = [];
    for (const f of imageFiles) {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(f.originalname).toLowerCase() || '.jpg';
      const storagePath = `gallery/${unique}${ext}`;
      const url = await uploadBufferToStorage(f.buffer, storagePath, f.mimetype);
      uploadedFiles.push({ url, filename: storagePath, source: 'upload' });
    }

    let images;
    if (imageOrder) {
      const existingByFilename = {};
      existingImages.forEach(im => { if (im.filename) existingByFilename[im.filename] = im; });

      let order = [];
      try { order = JSON.parse(imageOrder); } catch { order = []; }

      images = [];
      let uploadIdx = 0;
      for (const token of order) {
        if (!token) continue;
        if (token.type === 'existing' && existingByFilename[token.filename]) {
          images.push(existingByFilename[token.filename]);
        } else if (token.type === 'new') {
          if (uploadedFiles[uploadIdx]) images.push(uploadedFiles[uploadIdx]);
          uploadIdx++;
        } else if (token.type === 'pinterest' && isPinterestImageUrl(token.url)) {
          images.push({ url: token.url, filename: null, source: 'pinterest' });
        }
      }
      if (uploadIdx < uploadedFiles.length) images = images.concat(uploadedFiles.slice(uploadIdx));

      // Delete storage assets for any existing images that were dropped from the order.
      const keptFilenames = new Set(images.filter(im => im.filename).map(im => im.filename));
      for (const im of existingImages) {
        if (im.filename && !keptFilenames.has(im.filename)) {
          await deleteImageAsset(im.filename);
        }
      }
    } else {
      images = existingImages;
      if (removeImages) {
        let toRemove = [];
        try { toRemove = JSON.parse(removeImages); } catch { toRemove = []; }
        for (const filename of toRemove) {
          await deleteImageAsset(filename);
        }
        images = images.filter(im => !toRemove.includes(im.filename));
      }
      images = images.concat(uploadedFiles);
    }

    let coverImage = existing.coverImage || '';
    let coverImagePath = existing.coverImagePath || '';

    if (removeCoverImage === 'true' && coverImage) {
      if (coverImagePath && coverImagePath !== coverImage) {
        await deleteImageAsset(coverImagePath);
      }
      coverImage = '';
      coverImagePath = '';
    }

    if (coverFile) {
      if (coverImagePath && coverImagePath !== coverImage) {
        await deleteImageAsset(coverImagePath);
      }
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(coverFile.originalname).toLowerCase() || '.jpg';
      coverImagePath = `gallery/${unique}_cover${ext}`;
      coverImage = await uploadBufferToStorage(coverFile.buffer, coverImagePath, coverFile.mimetype);
    } else if (!coverImage && images.length > 0) {
      coverImage = images[0].url;
      coverImagePath = images[0].filename || '';
    }

    if (images.length === 0 && !coverImage)
      return res.status(400).json({ success: false, error: 'A photo post needs at least one photo or cover photo.' });
    if (images.length > 10)
      return res.status(400).json({ success: false, error: 'Max 10 images per photo post.' });

    const finalStatus = status === 'scheduled' && publishAt ? 'scheduled' : (status === 'published' ? 'published' : (status === 'draft' ? 'draft' : existing.status));

    await docRef.update({
      title: title !== undefined ? title.trim() : existing.title,
      category: category && GALLERY_CATEGORY_META[category] ? category : existing.category,
      layout: layout && ['normal', 'tall', 'wide'].includes(layout) ? layout : existing.layout,
      images,
      coverImage,
      coverImagePath,
      description: description !== undefined ? description.trim() : existing.description,
      tags: tags !== undefined ? tags.split(',').map(t => t.trim()).filter(Boolean) : existing.tags,
      pinterestUrl: pinterestUrl !== undefined ? pinterestUrl : existing.pinterestUrl,
      status: finalStatus,
      publishAt: finalStatus === 'scheduled' && publishAt ? admin.firestore.Timestamp.fromDate(new Date(publishAt)) : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: actor,
    });

    await logActivity('update', 'gallery_item', req.params.id, title || existing.title, actor, `Updated (${finalStatus})`);
    invalidateGalleryCache();
    if (finalStatus === 'published' && !existing.newsletterSent) {
      const updatedItem = {
        title: title !== undefined ? title.trim() : existing.title,
        category: category && GALLERY_CATEGORY_META[category] ? category : existing.category,
        description: description !== undefined ? description.trim() : existing.description,
        status: finalStatus
      };
      triggerAutomaticPostNewsletter('gallery_item', req.params.id, updatedItem);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Update gallery item error:', err.message);
    res.status(500).json({ success: false, error: err.message || 'Update failed.' });
  }
});

// Delete a photo post permanently (and its image files).
app.delete('/admin/gallery-items/:id', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('gallery_items').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'Not found.' });
    const data = doc.data();
    for (const img of (data.images || [])) {
      // Pinterest-linked photos have no asset to clean up.
      await deleteImageAsset(img.filename);
    }
    await docRef.delete();
    await logActivity('delete', 'gallery_item', req.params.id, data.title, req.admin?.username || 'admin', 'Deleted permanently');
    invalidateGalleryCache();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete gallery item error:', err.message);
    res.status(500).json({ success: false, error: 'Delete failed.' });
  }
});

// Public feed — only published posts, newest first, capped at the display limit.
app.get('/api/gallery-items', async (req, res) => {
  try {
    const items = await getCachedGalleryItems();
    res.json({ success: true, items });
  } catch (err) {
    console.error('Public gallery fetch error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load gallery.' });
  }
});

// Public view-counter — fired by the site whenever a visitor opens a photo post.
app.post('/api/gallery-items/:id/view', publicLimiter, async (req, res) => {
  try {
    await db.collection('gallery_items').doc(req.params.id).update({ views: admin.firestore.FieldValue.increment(1) });
    if (cacheGalleryItems) {
      const cached = cacheGalleryItems.find(it => it.id === req.params.id);
      if (cached) cached.views = (cached.views || 0) + 1;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// Public like-counter — fired by the site whenever a visitor likes a photo post.
app.post('/api/gallery-items/:id/like', publicLimiter, async (req, res) => {
  try {
    await db.collection('gallery_items').doc(req.params.id).update({ likes: admin.firestore.FieldValue.increment(1) });
    if (cacheGalleryItems) {
      const cached = cacheGalleryItems.find(it => it.id === req.params.id);
      if (cached) cached.likes = (cached.likes || 0) + 1;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// ═══════════════════════════════════════════════════════════════
//  BLOG POSTS  (blog_posts)
// ═══════════════════════════════════════════════════════════════

function serializeBlogPost(doc) {
  const d = doc.data();
  return {
    id: doc.id,
    title: d.title || '',
    tag: d.tag || 'Life',
    excerpt: d.excerpt || '',
    content: d.content || '',
    read: d.read || '3 min read',
    coverImage: d.coverImage || '',
    icon: d.icon || 'fa-pen-nib',
    bg: d.bg || BLOG_BG_POOL[0],
    tags: d.tags || [],
    status: d.status || 'draft',
    publishAt: tsToIso(d.publishAt),
    createdAt: tsToIso(d.createdAt),
    updatedAt: tsToIso(d.updatedAt),
    views: d.views || 0,
    createdBy: d.createdBy || 'admin',
    updatedBy: d.updatedBy || d.createdBy || 'admin',
  };
}

async function getCachedAdminBlogPosts() {
  if (cacheAdminBlogPosts) return cacheAdminBlogPosts;
  const snap = await db.collection('blog_posts').orderBy('createdAt', 'desc').get();
  cacheAdminBlogPosts = snap.docs.map(serializeBlogPost);
  return cacheAdminBlogPosts;
}

app.get('/admin/blog-posts', authMiddleware, async (req, res) => {
  try {
    const posts = await getCachedAdminBlogPosts();
    res.json({ success: true, posts, total: posts.length });
  } catch (err) {
    console.error('List blog posts error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load blog posts.' });
  }
});

app.post('/admin/blog-posts', authMiddleware, blogUpload.single('coverImage'), async (req, res) => {
  try {
    const { title, tag, excerpt, content, tags, status, publishAt } = req.body;
    if (!title || !title.trim() || !content || !content.trim())
      return res.status(400).json({ success: false, error: 'Title and content are required.' });

    let coverImage = '';
    let coverImagePath = '';
    if (req.file) {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(req.file.originalname).toLowerCase() || '.jpg';
      coverImagePath = `blog/${unique}${ext}`;
      coverImage = await uploadBufferToStorage(req.file.buffer, coverImagePath, req.file.mimetype);
    }
    const wordCount = content.trim().split(/\s+/).length;
    const readTime = Math.max(1, Math.round(wordCount / 200)) + ' min read';
    const finalStatus = status === 'scheduled' && publishAt ? 'scheduled' : (status === 'published' ? 'published' : 'draft');
    const actor = req.admin?.username || 'admin';

    const docRef = await db.collection('blog_posts').add({
      title: title.trim(),
      tag: (tag || 'Life').trim(),
      excerpt: (excerpt || content.trim().slice(0, 160)).trim(),
      content: content.trim(),
      read: readTime,
      coverImage,
      coverImagePath,
      bg: pickRandom(BLOG_BG_POOL),
      icon: pickRandom(BLOG_ICON_POOL),
      tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      status: finalStatus,
      publishAt: finalStatus === 'scheduled' && publishAt ? admin.firestore.Timestamp.fromDate(new Date(publishAt)) : null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      views: 0,
      createdBy: actor,
      updatedBy: actor,
    });

    await logActivity('create', 'blog_post', docRef.id, title.trim(), actor, `Created as ${finalStatus}`);
    invalidateBlogCache();
    if (finalStatus === 'published') {
      const createdPost = {
        title: title.trim(),
        excerpt: (excerpt || content.trim().slice(0, 160)).trim(),
        content: content.trim(),
        status: finalStatus
      };
      triggerAutomaticPostNewsletter('blog_post', docRef.id, createdPost);
    }
    res.json({ success: true, id: docRef.id });
  } catch (err) {
    console.error('Create blog post error:', err.message);
    res.status(500).json({ success: false, error: err.message || 'Failed to create blog post.' });
  }
});

app.put('/admin/blog-posts/:id', authMiddleware, blogUpload.single('coverImage'), async (req, res) => {
  try {
    const docRef = db.collection('blog_posts').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'Blog post not found.' });
    const existing = doc.data();
    const actor = req.admin?.username || 'admin';

    const { title, tag, excerpt, content, tags, status, publishAt, removeCoverImage } = req.body;

    let coverImage = existing.coverImage || '';
    let coverImagePath = existing.coverImagePath || '';
    if (removeCoverImage === 'true' && coverImage) {
      await deleteImageAsset(coverImagePath);
      coverImage = '';
      coverImagePath = '';
    }
    if (req.file) {
      if (coverImage) await deleteImageAsset(coverImagePath);
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      const ext = path.extname(req.file.originalname).toLowerCase() || '.jpg';
      coverImagePath = `blog/${unique}${ext}`;
      coverImage = await uploadBufferToStorage(req.file.buffer, coverImagePath, req.file.mimetype);
    }

    const newContent = content !== undefined ? content.trim() : existing.content;
    const wordCount = newContent.trim().split(/\s+/).length;
    const readTime = Math.max(1, Math.round(wordCount / 200)) + ' min read';
    const finalStatus = status === 'scheduled' && publishAt ? 'scheduled' : (status === 'published' ? 'published' : (status === 'draft' ? 'draft' : existing.status));

    await docRef.update({
      title: title !== undefined ? title.trim() : existing.title,
      tag: tag !== undefined ? tag.trim() : existing.tag,
      excerpt: excerpt !== undefined ? excerpt.trim() : existing.excerpt,
      content: newContent,
      read: readTime,
      coverImage,
      coverImagePath,
      tags: tags !== undefined ? tags.split(',').map(t => t.trim()).filter(Boolean) : existing.tags,
      status: finalStatus,
      publishAt: finalStatus === 'scheduled' && publishAt ? admin.firestore.Timestamp.fromDate(new Date(publishAt)) : null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: actor,
    });

    await logActivity('update', 'blog_post', req.params.id, title || existing.title, actor, `Updated (${finalStatus})`);
    invalidateBlogCache();
    if (finalStatus === 'published' && !existing.newsletterSent) {
      const updatedPost = {
        title: title !== undefined ? title.trim() : existing.title,
        excerpt: excerpt !== undefined ? excerpt.trim() : existing.excerpt,
        content: newContent,
        status: finalStatus
      };
      triggerAutomaticPostNewsletter('blog_post', req.params.id, updatedPost);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Update blog post error:', err.message);
    res.status(500).json({ success: false, error: err.message || 'Update failed.' });
  }
});

app.delete('/admin/blog-posts/:id', authMiddleware, async (req, res) => {
  try {
    const docRef = db.collection('blog_posts').doc(req.params.id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ success: false, error: 'Not found.' });
    const data = doc.data();
    if (data.coverImage) {
      await deleteImageAsset(data.coverImagePath || path.basename(data.coverImage));
    }
    await docRef.delete();
    await logActivity('delete', 'blog_post', req.params.id, data.title, req.admin?.username || 'admin', 'Deleted permanently');
    invalidateBlogCache();
    res.json({ success: true });
  } catch (err) {
    console.error('Delete blog post error:', err.message);
    res.status(500).json({ success: false, error: 'Delete failed.' });
  }
});

// Public feed — only published posts, newest first, capped at the display limit.
app.get('/api/blog-posts', async (req, res) => {
  try {
    const posts = await getCachedBlogPosts();
    res.json({ success: true, posts });
  } catch (err) {
    console.error('Public blog fetch error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load blog posts.' });
  }
});

app.post('/api/blog-posts/:id/view', publicLimiter, async (req, res) => {
  try {
    await db.collection('blog_posts').doc(req.params.id).update({ views: admin.firestore.FieldValue.increment(1) });
    if (cacheBlogPosts) {
      const cached = cacheBlogPosts.find(p => p.id === req.params.id);
      if (cached) cached.views = (cached.views || 0) + 1;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// Public like-counter — fired by the site whenever a visitor likes a blog post.
app.post('/api/blog-posts/:id/like', publicLimiter, async (req, res) => {
  try {
    await db.collection('blog_posts').doc(req.params.id).update({ likes: admin.firestore.FieldValue.increment(1) });
    if (cacheBlogPosts) {
      const cached = cacheBlogPosts.find(p => p.id === req.params.id);
      if (cached) cached.likes = (cached.likes || 0) + 1;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

// ═══════════════════════════════════════════════════════════════
//  ACTIVITY LOG  (who edited what and when, across both modules)
// ═══════════════════════════════════════════════════════════════
app.get('/admin/activity-logs', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 300);
    const snap = await db.collection('activity_logs').orderBy('timestamp', 'desc').limit(limit).get();
    const logs = snap.docs.map(doc => {
      const d = doc.data();
      return {
        id: doc.id,
        action: d.action,
        entityType: d.entityType,
        entityId: d.entityId,
        entityTitle: d.entityTitle,
        actor: d.actor,
        details: d.details || '',
        timestamp: tsToIso(d.timestamp),
      };
    });
    res.json({ success: true, logs, total: logs.length });
  } catch (err) {
    console.error('List activity logs error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to load activity logs.' });
  }
});


// ─── Site Context for Chatbot ─────────────────────────────────────────────────
// Returns live blog posts, gallery items and author info so the AI can answer
// questions about real content on the site.
app.get('/api/site-context', async (req, res) => {
  try {
    // Fetch published blog posts only — drafts/scheduled posts stay out of the chatbot's view.
    const postsSnap = await db.collection('blog_posts')
      .where('status', '==', 'published')
      .get();

    const allPosts = postsSnap.docs.map(doc => {
      const d = doc.data();
      const created = d.createdAt?.toDate ? d.createdAt.toDate() : new Date();
      return {
        title:   d.title   || '',
        tag:     d.tag     || '',
        date:    created.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
        read:    d.read    || '',
        excerpt: d.excerpt || '',
        author:  d.author  || 'Chanuka Nimsara',
        createdTime: created.getTime(),
      };
    });
    // Sort in-memory by createdTime descending and limit to 20
    allPosts.sort((a, b) => b.createdTime - a.createdTime);
    const posts = allPosts.slice(0, 20).map(p => {
      const { createdTime, ...rest } = p;
      return rest;
    });

    // Fetch published gallery items only
    const gallerySnap = await db.collection('gallery_items')
      .where('status', '==', 'published')
      .get();

    const allGallery = gallerySnap.docs.map(doc => {
      const d = doc.data();
      const created = d.createdAt?.toDate ? d.createdAt.toDate() : new Date();
      return {
        title:       d.title       || '',
        category:    d.category    || '',
        description: d.description || '',
        createdTime: created.getTime(),
      };
    });
    // Sort in-memory by createdTime descending and limit to 30
    allGallery.sort((a, b) => b.createdTime - a.createdTime);
    const gallery = allGallery.slice(0, 30).map(g => {
      const { createdTime, ...rest } = g;
      return rest;
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