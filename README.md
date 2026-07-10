# Chanuka Nimsara — Personal Blog & Gallery Platform

An elegant, premium, and fully featured personal website, blog, and photo gallery platform. Powered by **Node.js/Express** on the backend and **Firebase (Firestore & Cloud Storage)** for persistence, this project features an automated newsletter system, real-time interactive statistics, and a secure administrative dashboard.

---

## 1. Key Features

### 1.1 Photo Gallery & Blog
- **Dynamic Capped Feeds**: Public feeds display the freshest content (capped at 8 gallery items and 4 blog posts) while older items automatically roll off to optimize load performance.
- **Flexible Cover Photos**: Choose to specify a custom cover image or let the platform automatically fall back to using the first uploaded photo as the cover.
- **Likes & Views Tracking**: Post views are logged automatically, and visitors can interactive-like posts with instant local storage protection to prevent double votes.

### 1.2 Performance & Network Robustness
- **High-Performance In-Memory Cache**: Feeds are served to public visitors directly from memory (taking `< 1ms`), reducing Firestore reads to nearly zero. The cache automatically invalidates on updates or scheduler publishes.
- **REST-fallback Database Connection**: Configured with `preferRest: true` and IPv4-first DNS resolution to ensure smooth operations even behind restrictive firewalls, proxies, or networks with broken IPv6 routing.

### 1.3 Automated Newsletter Dispatch
- **Automated Sunday Letter**: Newsletter emails are auto-composed and dispatched to all subscribers using a Nodemailer batch sender as soon as a new post is published.
- **History Logs**: Every sent newsletter is logged with subject lines, recipient counts, and timestamps inside the admin panel.

### 1.4 Interactive AI Chatbot
- **Gemini Chat widget**: A responsive floating chat window allows users to interact with a context-aware AI chatbot pre-programmed with background info on the site author.

---

## 2. Tech Stack

- **Backend**: Node.js, Express.js, Multer
- **Database / Cloud**: Firebase Admin SDK (Firestore Database, Firebase Cloud Storage)
- **Email Delivery**: Nodemailer (via Gmail SMTP)
- **Frontend**: Vanilla HTML5, CSS3 (Glassmorphism, custom dark mode, keyframe animations), Modern JavaScript (ES6)

---

## 3. Directory Structure

```text
├── app.js               # Main Express server, APIs, caching, and cron scheduler
├── package.json         # Dependencies and dev scripts
├── public/
│   ├── index.html       # Public portfolio website & chatbot interface
│   ├── admin.html       # Secured administrative dashboard
│   └── admin-login.html # Admin panel authorization page
└── serviceAccountKey.json # Private Firebase credentials (keep secured!)
```

---

## 4. Environment Configuration

Create a `.env` file in the root directory:

```env
PORT=3000
GMAIL_USER=your-email@gmail.com
GMAIL_PASS=your-gmail-app-password
JWT_SECRET=your-jwt-auth-session-secret
FIREBASE_STORAGE_BUCKET=your-project-id.firebasestorage.app
```

---

## 5. Getting Started

### 5.1 Prerequisites
Ensure you have **Node.js (v18+)** installed.

### 5.2 Installation
Clone the repository, navigate to the folder, and install dependencies:
```bash
npm install
```

### 5.3 Firebase Service Key Setup
1. Go to **Firebase Console** → **Project Settings** → **Service Accounts**.
2. Click **Generate new private key** and download the JSON file.
3. Place this JSON file in the project root directory and name it `serviceAccountKey.json`.

### 5.4 Running the Project
Launch the development server using `nodemon`:
```bash
npm run dev
```

The application will be running at:
- **Main Website**: `http://localhost:3000`
- **Admin Dashboard**: `http://localhost:3000/admin-login.html`
