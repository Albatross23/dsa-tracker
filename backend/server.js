/**
 * DSA Practice Tracker — Backend Proxy & Secure REST API
 * ----------------------------------------------------
 * Includes:
 * - Public platform proxy endpoints (LeetCode, HackerRank, CodeChef)
 * - Public content API (dynamic question bank & topics)
 * - Role-Based Access Control (RBAC) & Secure Session Tokens (24h expiry)
 * - Password hashing using PBKDF2 (SHA-256)
 * - Admin User Management (add, edit, disable, reset password, force logout, delete)
 * - Admin Question & Topic Management (auto-platform detection, duplicate check, CRUD, bulk import, export)
 * - Trash / Soft-Delete with Restore capabilities
 * - Detailed Audit Logging with before/after diffs
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const cheerio = require("cheerio");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const mongoose = require("mongoose");

const User = require("./models/User");
const Question = require("./models/Question");

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, "data");

// Connect to MongoDB Atlas if MONGODB_URI is provided
let isCloudDbConnected = false;
if (process.env.MONGODB_URI) {
  mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
      isCloudDbConnected = true;
      console.log("Connected to Cloud Database (MongoDB Atlas) successfully.");
    })
    .catch(err => {
      console.warn("MongoDB Atlas connection warning (falling back to local JSON):", err.message);
    });
}

// Helper: Ensure Data Files Exist
function readJsonFile(filename, defaultValue = []) {
  const filePath = path.join(DATA_DIR, filename);
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
      return defaultValue;
    }
    const content = fs.readFileSync(filePath, "utf8");
    return JSON.parse(content);
  } catch (e) {
    console.error(`Error reading ${filename}:`, e);
    return defaultValue;
  }
}

function writeJsonFile(filename, data) {
  const filePath = path.join(DATA_DIR, filename);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

// Password Hashing & Verification
function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, s, 1000, 64, "sha256").toString("hex");
  return { hash, salt: s };
}

function verifyPassword(password, hash, salt) {
  const res = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha256").toString("hex");
  return res === hash;
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex") + "." + (Date.now() + 24 * 60 * 60 * 1000);
}

function isTokenValid(token) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length < 2) return false;
  const expiry = parseInt(parts[1], 10);
  return Date.now() < expiry;
}

// Audit Logger
function logAdminAction(adminUsername, action, target, details = {}, oldValue = null, newValue = null) {
  const logs = readJsonFile("logs.json", []);
  const entry = {
    id: `LOG_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    timestamp: Date.now(),
    admin: adminUsername || "admin",
    action,
    target,
    details,
    oldValue,
    newValue
  };
  logs.unshift(entry);
  writeJsonFile("logs.json", logs.slice(0, 500)); // keep last 500 logs
}

// Auto Platform Detector
function detectPlatform(urlStr) {
  if (!urlStr) return { platform: "OA", slug: "" };
  const raw = urlStr.trim();
  let platform = "OA";
  let slug = "";

  if (raw.includes("leetcode.com")) {
    platform = "LC";
    const match = raw.match(/leetcode\.com\/problems\/([^\/]+)/);
    if (match) slug = match[1];
  } else if (raw.includes("hackerrank.com")) {
    platform = "HR";
  } else if (raw.includes("codeforces.com")) {
    platform = "CF";
  } else if (raw.includes("codechef.com")) {
    platform = "CC";
  } else if (raw.includes("geeksforgeeks.org")) {
    platform = "GFG";
  } else if (raw.includes("atcoder.jp")) {
    platform = "AC";
  } else if (raw.includes("interviewbit.com")) {
    platform = "IB";
  }
  return { platform, slug };
}

// Authentication Middleware
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7) : req.query.token;

  if (!token || !isTokenValid(token)) {
    return res.status(401).json({ status: "error", message: "Unauthorized: Invalid or expired admin session." });
  }

  const users = readJsonFile("users.json", []);
  const adminUser = users.find(u => u.role === "admin" && u.sessionToken === token && u.status === "active");

  if (!adminUser) {
    return res.status(403).json({ status: "error", message: "Forbidden: Admin privileges required." });
  }

  req.adminUser = adminUser;
  next();
}

function requireUser(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7) : req.query.token;

  if (!token || !isTokenValid(token)) {
    return res.status(401).json({ status: "error", message: "Session expired or invalid. Please sign in again." });
  }

  const users = readJsonFile("users.json", []);
  const user = users.find(u => u.sessionToken === token);

  if (!user || user.status === "disabled") {
    return res.status(403).json({ status: "error", message: "Your account has been disabled or session invalidated by Admin." });
  }

  req.currentUser = user;
  next();
}

/* ============================================================
   PUBLIC & USER ENDPOINTS
   ============================================================ */

// Public Dynamic Content (Question Bank & Topics)
app.get("/api/content", (req, res) => {
  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  const activeQuestions = (store.questions || []).filter(q => !q.deletedAt);

  // Group questions by topic code
  const problemsObj = {};
  (store.modules || []).forEach(m => {
    (m.topics || []).forEach(tName => {
      // Find matching questions
      const items = activeQuestions.filter(q => q.topic === tName || q.topicCode === tName);
      problemsObj[tName] = {
        name: tName,
        items: items.map(q => ({
          id: q.id,
          t: q.title,
          d: q.difficulty,
          p: q.platform,
          u: q.slug || q.url
        }))
      };
    });
  });

  res.json({
    status: "success",
    modules: store.modules || [],
    questions: activeQuestions,
    grouped: problemsObj,
    updatedAt: store.updatedAt || Date.now()
  });
});

// Admin Authentication
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ status: "error", message: "Username and password are required." });
  }

  const users = readJsonFile("users.json", []);
  const adminUser = users.find(u => u.username === username && u.role === "admin");

  if (!adminUser || !verifyPassword(password, adminUser.passwordHash, adminUser.salt)) {
    return res.status(401).json({ status: "error", message: "Invalid admin username or password." });
  }

  if (adminUser.status === "disabled") {
    return res.status(403).json({ status: "error", message: "This admin account is disabled." });
  }

  const token = generateToken();
  adminUser.sessionToken = token;
  adminUser.lastLogin = Date.now();
  writeJsonFile("users.json", users);

  logAdminAction(adminUser.username, "ADMIN_LOGIN", adminUser.username, { ip: req.ip });

  res.json({
    status: "success",
    token,
    user: {
      id: adminUser.id,
      name: adminUser.name,
      username: adminUser.username,
      role: adminUser.role
    }
  });
});

// User Authentication
app.post("/api/user/login", (req, res) => {
  const { email, name, batch, leetcode, hackerrank, codechef } = req.body;
  if (!email) {
    return res.status(400).json({ status: "error", message: "Email ID is required." });
  }

  const users = readJsonFile("users.json", []);
  let user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (user && user.status === "disabled") {
    return res.status(403).json({ status: "error", message: "Your account has been disabled by Admin." });
  }

  const token = generateToken();

  if (user) {
    user.name = name || user.name;
    user.batch = batch || user.batch;
    if (leetcode) user.leetcode = leetcode;
    if (hackerrank) user.hackerrank = hackerrank;
    if (codechef) user.codechef = codechef;
    user.sessionToken = token;
    user.lastLogin = Date.now();
  } else {
    user = {
      id: `USR_${Date.now()}`,
      name: name || email.split("@")[0],
      email: email.toLowerCase(),
      username: email.split("@")[0],
      role: "user",
      status: "active",
      batch: batch || "BCA24",
      leetcode: leetcode || "",
      hackerrank: hackerrank || "",
      codechef: codechef || "",
      solved: [],
      createdAt: Date.now(),
      lastLogin: Date.now(),
      sessionToken: token
    };
    users.push(user);
  }

  writeJsonFile("users.json", users);

  res.json({
    status: "success",
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      batch: user.batch,
      leetcode: user.leetcode,
      hackerrank: user.hackerrank,
      codechef: user.codechef,
      solved: user.solved || [],
      lcStats: user.lcStats || null,
      hrStats: user.hrStats || null,
      ccStats: user.ccStats || null,
      lastSync: user.lastSync || null
    }
  });
});

// Get Current User Profile (Session validation on refresh)
app.get("/api/user/me", requireUser, (req, res) => {
  const u = req.currentUser;
  res.json({
    status: "success",
    user: {
      id: u.id,
      name: u.name,
      email: u.email,
      batch: u.batch,
      leetcode: u.leetcode || "",
      hackerrank: u.hackerrank || "",
      codechef: u.codechef || "",
      solved: u.solved || [],
      bookmarks: u.bookmarks || [],
      notes: u.notes || {},
      recentActivity: u.recentActivity || [],
      streak: u.streak || 1,
      lcStats: u.lcStats || null,
      hrStats: u.hrStats || null,
      ccStats: u.ccStats || null,
      lastSync: u.lastSync || null
    }
  });
});

// Update User Progress & Solved List
app.put("/api/user/progress", requireUser, (req, res) => {
  const { solved, bookmarks, notes, recentActivity, streak, lcStats, hrStats, ccStats, lastSync } = req.body;
  const users = readJsonFile("users.json", []);
  const uIndex = users.findIndex(x => x.id === req.currentUser.id);

  if (uIndex === -1) {
    return res.status(404).json({ status: "error", message: "User profile not found." });
  }

  const u = users[uIndex];
  if (Array.isArray(solved)) u.solved = solved;
  if (Array.isArray(bookmarks)) u.bookmarks = bookmarks;
  if (notes && typeof notes === "object") u.notes = notes;
  if (Array.isArray(recentActivity)) u.recentActivity = recentActivity;
  if (streak !== undefined) u.streak = streak;
  if (lcStats !== undefined) u.lcStats = lcStats;
  if (hrStats !== undefined) u.hrStats = hrStats;
  if (ccStats !== undefined) u.ccStats = ccStats;
  if (lastSync) u.lastSync = lastSync;

  users[uIndex] = u;
  writeJsonFile("users.json", users);

  res.json({
    status: "success",
    message: "User progress updated successfully.",
    user: {
      id: u.id,
      solved: u.solved,
      bookmarks: u.bookmarks,
      notes: u.notes,
      recentActivity: u.recentActivity,
      streak: u.streak,
      lcStats: u.lcStats,
      hrStats: u.hrStats,
      ccStats: u.ccStats,
      lastSync: u.lastSync
    }
  });
});

// Toggle Solved Status of a Specific Problem
app.post("/api/user/toggle-solved", requireUser, (req, res) => {
  const { problemId } = req.body;
  if (!problemId) return res.status(400).json({ status: "error", message: "problemId is required." });

  const users = readJsonFile("users.json", []);
  const uIndex = users.findIndex(x => x.id === req.currentUser.id);
  if (uIndex === -1) return res.status(404).json({ status: "error", message: "User profile not found." });

  const u = users[uIndex];
  let solved = new Set(u.solved || []);

  if (solved.has(problemId)) {
    solved.delete(problemId);
  } else {
    solved.add(problemId);
  }

  u.solved = Array.from(solved);
  users[uIndex] = u;
  writeJsonFile("users.json", users);

  res.json({
    status: "success",
    solved: u.solved,
    isSolved: solved.has(problemId)
  });
});

// Public Student Leaderboard
app.get("/api/leaderboard", (req, res) => {
  const users = readJsonFile("users.json", []);
  const testKeywords = ["aditi", "test", "demo", "sample", "dummy"];

  const leaderboard = users
    .filter(u => {
      if (u.role === "admin" || u.status === "disabled") return false;
      const nameLower = (u.name || "").toLowerCase();
      const emailLower = (u.email || "").toLowerCase();
      if (testKeywords.some(k => nameLower.includes(k) || emailLower.includes(k))) return false;
      return true;
    })
    .map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      batch: u.batch || "BCA24",
      solvedCount: (u.solved || []).length,
      lcSolved: u.lcStats ? u.lcStats.totalSolved : 0,
      hrSolved: u.hrStats ? u.hrStats.totalSolved : 0,
      ccSolved: u.ccStats ? u.ccStats.totalSolved : 0,
      lastLogin: u.lastLogin || u.createdAt
    }))
    .sort((a, b) => b.solvedCount - a.solvedCount || b.lcSolved - a.lcSolved);

  res.json({
    status: "success",
    leaderboard
  });
});

/* ============================================================
   ADMIN USER MANAGEMENT ENDPOINTS
   ============================================================ */

// List Users
app.get("/api/admin/users", requireAdmin, (req, res) => {
  const users = readJsonFile("users.json", []);
  const safeUsers = users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email,
    username: u.username,
    role: u.role,
    status: u.status,
    batch: u.batch,
    leetcode: u.leetcode || "",
    hackerrank: u.hackerrank || "",
    codechef: u.codechef || "",
    solvedCount: (u.solved || []).length,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin,
    isOnline: isTokenValid(u.sessionToken)
  }));
  res.json({ status: "success", users: safeUsers });
});

// Add User
app.post("/api/admin/users", requireAdmin, (req, res) => {
  const { name, email, role, batch, leetcode, hackerrank, codechef, password } = req.body;
  if (!email || !name) {
    return res.status(400).json({ status: "error", message: "Name and email are required." });
  }

  const users = readJsonFile("users.json", []);
  if (users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(400).json({ status: "error", message: "A user with this email already exists." });
  }

  const pass = password || "user123";
  const passData = hashPassword(pass);

  const newUser = {
    id: `USR_${Date.now()}`,
    name,
    email: email.toLowerCase(),
    username: email.split("@")[0],
    passwordHash: passData.hash,
    salt: passData.salt,
    role: role || "user",
    status: "active",
    batch: batch || "BCA24",
    leetcode: leetcode || "",
    hackerrank: hackerrank || "",
    codechef: codechef || "",
    solved: [],
    createdAt: Date.now(),
    lastLogin: null,
    sessionToken: null
  };

  users.push(newUser);
  writeJsonFile("users.json", users);

  logAdminAction(req.adminUser.username, "CREATE_USER", newUser.email, { name, role });
  res.json({ status: "success", message: "User created successfully.", user: newUser });
});

// Toggle User Status (Active / Disabled)
app.put("/api/admin/users/:id/status", requireAdmin, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!["active", "disabled"].includes(status)) {
    return res.status(400).json({ status: "error", message: "Status must be 'active' or 'disabled'." });
  }

  const users = readJsonFile("users.json", []);
  const user = users.find(u => u.id === id);
  if (!user) {
    return res.status(404).json({ status: "error", message: "User not found." });
  }

  const oldStatus = user.status;
  user.status = status;
  if (status === "disabled") {
    user.sessionToken = null; // force logout if disabled
  }
  writeJsonFile("users.json", users);

  logAdminAction(req.adminUser.username, "CHANGE_USER_STATUS", user.email, {}, { status: oldStatus }, { status });
  res.json({ status: "success", message: `User status changed to ${status}.`, user });
});

// Force Logout User
app.post("/api/admin/users/:id/force-logout", requireAdmin, (req, res) => {
  const { id } = req.params;
  const users = readJsonFile("users.json", []);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ status: "error", message: "User not found." });

  user.sessionToken = null;
  writeJsonFile("users.json", users);

  logAdminAction(req.adminUser.username, "FORCE_LOGOUT", user.email);
  res.json({ status: "success", message: `Active session for ${user.email} invalidated.` });
});

// Reset User Password
app.post("/api/admin/users/:id/reset-password", requireAdmin, (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ status: "error", message: "Password must be at least 4 characters long." });
  }

  const users = readJsonFile("users.json", []);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ status: "error", message: "User not found." });

  const passData = hashPassword(newPassword);
  user.passwordHash = passData.hash;
  user.salt = passData.salt;
  user.sessionToken = null; // force re-login
  writeJsonFile("users.json", users);

  logAdminAction(req.adminUser.username, "RESET_PASSWORD", user.email);
  res.json({ status: "success", message: `Password for ${user.email} reset successfully.` });
});

// Delete User
app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  let users = readJsonFile("users.json", []);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ status: "error", message: "User not found." });

  if (user.role === "admin") {
    return res.status(400).json({ status: "error", message: "Primary admin account cannot be deleted." });
  }

  // Move user to trash
  const trash = readJsonFile("trash.json", []);
  trash.unshift({
    type: "user",
    item: user,
    deletedAt: Date.now(),
    deletedBy: req.adminUser.username
  });
  writeJsonFile("trash.json", trash);

  users = users.filter(u => u.id !== id);
  writeJsonFile("users.json", users);

  logAdminAction(req.adminUser.username, "DELETE_USER", user.email, { user });
  res.json({ status: "success", message: "User deleted and moved to trash." });
});

/* ============================================================
   ADMIN QUESTION BANK & TOPIC ENDPOINTS
   ============================================================ */

// Add Question (with auto platform detector & duplicate check)
app.post("/api/admin/questions", requireAdmin, (req, res) => {
  const { title, topic, difficulty, url, module } = req.body;
  if (!title || !topic) {
    return res.status(400).json({ status: "error", message: "Question title and topic are required." });
  }

  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  const activeQuestions = store.questions.filter(q => !q.deletedAt);

  const { platform, slug } = detectPlatform(url);

  // Duplicate Check
  if (url) {
    const dupUrl = activeQuestions.find(q => q.url && q.url.trim().toLowerCase() === url.trim().toLowerCase());
    if (dupUrl) {
      return res.status(409).json({ status: "error", message: `Duplicate Question: A problem with this URL already exists ("${dupUrl.title}").` });
    }
  }
  if (slug && platform === "LC") {
    const dupSlug = activeQuestions.find(q => q.slug && q.slug.toLowerCase() === slug.toLowerCase());
    if (dupSlug) {
      return res.status(409).json({ status: "error", message: `Duplicate Question: LeetCode problem with slug "${slug}" already exists ("${dupSlug.title}").` });
    }
  }

  const newQuestion = {
    id: `Q_${Date.now()}_${Math.floor(Math.random() * 100)}`,
    title: title.trim(),
    topic: topic.trim(),
    difficulty: difficulty || "m",
    platform: platform,
    url: url || "",
    slug: slug || "",
    module: module || "m1",
    createdAt: Date.now(),
    deletedAt: null
  };

  store.questions.push(newQuestion);
  store.updatedAt = Date.now();
  writeJsonFile("questions.json", store);

  logAdminAction(req.adminUser.username, "ADD_QUESTION", newQuestion.title, { id: newQuestion.id, topic, platform });
  res.json({ status: "success", message: "Question added successfully.", question: newQuestion });
});

// Update Question
app.put("/api/admin/questions/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const { title, topic, difficulty, url } = req.body;

  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  const qIndex = store.questions.findIndex(q => q.id === id);
  if (qIndex === -1) return res.status(404).json({ status: "error", message: "Question not found." });

  const oldQ = { ...store.questions[qIndex] };
  const { platform, slug } = detectPlatform(url || oldQ.url);

  const newQ = {
    ...oldQ,
    title: title ? title.trim() : oldQ.title,
    topic: topic ? topic.trim() : oldQ.topic,
    difficulty: difficulty || oldQ.difficulty,
    platform: platform,
    url: url !== undefined ? url : oldQ.url,
    slug: slug || oldQ.slug
  };

  store.questions[qIndex] = newQ;
  store.updatedAt = Date.now();
  writeJsonFile("questions.json", store);

  logAdminAction(req.adminUser.username, "EDIT_QUESTION", newQ.title, {}, oldQ, newQ);
  res.json({ status: "success", message: "Question updated successfully.", question: newQ });
});

// Soft Delete Question
app.delete("/api/admin/questions/:id", requireAdmin, (req, res) => {
  const { id } = req.params;
  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  const q = store.questions.find(q => q.id === id);
  if (!q) return res.status(404).json({ status: "error", message: "Question not found." });

  q.deletedAt = Date.now();
  store.updatedAt = Date.now();
  writeJsonFile("questions.json", store);

  // Add to trash
  const trash = readJsonFile("trash.json", []);
  trash.unshift({
    type: "question",
    item: q,
    deletedAt: Date.now(),
    deletedBy: req.adminUser.username
  });
  writeJsonFile("trash.json", trash);

  logAdminAction(req.adminUser.username, "DELETE_QUESTION", q.title, { id });
  res.json({ status: "success", message: "Question moved to trash." });
});

// Add Topic / Section
app.post("/api/admin/topics", requireAdmin, (req, res) => {
  const { name, moduleId } = req.body;
  if (!name || !moduleId) {
    return res.status(400).json({ status: "error", message: "Topic name and Module ID are required." });
  }

  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  const mod = store.modules.find(m => m.id === moduleId);
  if (!mod) return res.status(404).json({ status: "error", message: "Module not found." });

  if (!mod.topics.includes(name)) {
    mod.topics.push(name);
    store.updatedAt = Date.now();
    writeJsonFile("questions.json", store);
  }

  logAdminAction(req.adminUser.username, "ADD_TOPIC", name, { moduleId });
  res.json({ status: "success", message: "Topic added successfully.", modules: store.modules });
});

// Delete Topic & Affected Questions
app.delete("/api/admin/topics/:name", requireAdmin, (req, res) => {
  const topicName = decodeURIComponent(req.params.name);
  const store = readJsonFile("questions.json", { modules: [], questions: [] });

  let affectedCount = 0;
  store.questions.forEach(q => {
    if (q.topic === topicName && !q.deletedAt) {
      q.deletedAt = Date.now();
      affectedCount++;
    }
  });

  store.modules.forEach(m => {
    m.topics = m.topics.filter(t => t !== topicName);
  });

  store.updatedAt = Date.now();
  writeJsonFile("questions.json", store);

  logAdminAction(req.adminUser.username, "DELETE_TOPIC", topicName, { affectedQuestions: affectedCount });
  res.json({ status: "success", message: `Topic "${topicName}" and ${affectedCount} questions moved to trash.` });
});

// Bulk Import Questions (JSON or CSV)
app.post("/api/admin/questions/import", requireAdmin, (req, res) => {
  const { questionsData, format } = req.body;
  if (!questionsData) return res.status(400).json({ status: "error", message: "Import data required." });

  const store = readJsonFile("questions.json", { modules: [], questions: [] });
  let importedItems = [];

  try {
    if (format === "csv") {
      const lines = questionsData.split("\n").filter(Boolean);
      lines.forEach((line, i) => {
        if (i === 0 && line.toLowerCase().includes("title")) return; // header
        const parts = line.split(",");
        if (parts.length >= 2) {
          const title = parts[0].trim();
          const topic = parts[1] ? parts[1].trim() : "General";
          const diff = parts[2] ? parts[2].trim().toLowerCase()[0] : "m";
          const url = parts[3] ? parts[3].trim() : "";
          const { platform, slug } = detectPlatform(url);
          importedItems.push({
            id: `Q_${Date.now()}_${i}`,
            title,
            topic,
            difficulty: ["e", "m", "h"].includes(diff) ? diff : "m",
            platform,
            url,
            slug,
            createdAt: Date.now(),
            deletedAt: null
          });
        }
      });
    } else {
      const parsed = typeof questionsData === "string" ? JSON.parse(questionsData) : questionsData;
      if (Array.isArray(parsed)) {
        parsed.forEach((item, i) => {
          const { platform, slug } = detectPlatform(item.url || item.u);
          importedItems.push({
            id: `Q_${Date.now()}_${i}`,
            title: item.title || item.t || "Untitled",
            topic: item.topic || "General",
            difficulty: item.difficulty || item.d || "m",
            platform: item.platform || platform,
            url: item.url || "",
            slug: item.slug || slug || "",
            createdAt: Date.now(),
            deletedAt: null
          });
        });
      }
    }

    store.questions.push(...importedItems);
    store.updatedAt = Date.now();
    writeJsonFile("questions.json", store);

    logAdminAction(req.adminUser.username, "BULK_IMPORT_QUESTIONS", `${importedItems.length} questions imported`);
    res.json({ status: "success", message: `Successfully imported ${importedItems.length} questions.`, count: importedItems.length });
  } catch (e) {
    res.status(400).json({ status: "error", message: "Failed to parse import data: " + e.message });
  }
});

// Export Backup (Questions, Users, Logs)
app.get("/api/admin/export", requireAdmin, (req, res) => {
  const questions = readJsonFile("questions.json", {});
  const users = readJsonFile("users.json", []).map(u => {
    const copy = { ...u };
    delete copy.passwordHash;
    delete copy.salt;
    delete copy.sessionToken;
    return copy;
  });
  const logs = readJsonFile("logs.json", []);

  res.json({
    status: "success",
    backupTimestamp: Date.now(),
    questions,
    users,
    logs
  });
});

/* ============================================================
   ADMIN TRASH & AUDIT LOG ENDPOINTS
   ============================================================ */

// List Trash Items
app.get("/api/admin/trash", requireAdmin, (req, res) => {
  const trash = readJsonFile("trash.json", []);
  res.json({ status: "success", trash });
});

// Restore Item from Trash
app.post("/api/admin/trash/restore", requireAdmin, (req, res) => {
  const { id, type } = req.body;
  let trash = readJsonFile("trash.json", []);
  const entryIndex = trash.findIndex(t => (t.item && t.item.id === id) || t.id === id);

  if (entryIndex === -1) {
    return res.status(404).json({ status: "error", message: "Item not found in trash." });
  }

  const restored = trash[entryIndex];
  trash.splice(entryIndex, 1);
  writeJsonFile("trash.json", trash);

  if (restored.type === "question" || type === "question") {
    const store = readJsonFile("questions.json", { modules: [], questions: [] });
    const q = store.questions.find(q => q.id === id);
    if (q) {
      q.deletedAt = null;
      store.updatedAt = Date.now();
      writeJsonFile("questions.json", store);
    }
  } else if (restored.type === "user" || type === "user") {
    const users = readJsonFile("users.json", []);
    if (!users.some(u => u.id === restored.item.id)) {
      users.push(restored.item);
      writeJsonFile("users.json", users);
    }
  }

  logAdminAction(req.adminUser.username, "RESTORE_ITEM", restored.item?.title || restored.item?.email || id);
  res.json({ status: "success", message: "Item restored successfully." });
});

// Purge Trash Item
app.delete("/api/admin/trash/purge", requireAdmin, (req, res) => {
  const { id } = req.query;
  let trash = readJsonFile("trash.json", []);
  if (id === "all") {
    writeJsonFile("trash.json", []);
    logAdminAction(req.adminUser.username, "PURGE_TRASH", "All items");
    return res.json({ status: "success", message: "Trash purged completely." });
  }

  trash = trash.filter(t => (t.item && t.item.id !== id) && t.id !== id);
  writeJsonFile("trash.json", trash);

  logAdminAction(req.adminUser.username, "PURGE_TRASH_ITEM", id);
  res.json({ status: "success", message: "Item permanently deleted from trash." });
});

// Get Audit Logs
app.get("/api/admin/logs", requireAdmin, (req, res) => {
  const logs = readJsonFile("logs.json", []);
  res.json({ status: "success", logs });
});

/* ============================================================
   EXISTING PLATFORM PROXY ROUTERS (LeetCode, HackerRank, CodeChef)
   ============================================================ */

app.get("/api/leetcode/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const query = `
      query userSyncData($username: String!) {
        matchedUser(username: $username) {
          username
          submitStatsGlobal {
            acSubmissionNum { difficulty count }
          }
        }
        recentAcSubmissionList(username: $username, limit: 30) {
          title
          titleSlug
          timestamp
        }
      }
    `;
    const response = await fetch("https://leetcode.com/graphql", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Referer: `https://leetcode.com/${username}/`
      },
      body: JSON.stringify({ query, variables: { username } })
    });

    if (!response.ok) return res.status(502).json({ status: "error", message: `LeetCode status ${response.status}` });

    const data = await response.json();
    const matched = data && data.data && data.data.matchedUser;
    if (!matched) return res.status(404).json({ status: "error", message: "LeetCode user not found." });

    const stats = matched.submitStatsGlobal.acSubmissionNum || [];
    const pick = d => (stats.find(s => s.difficulty === d) || {}).count || 0;
    const easySolved = pick("Easy");
    const mediumSolved = pick("Medium");
    const hardSolved = pick("Hard");
    const totalSolved = pick("All") || easySolved + mediumSolved + hardSolved;

    const recent = (data.data.recentAcSubmissionList || []).map(s => ({
      title: s.title,
      slug: s.titleSlug,
      timestamp: s.timestamp
    }));

    res.json({ status: "success", username, totalSolved, easySolved, mediumSolved, hardSolved, recent });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Failed to reach LeetCode.", detail: String(err) });
  }
});

app.get("/api/hackerrank/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const response = await fetch(`https://www.hackerrank.com/rest/hackers/${username}/badges`);
    if (!response.ok) return res.status(404).json({ status: "error", message: "HackerRank user not found." });
    const data = await response.json();
    const badges = (data.models || []).map(b => ({
      track: b.badge_name,
      stars: b.stars,
      solved: b.solved_challenges
    }));
    const totalSolved = badges.reduce((sum, b) => sum + (b.solved || 0), 0);
    res.json({ status: "success", username, totalSolved, badges });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Failed to reach HackerRank.", detail: String(err) });
  }
});

app.get("/api/codechef/:username", async (req, res) => {
  const { username } = req.params;
  try {
    const response = await fetch(`https://www.codechef.com/users/${username}`, {
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
    });
    if (!response.ok) return res.status(404).json({ status: "error", message: "CodeChef user not found." });
    const html = await response.text();
    const $ = cheerio.load(html);

    let totalSolved = 0;
    const sections = [];
    $(".problems-solved .content h5").each((i, el) => {
      const heading = $(el).text().trim();
      const listText = $(el).next("p").text();
      const list = listText.split(",").map(s => s.trim()).filter(Boolean);
      sections.push({ heading, count: list.length });
      totalSolved += list.length;
    });

    const rawRating = $(".rating-number").first().text().trim();
    const rating = rawRating ? rawRating.replace(/[^0-9\?]/g, "") : "927?";
    const ratingHeader = $(".rating-header").text().replace(/\s+/g, " ").trim();
    const ranksText = $(".rating-ranks").text().replace(/\s+/g, " ").trim();

    let stars = $(".rating-star").text().trim() || "⭐ 1-Star";
    let div = "(Div 4)";
    if (ratingHeader.includes("Div")) {
      const match = ratingHeader.match(/\(Div\s*\d+\)/i);
      if (match) div = match[0];
    }
    let highestRating = rating.replace(/[^0-9]/g, "") || "927";
    const hMatch = ratingHeader.match(/Highest Rating\s*(\d+)/i);
    if (hMatch) highestRating = hMatch[1];

    let globalRank = "Inactive";
    let countryRank = "Inactive";
    if (ranksText.includes("Global Rank")) {
      const gMatch = ranksText.match(/Global Rank\s*[:\s]*([\d,]+|Inactive)/i);
      if (gMatch) globalRank = gMatch[1];
    }
    if (ranksText.includes("Country Rank")) {
      const cMatch = ranksText.match(/Country Rank\s*[:\s]*([\d,]+|Inactive)/i);
      if (cMatch) countryRank = cMatch[1];
    }

    res.json({
      status: "success",
      username,
      totalSolved,
      rating,
      stars,
      div,
      highestRating,
      globalRank,
      countryRank,
      sections
    });
  } catch (err) {
    res.status(500).json({ status: "error", message: "Failed to reach CodeChef.", detail: String(err) });
  }
});

app.get("/", (req, res) => {
  res.send("DSA Practice Tracker Backend REST API running.");
});

app.listen(PORT, () => console.log(`DSA Tracker Backend REST API listening on port ${PORT}`));
