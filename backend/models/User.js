const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  username: { type: String },
  role: { type: String, default: "user" },
  status: { type: String, default: "active" },
  batch: { type: String, default: "BCA24" },
  leetcode: { type: String, default: "" },
  hackerrank: { type: String, default: "" },
  codechef: { type: String, default: "" },
  solved: { type: [String], default: [] },
  bookmarks: { type: [String], default: [] },
  notes: { type: mongoose.Schema.Types.Mixed, default: {} },
  recentActivity: { type: [Object], default: [] },
  streak: { type: Number, default: 1 },
  passwordHash: { type: String },
  salt: { type: String },
  sessionToken: { type: String, index: true },
  createdAt: { type: Number, default: Date.now },
  lastLogin: { type: Number, default: Date.now },
  lastSync: { type: Number, default: Date.now },
  lcStats: { type: Object, default: null },
  hrStats: { type: Object, default: null },
  ccStats: { type: Object, default: null }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
