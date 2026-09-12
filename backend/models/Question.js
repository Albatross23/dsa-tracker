const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  title: { type: String, required: true },
  url: { type: String, required: true },
  slug: { type: String, default: "" },
  platform: { type: String, default: "LC" },
  difficulty: { type: String, default: "e" },
  module: { type: String, default: "m1" },
  topic: { type: String, default: "Arrays" },
  topicCode: { type: String, default: "1.1" },
  deletedAt: { type: Number, default: null }
}, { timestamps: true, strict: false });

module.exports = mongoose.model('Question', questionSchema);
