const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  sender: {
    type: String,
    required: true,
    trim: true
  },
  recipient: {
    type: String,
    required: true,
    trim: true
  },
  fileUrl: {
    type: String,
    required: true
  },
  fileName: {
    type: String,
    required: true
  },
  originalFileName: {
    type: String,
    required: true
  },
  aesKeyHash: {
    type: String,
    required: true
  },
  unlockTime: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('File', fileSchema);
