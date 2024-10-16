const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    body: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    userIds: [
      { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    ],
  },
  { versionKey: false }
);

const Message = mongoose.model('Message', messageSchema);

module.exports = Message;
