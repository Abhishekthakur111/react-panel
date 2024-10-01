const mongoose = require('mongoose');

const newCategory = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  image: {
    type: String,
    required: false,
  },
  status: {
    type: String,
    enum: ['0', '1'],
    default: '0',
  }
}, { timestamps: true });

const Category = mongoose.model("Category", newCategory);
module.exports = Category;
