const mongoose = require('mongoose');

const Category = require('../models/categeory');

const servicesSchema = new mongoose.Schema({
    cat_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category', 
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    image: {
        type: String,
        required: true,
    },
    price: {
        type: Number,
        required: false,
    },
    status: {
        type: String,
        enum: ['0', '1'],
        default: '0',
    }
}, { timestamps: true });
servicesSchema.index({ cat_id: 1 });

const ServicesModel = mongoose.model('Services', servicesSchema);

module.exports = ServicesModel;
