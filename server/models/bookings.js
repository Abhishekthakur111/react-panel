const mongoose = require('mongoose');

const User = require('../models/users'); 
const Services = require('../models/services'); 
const categeory = require('../models/categeory');


const bookingSchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', 
        required: true,
    },
    booking_code: {
        type: String,
        required: true,
    },
    
    service_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Services', 
        required: true,
    },
    cat_id:{
        type:mongoose.Schema.Types.ObjectId,
        ref:'Category',
        required:false,
    },
    amount: {
        type: Number, 
        required: true,
    },
    no_of_booking: {
        type: Number, 
        required: false,
    },
    description: { 
        type: String,
        required: false,
    },
    status: {
        type: String,
        enum: ['0', '1'],
        default: '0',
    },
    location: {
        type: String,
        required: false,
    },
    date: {
        type: Date,
        required: true,
    },
}, { timestamps: true });

const BookingModel = mongoose.model('Booking', bookingSchema); 

module.exports = BookingModel;
