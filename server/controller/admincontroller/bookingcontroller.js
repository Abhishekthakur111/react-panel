const mongoose = require('mongoose');
const { Validator } = require('node-input-validator');
const Booking = require('../../models/bookings');
const User = require('../../models/users');
const Services = require('../../models/services');
const Category = require('../../models/categeory');
const helper = require('../../helper/helper');
const { deletecategeory } = require('./categorycontroller');

const createBooking = async (req, res) => {
    try {
        const validator = new Validator(req.body, {
            user_id: 'required',
            service_id: 'required',
            cat_id: 'required'
        });

        const isValid = await validator.check();
        if (!isValid) {
            return helper.error(res, 'Invalid data', validator.errors);
        }

        const userId = req.body.user_id.trim();
        const serviceId = req.body.service_id.trim();
        const catId = req.body.cat_id.trim();

        const userExists = await User.exists({ _id: userId });
        const serviceExists = await Services.exists({ _id: serviceId });
        const carExists = await Category.exists({ _id: catId });
        const newBooking = await Booking.create({
            user_id: userId,
            booking_code: req.body.booking_code,
            cat_id: catId,
            service_id: serviceId,
            amount: req.body.amount,
            no_of_booking: req.body.no_of_booking,
            description: req.body.description,
            location: req.body.location,
            date: req.body.date,
        });
        return helper.success(res, 'Booking Created Successfully', { data: newBooking });
    } catch (error) {
        throw error
    }
};
const bookinglist = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const totalBookings = await Booking.countDocuments(); 
        const bookings = await Booking.find()
            .populate('user_id')
            .populate('service_id')
            .populate('cat_id')
            .skip(skip) 
            .limit(limit)
            .exec();

        return helper.success(res, "All booking details", {
            data: bookings,
            total: totalBookings,
            page,
            limit,
            totalPages: Math.ceil(totalBookings / limit),
        });
    } catch (error) {
        return helper.error(res, error.message);
    }
};
const bookingView = async (req, res) => {
    try {
        const booking = await Booking.findById(req.params._id)
            .populate("user_id")
            .populate('service_id')
            .populate('cat_id')
            .exec();

        res.status(200).json({
            success: true,
            message: "Booking retrieved successfully",
            body: booking
        });

    } catch (error) {
        throw error
    }
};
const status = async (req, res) => {
    try {
        const { id, status } = req.body;
        const updatebooking = await Booking.findByIdAndUpdate(
            id,
            { status },
            { new: true }
        );
        return res.status(200).json({
            success: true,
            message: "Booking status updated successfully",
            data: updatebooking
        });
    } catch (error) {
      throw error
    }
};
const deletebooking = async (req, res) => {
    try {
        const { _id } = req.params;
        let data = await Booking.findByIdAndDelete(_id);
       return helper.success(res, "Booking deleted successfully");
    } catch (error) {
        throw error
    }
};
module.exports = {
    createBooking,
    bookinglist,
    bookingView,
    status,
    deletebooking,
};
