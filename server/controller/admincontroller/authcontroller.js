const helper = require("../../helper/helper");
let user = require("../../models/users");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const category = require('../../models/categeory');
const SubCategory = require('../../models/services');
const booking = require('../../models/bookings');
const Contact = require('../../models/contacts');

module.exports = {
  dashboard: async (req, res) => {
    try {
      let userCount = await user.countDocuments({ role: 1 });
      let data = await category.countDocuments({});
      let subdata = await SubCategory.countDocuments({});
      let databooking = await booking.countDocuments({});
      let datacontact = await Contact.countDocuments({});

      return helper.success(res, "Dashboard data fetched successfully", {
        userCount,
        data,
        subdata,
        databooking,
        datacontact
      });
    } catch (error) {
      throw error
    }
  },
  apexcharts: async (req, res) => {
    try {
      const currentYear = new Date().getFullYear();
      const data = await Promise.all(
        Array.from({ length: 12 }, async (_, month) => {
          const startOfMonth = new Date(currentYear, month, 1);
          const endOfMonth = new Date(currentYear, month + 1, 0);

          return await user.countDocuments({
            role: { $in: ['1'] },
            createdAt: {
              $gte: startOfMonth,
              $lte: endOfMonth
            }
          });
        })
      );

      const categories = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];


      res.json({
        data,
        categories
      });
    } catch (error) {
      throw error
    }
  },
  login: async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) {
        return helper.error(res, "Email and Password are required");
      }
      const userData = await user.findOne({ email, role: 0 });
      if (!userData) {
        return helper.error(res, "Invalid Email or user not authorized");
      }
      const isPasswordValid = await bcrypt.compare(password, userData.password);
      if (!isPasswordValid) {
        return helper.error(res, "Incorrect Password");
      }
      const secret = process.env.SECRET;
      const token = jwt.sign(
        { id: userData.id, name: userData.name },
        secret,
        { expiresIn: "2h" }
      );
      userData.token = token;
      await userData.save();
      return helper.success(res, "Login successful", { token });
    } catch (error) {
      throw error
    }
  },
  user_list: async (req, res) => {
    try {
      let { page, limit } = req.query;
      page = parseInt(page) || 1;
      limit = parseInt(limit) || 10;
      const skip = (page - 1) * limit;
      const data = await user.find({ role: 1 }).skip(skip).limit(limit);
      const totalUsers = await user.countDocuments({ role: 1 });
  
      return helper.success(res, "All users Detail", {
        data,
        currentPage: page,
        totalPages: Math.ceil(totalUsers / limit),
        totalUsers,
      });
    } catch (error) {
      throw error;
    }
  },
  view: async (req, res) => {
    try {
      let view = await user.findById({ _id: req.params._id });
      return helper.success(res, "data", view);
    } catch (error) {
      throw error
    }
  },
  user_edit: async (req, res) => {
    try {
      if (req.files && req.files.image) {
        let images = await helper.fileUpload(req.files.image);
        req.body.image = images;
      };
      let find_data = await user.findByIdAndUpdate(
        { _id: req.params._id },
        {
          name: req.body.name,
          email: req.body.email,
          address: req.body.address,
          phone_no: req.body.phone_no,
          image: req.body.image,
        },
        {
          new: true
        }
      );
        return helper.success(res, "User update successfully", find_data);
    } catch (error) {
      throw error
    }
  },
  delete_user: async (req, res) => {
    try {
      const { _id } = req.params;
       await user.findByIdAndDelete(_id);
      return helper.success(res, "User Deleted successfully");
    } catch (error) {
      throw error
    }
  },
  profile: async (req, res) => {
    try {
      const userId = req.user._id;
      const find_user = await user.findById(userId).select('name email address phone_no image');
      return res.status(200).json({ message: "Profile fetched successfully", body: find_user });
    } catch (error) {
      throw error
    }
  },
  edit_profile: async (req, res) => {
    try {
      const userId = req.user._id;
      const find_user = await user.findById(userId);
      let imagePath = find_user.image;
      if (req.files && req.files.image) {
        try {
          imagePath = await helper.fileUpload(req.files.image);
        } catch (uploadError) {
          return res.status(500).json({ message: "Failed to upload image" });
        }
      }
      const updatedProfile = await user.findByIdAndUpdate(
        userId,
        {
          name: req.body.name || find_user.name,
          email: req.body.email || find_user.email,
          address: req.body.address || find_user.address,
          phone_no: req.body.phone_no || find_user.phone_no,
          image: imagePath,
        },
        { new: true }
      );
      return res.status(200).json({ message: "Profile updated successfully", body: updatedProfile });
    } catch (error) {
      throw error
    }
  },
  reset_password: async (req, res) => {
  try {
    const { password, newPassword } = req.body;
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return helper.error(res, "No token provided");
    }

    const decoded = jwt.verify(token, process.env.SECRET);
    const userId = decoded.id;

    const find_data = await user.findById(userId);
    if (!find_data) {
      return helper.error(res, "User not found");
    }

    const isPasswordMatch = await bcrypt.compare(password, find_data.password);
    if (!isPasswordMatch) {
      return helper.error(res, "Old password is incorrect");
    }

    const isSameAsOld = await bcrypt.compare(newPassword, find_data.password);
    if (isSameAsOld) {
      return helper.error(res, "New password cannot be the same as the current password");
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await user.findByIdAndUpdate(
      userId,
      { password: hashedNewPassword },
      { new: true }
    );

    return helper.success(res, "Password changed successfully", updatedUser);
  } catch (error) {
    console.error("Error in reset_password:", error);
    return helper.error(res, "Something went wrong");
  }
},

  status: async (req, res) => {
    try {
      const { id, status } = req.body;
      const updatedUser = await user.findByIdAndUpdate(
        id,
        { status },
        { new: true }
      );
      return res.status(200).json({ success: true, message: "User status updated successfully" });
    } catch (error) {
      throw error
    }
  },
  logout: (req, res) => {
    try {
      res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
      throw error
    }
  },
};
