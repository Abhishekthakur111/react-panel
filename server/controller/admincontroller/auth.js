const helper = require("../../helper/helper");
let user = require("../../models/users");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");
const category = require('../../models/categeory');
const SubCategory = require('../../models/services');
const booking = require('../../models/bookings');

module.exports = {
  dashboard: async (req, res) => {
    try {
      let userCount = await user.countDocuments({ role: 1 });
      let data = await category.countDocuments({});
      let subdata = await SubCategory.countDocuments({});
      let databooking = await booking.countDocuments({});
  
      return helper.success(res, "Dashboard data fetched successfully", {
        userCount,
        data,
        subdata,
        databooking
       
      });
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
      return helper.error(res, "Internal server error");
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
      res.status(500).json({ message: "Internal server error" });
    }
  },
  
  
  login: async (req, res) => {
    try {
      let log_data = await user.findOne({
        email: req.body.email,
        role: 0,
      });
      if (!log_data) {
        return helper.error(res, "User not found");
      } else {
        var ciphertext = log_data.password;
        let bytes = CryptoJS.AES.decrypt(ciphertext, "secretkey_12");
        var originalText = bytes.toString(CryptoJS.enc.Utf8);

        const result = req.body.password == originalText;
        if (result) {
          var secret = "secretkey_12";
          const token = jwt.sign(
            {
              id: log_data.id,
              name: log_data.name,
            },
            secret,
            { expiresIn: "9999hr" }
          );
          log_data.token = token;
          return helper.success(res, "You are login successfully", {
            log_data,
            token,
          });
        } else {
          return helper.error(res, "please enter the valid password");
        }
      }
    } catch (error) {
      console.error(error);
      return helper.error(res, "Internal server error", error);
    }
  },
  user_list: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1; 
      const size = parseInt(req.query.size) || 5; 
    
      const skip = (page - 1) * size;
      const data = await user.find({role: 1 , raw: true, nest: true })
          .skip(skip)
          .limit(size);
      const totalCount = await user.countDocuments({role: 1});
      const totalPages = Math.ceil(totalCount / size);

      return helper.success(res, "All users Detail", {
          data,
          pagination: {
              totalCount,
              totalPages,
              currentPage: page,
              pageSize: size
          }
      });
    } catch (error) {
      console.log(error);
      return helper.error(res, "Internal server error");
    }
  },
  provider_list: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1; 
      const size = parseInt(req.query.size) || 5; 
    
      const skip = (page - 1) * size;
      const data = await user.find({role: 2 , raw: true, nest: true })
          .skip(skip)
          .limit(size);
      const totalCount = await user.countDocuments({role: 2});
      const totalPages = Math.ceil(totalCount / size);

      return helper.success(res, "All providers Detail", {
          data,
          pagination: {
              totalCount,
              totalPages,
              currentPage: page,
              pageSize: size
          }
      });
    } catch (error) {
      console.error("Error fetching providers:", error);
      return helper.error(res, "Internal server error");
    }
  },
  workers_list:async(req,res)=>{
    try {
      const page = parseInt(req.query.page) || 1; 
      const size = parseInt(req.query.size) || 5; 
    
      const skip = (page - 1) * size;
      const data = await user.find({role: 3 , raw: true, nest: true })
          .skip(skip)
          .limit(size);
      const totalCount = await user.countDocuments({role: 3});
      const totalPages = Math.ceil(totalCount / size);

      return helper.success(res, "All workers Detail", {
          data,
          pagination: {
              totalCount,
              totalPages,
              currentPage: page,
              pageSize: size
          }
      });
    } catch (error) {
      console.error('error fetching workers: ',error);
      return helper.error(res, "internal server error");
    }
  },
view: async (req, res) => {
    try {
      let view = await user.findById({_id:req.params._id});
      return helper.success(res, "data", view);
    } catch (error) {
      console.log(error);
      return helper.error(res, "An error occurred", error);
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
          new:true
        }
      );
      if (find_data)
        return helper.success(res, "User update successfully", find_data);
    } catch (error) {
      
      return res.status(500).json({ message: "Internal server error" });
    }
  },
  delete_user: async (req, res) => {
    try {
      const { _id } = req.params;
      let data = await user.findByIdAndDelete(_id);
      if (data) {
        return helper.success(res, "User Deleted successfully");
      } else {
        return helper.error(res, "User not found");
      }
    } catch (error) {
      
      return res.status(500).json({ message: "Internal server error" });
    }
  },


  profile: async (req, res) => {
    try {
      const userId = req.user._id;
      const find_user = await user.findById(userId).select('name email address phone_no image'); 

      if (!find_user) {
        return res.status(404).json({ message: "User not found" });
      }

      return res.status(200).json({ message: "Profile fetched successfully", body: find_user });
    } catch (error) {
      console.error("Error fetching profile:", error);
      return res.status(500).json({ message: "An error occurred while fetching profile" });
    }
  },
  
  edit_profile: async (req, res) => {
    try {
      const userId = req.user._id;
      const find_user = await user.findById(userId);
      if (!find_user) {
        return res.status(404).json({ message: "User not found" });
      }
  
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
  
      if (!updatedProfile) {
        return res.status(400).json({ message: "No changes were made" });
      }
  
      return res.status(200).json({ message: "Profile updated successfully", body: updatedProfile });
    } catch (error) {
      console.error("Error updating profile:", error);
      return res.status(500).json({ message: "An error occurred while updating profile" });
    }
  },
   reset_password :async (req, res) => {
    try {
      const { password, newPassword } = req.body;
      const token = req.headers.authorization?.split(' ')[1]; 
  
      if (!token) {
        return helper.error(res, "No token provided");
      }
  
      
      const decoded = jwt.verify(token, "secretkey_12");
      const userId = decoded.id; 
  
      const find_data = await user.findById(userId);
  
      if (!find_data) {
        return helper.error(res, "User not found");
      }
  
      const ciphertext = find_data.password;
      const bytes = CryptoJS.AES.decrypt(ciphertext, "secretkey_12");
      const originalText = bytes.toString(CryptoJS.enc.Utf8);
  
      if (password !== originalText) {
        return helper.error(res, "Current password is incorrect");
      }
  
      const encryptedNewPassword = CryptoJS.AES.encrypt(newPassword, "secretkey_12").toString();
      const updatedUser = await user.findByIdAndUpdate(
        userId, 
        { password: encryptedNewPassword },
        { new: true }
      );
  
      return helper.success(res, "Password changed successfully", updatedUser);
    } catch (error) {
      console.error("Error resetting password:", error);
      return helper.error(res, "An error occurred while resetting the password");
    }
  },

status: async (req, res) => {
  try {
    const { id, status } = req.body;

    
    if (status !== "0" && status !== "1") {
      return res.status(400).json({ message: "Invalid status value" });
    }
    const updatedUser = await user.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ success: true, message: "User status updated successfully" });
  } catch (error) {
    console.error("Error updating user status:", error);
    return res.status(500).json({ message: "An error occurred while updating user status" });
  }
},   
  logout: (req, res) => {
    try {
      res.status(200).json({ message: "Logged out successfully" });
    } catch (error) {
      console.error("Error during logout:", error);
      return res.status(500).json({ message: "An error occurred during logout" });
    }
  },
};
