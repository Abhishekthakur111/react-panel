const Category = require("../../models/categeory");
const { Validator } = require("node-input-validator");
const helper = require('../../helper/helper');

module.exports = {
  createCategory: async (req, res) => {
    try {
      const v = new Validator(req.body, {
        name: "required|string",
        image: "string", 
      });
      let errorsResponse = await helper.checkValidation(v);
      if (errorsResponse) {
        return helper.error(res, errorsResponse);
      }
      const existingCategory = await Category.findOne({ name: req.body.name });
      if (existingCategory) {
        return helper.error(res, "Category already exists with that name");
      }
      if (req.files && req.files.image) {
        let images = await helper.fileUpload(req.files.image);
        req.body.image = images;
      }
      const newCategory = await Category.create({
        name: req.body.name,
        image: req.body.image,
        status: req.body.status || '0', 
      });

      return helper.success(res, "Category Created Successfully", { data: newCategory });
    } catch (error) {
      console.error("Error creating category:", error);
      return helper.error(res, "Internal server error");
    }
  },
  Categorylist:async(req, res) =>{
   try {
    const page = parseInt(req.query.page) || 1; 
    const size = parseInt(req.query.size) || 5; 
  
    const skip = (page - 1) * size;
    const data = await Category.find()
        .skip(skip)
        .limit(size);
    const totalCount = await Category.countDocuments({});
    const totalPages = Math.ceil(totalCount / size);

    return helper.success(res, "All category Detail", {
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
  categeoryview: async(req,res)=> {
    try {
        let categeoryview= await Category.findById({_id:req.params._id});
        return helper.success(res, "data", categeoryview);
      } catch (error) {
        console.log(error);
        return helper.error(res, "An error occurred", error);
      }

  },
  status: async (req, res) => {
    try {
      const { id, status } = req.body;
  
      
      if (status !== "0" && status !== "1") {
        return res.status(400).json({ message: "Invalid status value" });
      }
      const updatedUser = await Category.findByIdAndUpdate(
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
  deletecategeory: async(req, res)=>{
    try {
        const { _id } = req.params;
        let data = await Category.findByIdAndDelete(_id);
        if (data) {
          return helper.success(res, "User Deleted successfully");
        } else {
          return helper.error(res, "User not found");
        }
      } catch (error) {
        
        return res.status(500).json({ message: "Internal server error" });
      }
  },
};
