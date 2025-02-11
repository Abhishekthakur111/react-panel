const Category = require("../../models/categeory");
const { Validator } = require("node-input-validator");
const helper = require('../../helper/helper');
const SubCategory = require('../../models/services');

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
      throw error
    }
  },
  Categorylist: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;

      const totalCategories = await Category.countDocuments();
      const data = await Category.find().skip(skip).limit(limit);

      return helper.success(res, "All category Detail", {
        data,
        total: totalCategories,
        page,
        limit,
        totalPages: Math.ceil(totalCategories / limit),
      });
    } catch (error) {
      throw error;
    }
  },
  categeoryview: async (req, res) => {
    try {
      let categeoryview = await Category.findById({ _id: req.params._id });
      return helper.success(res, "data", categeoryview);
    } catch (error) {
      throw error
    }
  },
  status: async (req, res) => {
    try {
      const { id, status } = req.body;
      const updatedUser = await Category.findByIdAndUpdate(
        id,
        { status },
        { new: true }
      );
      return res.status(200).json({ success: true, message: "User status updated successfully" });
    } catch (error) {
      throw error
    }
  },
  deleteCategory: async (req, res) => {
    try {
      const { _id } = req.params;
      const deletedCategory = await Category.findByIdAndDelete(_id);
      await SubCategory.deleteMany({ category_id: _id });
      return helper.success(res, "Category and its subcategories deleted successfully");
    } catch (error) {
      return helper.error(res, error.message);
    }
  },
  editcategory: async (req, res) => {
    try {
      const { _id } = req.params;
      const v = new Validator(req.body, {
        name: "required|string",
        image: "string",
      });
      let errorsResponse = await helper.checkValidation(v);
      if (errorsResponse) {
        return helper.error(res, errorsResponse);
      }
      const category = await Category.findById(_id);
      if (!category) {
        return helper.error(res, "Category not found");
      }
      const existingCategory = await Category.findOne({ name: req.body.name, _id: { $ne: _id } });
      if (existingCategory) {
        return helper.error(res, "Another category already exists with that name");
      }
      if (req.files && req.files.image) {
        let images = await helper.fileUpload(req.files.image);
        req.body.image = images;
      }
      category.name = req.body.name;
      if (req.body.image) {
        category.image = req.body.image;
      }
      await category.save();
      return helper.success(res, "Category updated successfully", { data: category });
    } catch (error) {
      throw error
    }
  },
};
