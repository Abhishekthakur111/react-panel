const Services = require('../../models/services');
const Category = require('../../models/categeory'); 
const { Validator } = require('node-input-validator');
const helper = require('../../helper/helper');

module.exports = {
    createService: async (req, res) => {
        try {
            const v = new Validator(req.body, {
                name: "required|string",
                price: "numeric",
                image: "string",
                cat_id: "string"
            });
            const category = await Category.findById(req.body.cat_id);
            if (!category) {
                return helper.error(res, "Category not found", 404);
            }
            let errorsResponse = await helper.checkValidation(v);
            if (errorsResponse) {
                return helper.error(res, errorsResponse);
            }

            if (req.files && req.files.image) {
                let images = await helper.fileUpload(req.files.image);
                req.body.image = images;
            }

            const newService = await Services.create({
                name: req.body.name,
                price: req.body.price,
                image: req.body.image,
                cat_id: req.body.cat_id,
            });

            return helper.success(res, "Service Created Successfully", { data: newService });
        } catch (error) {
            console.error("Error creating service:", error);
            return helper.error(res, "Internal server error");
        }
    },
    servicelist: async (req, res) => {
        try {
          const page = parseInt(req.query.page) || 1;
          const size = parseInt(req.query.size) || 10;
          const skip = (page - 1) * size;
          const { startDate, endDate } = req.query;
      
          const filter = {};
          if (startDate && endDate) {
            filter.createdAt = {
              $gte: new Date(startDate),
              $lte: new Date(endDate),
            };
          }
      
          const totalCount = await Services.countDocuments(filter);
          const data = await Services.find(filter)
            .populate("cat_id", "name status")
            .skip(skip)
            .limit(size)
            .exec();
      
          const totalPages = Math.ceil(totalCount / size);
      
          return helper.success(res, "All services detail", {
            data,
            pagination: {
              totalCount,
              totalPages,
              currentPage: page,
              pageSize: size,
            },
          });
        } catch (error) {
          console.error("Error retrieving services:", error);
          return helper.error(res, "Internal server error");
        }
    },  
    serviceView: async (req, res) => {
        try {
            const service = await Services.findById(req.params._id)
                .populate('cat_id')
                .exec();
                res.status(200).json({
                    success: true,
                    message: "Services retrieved successfully",
                    body: service});
            
        } catch (error) {
            console.error("Error retrieving service details:", error);
            return helper.error(res, "Internal server error");
        }
    },
    deleteService: async (req, res) => {
        try {
            const { _id } = req.params;
            
            const deletedService = await Services.findByIdAndDelete(_id);


            if (!deletedService) {
                return helper.error(res, "Service not found");
            }

            return helper.success(res, "Service deleted successfully");
        } catch (error) {
            console.error("Error deleting service:", error);
            return helper.error(res, "Internal server error");
        }
    },
    status: async (req, res) => {
        try {
            const { id, status } = req.body;
    
            if (status !== "0" && status !== "1") {
                return res.status(400).json({ message: "Invalid status value" });
            }
    
       
            const updatedService = await Services.findByIdAndUpdate(
                id,
                { status },
                { new: true }
            );
    
     
            if (!updatedService) {
                return res.status(404).json({ message: "Service not found" });
            }
    
       
            return res.status(200).json({
                success: true,
                message: "Service status updated successfully",
                data: updatedService
            });
        } catch (error) {
            console.error("Error updating service status:", error);
            return res.status(500).json({ message: "An error occurred while updating service status" });
        }
    },
    serviceViewedit: async (req, res) => {
        try {
            const service = await Services.findById(req.params._id)
                .populate()
                .exec();
                res.status(200).json({
                    success: true,
                    message: "Services retrieved successfully",
                    body: service});
            
        } catch (error) {
            console.error("Error retrieving service details:", error);
            return helper.error(res, "Internal server error");
        }
    },
    editservice: async (req, res) => {
        try {
            const { _id } = req.params; 
            
            const service = await Services.findById(_id);
            if (!service) {
                return helper.error(res, "Service not found", 404);
            }
    
            if (req.body.cat_id) {
                const category = await Category.findById(req.body.cat_id);
                if (!category) {
                    return helper.error(res, "Category not found", 404);
                }
            }
    
           
            if (req.files && req.files.image) {
                let images = await helper.fileUpload(req.files.image);
                req.body.image = images;
            }
            const updatedService = await Services.findByIdAndUpdate(
                _id,
                {
                    name: req.body.name ,
                    price: req.body.price || service.price,
                    image: req.body.image || service.image,
                    cat_id: req.body.cat_id || service.cat_id,
                },
                { new: true }
            );
    
            return helper.success(res, "Service updated successfully", { data: updatedService });
        } catch (error) {
            console.error("Error updating service:", error);
            return helper.error(res, "Internal server error");
        }
    }
};
