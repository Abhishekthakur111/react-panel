const user = require("../../models/users");
const bcrypt = require("bcryptjs");  
const { Validator } = require("node-input-validator");
const helper = require('../../helper/helper');

module.exports = {
  user_create: async (req, res) => {
    try {
      const v = new Validator(req.body, {
        email: "required|email",
        password: "required",
        role: "required|integer",
      });

      let errorsResponse = await helper.checkValidation(v);
      if (errorsResponse) {
        return helper.error(res, errorsResponse);
      }

      const find_email = await user.findOne({ email: req.body.email });
      if (find_email) {
        return helper.error(res, "User already exists with that email");
      } else {
        if (req.files && req.files.image) {
          let images = await helper.fileUpload(req.files.image);
          req.body.image = images;
        }
        
        
        const hashedPassword = await bcrypt.hash(req.body.password, 10);  

        let data = await user.create({
          role: req.body.role,
          name: req.body.name,
          email: req.body.email,
          password: hashedPassword,  
          address: req.body.address,
          phone_no: req.body.phone_no,
          image: req.body.image,
          status: req.body.status,
        });

        return helper.success(res, "User Created Successfully", { data });
      }
    } catch (error) {
      console.error("Error creating user:", error);
      return helper.error(res, "Internal server error");
    }
  },
};
