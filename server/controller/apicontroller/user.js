const user = require("../../models/users");
const CryptoJS = require("crypto-js");
const { Validator } = require("node-input-validator");
const jwt = require("jsonwebtoken");
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

        const ciphertext = CryptoJS.AES.encrypt(req.body.password, "secretkey_12").toString();
        let data = await user.create({
          role: req.body.role,
          name: req.body.name,
          email: req.body.email,
          password: ciphertext,
          address: req.body.address,
          phone_no: req.body.phone_no,
          image: req.body.image,
          status: req.body.status,
        });

        const secret = "secretkey_12";
        const token = jwt.sign(
          {
            id: data.id,
            name: data.name,
          },
          secret,
          { expiresIn: "9999hr" }
        );
        data.token = token;

        return helper.success(res, "User Created Successfully", { data, token });
      }
    } catch (error) {
      console.error("Error creating user:", error);
      return helper.error(res, "Internal server error");
    }
  },
  }
