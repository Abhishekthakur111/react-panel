const jwt = require('jsonwebtoken');
const user = require("../models/users");
const secret = process.env.SECRET; 
const helper = require("../helper/helper");

module.exports = {
  verifyToken: async (req, res, next) => {
    const token = req.headers['authorization'];
    try {
      const tokenData = token.split(" ")[1]; 
      const decoded = jwt.verify(tokenData, secret);
      const findUser = await user.findById(decoded.id);
      req.user = { _id: findUser._id };
      next();
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        return helper.failure(res, "Invalid token", 400);
      } else if (error.name === "TokenExpiredError") {
        return helper.failure(res, "Token expired", 400);
      }
      return helper.failure(res, "Internal server error", 400);
    }
  }
};
