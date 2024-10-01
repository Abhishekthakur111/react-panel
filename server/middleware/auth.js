const jwt = require('jsonwebtoken');
const user = require("../models/users");
const secret = "secretkey_12";

module.exports = {
  verifyToken: async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    try {
      const tokenData = token.split(" ")[1];
      jwt.verify(tokenData, secret, async (err, decoded) => {
        if (err) {
          return res.status(403).json({ message: 'Invalid token' });
        }

        if (!decoded.id) {
          return res.status(403).json({ message: 'User ID not found in token' });
        }

        try {
          const findUser = await user.findById(decoded.id);
          if (!findUser) {
            return res.status(404).json({ message: 'User not found' });
          }

          req.user = { _id: findUser._id };
          next();
        } catch (error) {
          console.error("Error finding user:", error);
          return res.status(500).json({ message: 'Internal server error' });
        }
      });
    } catch (error) {
      console.error("Error verifying token:", error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
};
