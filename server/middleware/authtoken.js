const jwt = require('jsonwebtoken');
const user = require("../models/users");
const secret = process.env.SECRET; 

module.exports = {
  verifyToken: async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    try {
      const tokenData = token.split(" ")[1]; 
      if (!tokenData) {
        return res.status(401).json({ message: 'Token format is incorrect' });
      }
      const decoded = jwt.verify(tokenData, secret);
      if (!decoded.id) {
        return res.status(403).json({ message: 'User ID not found in token' });
      }
      const findUser = await user.findById(decoded.id);
      if (!findUser) {
        return res.status(404).json({ message: 'User not found' });
      }
      req.user = { _id: findUser._id };
      next();
    } catch (error) {
      console.error("Error verifying token:", error);
      if (error.name === 'JsonWebTokenError') {
        return res.status(403).json({ message: 'Invalid token' });
      } else if (error.name === 'TokenExpiredError') {
        return res.status(403).json({ message: 'Token expired' });
      }
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
};
