const Contact = require('../../models/contacts');
const helper = require('../../helper/helper');

module.exports = {
  contact_get: async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const skip = (page - 1) * limit;
      const totalContacts = await Contact.countDocuments();
      const data = await Contact.find().skip(skip).limit(limit);

      return helper.success(res, "All contact details", {
        data,
        total: totalContacts,
        page,
        limit,
        totalPages: Math.ceil(totalContacts / limit),
      });
    } catch (error) {
      return helper.error(res, "Something went wrong", error);
    }
  },
  contact_view: async (req, res) => {
    try {
      const contactId = req.params._id
      data = await Contact.findById(contactId);
      return res.status(200).json({ message: true, data: data });
    } catch (error) {
      throw error
    }
  },
  contact_delete: async (req, res) => {
    try {
      const { _id } = req.params;
      const data = await Contact.findByIdAndDelete(_id);
      return res.status(200).json({ message: true, data: data });
    } catch (error) {
      throw error
    }
  }
}
