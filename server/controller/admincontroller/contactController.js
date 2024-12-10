const Contact = require('../../models/contacts');
const helper = require('../../helper/helper');

module.exports = {
    createcontact:async(req,res)=>{
        try {
            const contact = await Contact.create({
               name:req.body.name,
               email:req.body.email,
               address:req.body.address,
               phoneNumber:req.body.phoneNumber,
            });
            res.status(200).json({message:true, contact:contact});
        } catch (error) {
            console.log(error,'error');
        }
    },
    contact_get: async (req, res) => {
        try {
          const { page = 1, size = 5 } = req.query;
          const limit = parseInt(size, 10);
          const skip = (parseInt(page, 10) - 1) * limit;
      
          const totalCount = await Contact.countDocuments();
          const data = await Contact.find()
            .skip(skip)
            .limit(limit);
      
          res.status(200).json({
            success: true,
            message: "Contact List retrieved successfully",
            body: {
              data: data,
              pagination: {
                totalCount,
                totalPages: Math.ceil(totalCount / limit),
                currentPage: parseInt(page, 10),
                pageSize: limit,
              },
            },
          });
        } catch (error) {
          console.error('Error fetching contacts:', error);
          res.status(500).json({
            success: false,
            message: 'An error occurred while fetching contacts.',
          });
        }
      },
      
    contact_view:async(req,res)=>{
        try {
            const contactId = req.params._id
            data = await Contact.findById(contactId);
            return res.status(200).json({message:true, data:data});
        } catch (error) {
            console.log(error,'error');
        }
    },
    contact_delete:async(req,res)=>{
        try {
            const { _id } = req.params;
            const data = await Contact.findByIdAndDelete(_id);
            return res.status(200).json({message:true, data:data});
        } catch (error) {
            console.log(error,'error');
        }
    }

}
