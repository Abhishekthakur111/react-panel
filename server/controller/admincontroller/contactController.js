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
         throw error
        }
    },
    contact_get: async (req, res) => {
        try {
          const data = await Contact.find()
          res.status(200).json({
            success: true,
            message: "Contact List retrieved successfully",
            body: {
              data: data
            },
          });
        } catch (error) {
         throw error
        }
      },
      
    contact_view:async(req,res)=>{
        try {
            const contactId = req.params._id
            data = await Contact.findById(contactId);
            return res.status(200).json({message:true, data:data});
        } catch (error) {
           throw error
        }
    },
    contact_delete:async(req,res)=>{
        try {
            const { _id } = req.params;
            const data = await Contact.findByIdAndDelete(_id);
            return res.status(200).json({message:true, data:data});
        } catch (error) {
           throw error
        }
    }

}
