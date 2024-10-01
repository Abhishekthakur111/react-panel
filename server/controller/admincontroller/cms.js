const cms = require("../../models/cms");

module.exports ={

    createcms:async(req,res)=>{
        try {
            const data = await cms.create({
                ...req.body
            });
            res.status(200).json({message:'true',data});
        } catch (error) {
            console.log(error);
            return res.status(500).json({messgae:"Internal server error"});
        }
    },
    privacy_policy:async (req,res) =>{
        try {
            let data = await cms.findOne({type :1});
            return res.status(200).json({message:"privacy policy....",data});
        } catch (error) {
                    console.log(error);
                    return res.status(500).json({messgae:"Internal server error"});
        }
    },
    privacypolicy: async (req, res) => {
        try {
            const {  content } = req.body;
            let data = await cms.updateOne(
                { type: '1' }, 
                {  content },
                { new: true, upsert: true }
            );
            return res.status(200).json({ message: "Privacy policy updated successfully.", data });
        } catch (error) {
            console.log(error);
            return res.status(500).json({ message: "Internal server error" });
        }
    },
    aboutus:async(req, res) => {
        try {
            let data = await cms.findOne({type:2});
            return res.status(200).json({message:"about us..", data});
        } catch (error) {
            console.log(error);
            return res.status(500).json({messgae:"Internal server error"});
        }
    },
     
    updateabout: async (req, res) => {
        try {
            const { content } = req.body;
            if (!content || content.trim() === '') {
                return res.status(400).json({ message: 'Content field cannot be empty.' });
            }
            const result = await cms.updateOne(
                { type: 2 }, 
                { $set: { content } } 
            );
            if (result.matchedCount === 0) {
                return res.status(404).json({ message: 'Document not found.' });
            }
            if (result.modifiedCount === 0) {
                return res.status(400).json({ message: 'No changes made.' });
            }
            return res.status(200).json({ message: "Update About Us successfully." });
        } catch (error) {
            console.error("Error updating About Us:", error);
            return res.status(500).json({ message: "Internal server error" });
        }
    },
    
    
    term:async(req,res)=>{
        try {
            let data = await cms.findOne({type:3});
            return res.status(200).json({message:"Term and Condtions.....", data});            
        } catch (error) {
            console.log(error);
            return res.status(500).json({messgae:"Internal server error"});
        }
    },
    updateterm:async(req,res)=> {
        try {
            const { content} = req.body;
            let data = await cms.updateOne({type:3},
                { content},
                {new:true, upsert:true},
            );
            return res.status(200).json({message:'Term and conditions......', data});
        } catch (error) {
            console.log(error);
            return res.status(500).json({message:"internal server error"})
        }
    }
}