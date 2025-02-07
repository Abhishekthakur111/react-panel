const cms = require("../../models/cms");

module.exports = {
    privacy_policy: async (req, res) => {
        try {
            let data = await cms.findOne({ type: 1 });
            return res.status(200).json({ message: "privacy policy....", data });
        } catch (error) {
            throw error
        }
    },
    privacypolicy: async (req, res) => {
        try {
            const { content } = req.body;
            let data = await cms.updateOne(
                { type: '1' },
                { content },
                { new: true, upsert: true }
            );
            return res.status(200).json({ message: "Privacy policy updated successfully.", data });
        } catch (error) {
            throw error
        }
    },
    aboutus: async (req, res) => {
        try {
            let data = await cms.findOne({ type: 2 });
            return res.status(200).json({ message: "about us..", data });
        } catch (error) {
            throw error
        }
    },
    updateabout: async (req, res) => {
        try {
            const { content } = req.body;
            const result = await cms.updateOne(
                { type: 2 },
                { $set: { content } }
            );
            return res.status(200).json({ message: "Update About Us successfully." });
        } catch (error) {
            throw error
        }
    },
    term: async (req, res) => {
        try {
            let data = await cms.findOne({ type: 3 });
            return res.status(200).json({ message: "Term and Condtions.....", data });
        } catch (error) {
            throw error
        }
    },
    updateterm: async (req, res) => {
        try {
            const { content } = req.body;
            let data = await cms.updateOne({ type: 3 },
                { content },
                { new: true, upsert: true },
            );
            return res.status(200).json({ message: 'Term and conditions......', data });
        } catch (error) {
            throw error
        }
    }
}