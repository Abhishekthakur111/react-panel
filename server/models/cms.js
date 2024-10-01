const mongoose = require("mongoose");

const cms = new mongoose.Schema({
    id: {
        type: String,
        required: false,
    },
    type: {
        type: String,
        required: true,
    },
    title: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: true,
    },
},
    { timestamps: true });

const cmsModel = mongoose.model("cms", cms);
module.exports = cmsModel;


