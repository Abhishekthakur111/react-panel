const  mongoose  = require("mongoose") ;

const newusers = new mongoose.Schema({
    role:{
        type: String,
        required: true,
    },
    name:{
        type: String,
        required: true,
    },
    email:{
        type: String,
        required: true,
    },
    password:{
        type: String,
        required: true,
    },
    address:{
        type: String,
        required: false,
    },
  
    phone_no:{
        type: String,
        required: false,
    },
    image:{
        type:String,
        required: false,
    },
    status: {
        type: String,
        enum: ['0', '1'],
        default: '0',
    }
    
},
{ timestamps: true });

const usersModel = mongoose.model("User", newusers);
module.exports = usersModel;


