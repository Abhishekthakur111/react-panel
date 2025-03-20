const path = require('path');
const uuid = require("uuid").v4;

module.exports ={
    success:function(res,message="",body={})
    {
        return res.status(200).json({
           success:true,
            status:200,
            message:message,
            body:body
                });
    },
    error:function(res,message="",body={})
    {
        return res.status(403).json({
            success:false,
            status:403,
            message:message,
            body:body
        });
    },
    failure: function(res, message = "", body = {}) {
        return res.status(400).json({
            success: false,
            status: 400,
            message: message,
            body: body
        });
    },
     fileUpload : async (file) => {
        if (!file) return null;
      
        try {
          const extension = path.extname(file.name);
          const filename = uuid() + extension;
          const uploadPath = path.join(process.cwd(), "public", "images", filename);
      
          await file.mv(uploadPath);
      
          return `/images/${filename}`;
        } catch (err) {
          throw err; 
        }
      },
    checkValidation: async (v) => {
        var errorsResponse;
        const match = await v.check().then(function (matched)
      
        {
            if (!matched) {
                var valdErrors = v.errors;
                var respErrors = [];
                Object.keys(valdErrors).forEach(function (key) {
                    if (valdErrors && valdErrors[key] && valdErrors[key].message) {
                        respErrors.push(valdErrors[key].message);
                    }
                }); 
                errorsResponse=respErrors.length > 0 ? respErrors[0] : '';
            }
        });
        return errorsResponse;
    },
}