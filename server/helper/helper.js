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
        return res.status(200).json({
            success:false,
            status:400,
            message:message,
            body:body
        });
    },
    fileUpload: async (file) => {
        if (file) {
          var extension = path.extname(file.name);
          var filename = uuid() + extension;
          file.mv(
            process.cwd() + `/public/images/` + filename,
            function (err) {
              if (err) return err;
            }
          );   
        } 
    
        let fullpath = `/images/` + filename
        return fullpath;
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