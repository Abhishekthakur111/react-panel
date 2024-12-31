var express = require('express');
var router = express.Router();

let authcontroller = require('../controller/admincontroller/authcontroller');
let auth =require("../middleware/authtoken");
let cmscontroller = require("../controller/admincontroller/cmscontroller");
let category = require('../controller/admincontroller/categorycontroller');
let service = require('../controller/admincontroller/servicecontroller');
let booking = require('../controller/admincontroller/bookingcontroller');
let contact = require('../controller/admincontroller/contactController');

// routes for admincontroller
router.get('/dash_board',authcontroller.dashboard);
router.post('/login',authcontroller.login);
router.get("/user_list",authcontroller.user_list);
router.get('/view/:_id', authcontroller.view);


router.post('/user_edit/:_id',authcontroller.user_edit);
router.delete('/user_delete/:_id', authcontroller.delete_user);
router.post('/change_password',auth.verifyToken,authcontroller.reset_password);


// routes for profile
router.get('/profile', auth.verifyToken, authcontroller.profile);
router.post('/profileupdate', auth.verifyToken, authcontroller.edit_profile); 

// routesfor user controller
router.post('/userstatus',authcontroller.status);

// routes for cms

router.get("/privacy",cmscontroller.privacy_policy);
router.post("/privacypolicy", cmscontroller.privacypolicy);
router.get("/aboutus",cmscontroller.aboutus);
router.post("/updateabout", cmscontroller.updateabout);
router.get('/terms',cmscontroller.term);
router.post('/updateterm',cmscontroller.updateterm);

// route for logout
router.post('/logout', authcontroller.logout);

// route for graph
router.post('/graph', authcontroller.apexcharts);

// router for categeory
router.post('/createCategory', category.createCategory);
router.get('/categorylist', category.Categorylist);
router.get('/viewcategory/:_id', category.categeoryview);
router.delete('/deletecategory/:_id', category.deletecategeory);
router.post('/categorystatus',category.status);
router.post('/updatecategory/:_id',category.editcategory);

// router for services
router.post('/createservice', service.createService);
router.get('/services', service.servicelist);
router.get('/service/:_id', service.serviceView);
router.delete('/delete_service/:_id', service.deleteService);
router.post('/subcategorystatus', service.status);
router.post('/updatesubcategory/:_id', service.editservice);
router.get('/editget/:_id',service. serviceViewedit);

// router for bookings
router.post('/createbooking',booking.createBooking);
router.get('/booking', booking.bookinglist);
router.get('/booking/:_id', booking.bookingView);
router.post('/bookingstatus', booking.status);
router.delete('/bookingdelete/:_id',booking.deletebooking);

//router for contacts
router.post('/createcontact',contact.createcontact);
router.get('/contactlist',contact.contact_get);
router.get('/contactview/:_id', contact.contact_view);
router.delete('/contactdelete/:_id',contact.contact_delete);


module.exports = router;