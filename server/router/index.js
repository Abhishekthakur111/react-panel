var express = require('express');
var router = express.Router();

let usercontroller = require('../controller/apicontroller/user');
let authcontroller = require('../controller/admincontroller/auth');
let auth =require("../middleware/auth")
let cmscontroller = require("../controller/admincontroller/cms");
let category = require('../controller/admincontroller/categeory');
let service = require('../controller/admincontroller/services');
let booking = require('../controller/admincontroller/booking');

// routes for admincontroller
router.get('/dashboard',authcontroller.dashboard);
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
router.post("/Createuser",usercontroller.user_create);
router.post('/userstatus',authcontroller.status);

// routes for cms
router.post('/createcms',cmscontroller.createcms);
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

// router for provider
router.get('/provider', authcontroller.provider_list);

//  router for workers
router.get('/worker', authcontroller.workers_list);

// router for categeory
router.post('/createCategory', category.createCategory);
router.get('/catergeorylist', category.Categorylist);
router.get('/viewcategeory/:_id', category.categeoryview);
router.delete('/delete_categeory/:_id', category.deletecategeory);
router.post('/categorystatus',category.status);

// router for services
router.post('/createservice', service.createService);
router.get('/services', service.servicelist);
router.get('/service/:_id', service.serviceView);
router.delete('/delete_service/:_id', service.deleteService);
router.post('/status', service.status);

// router for bookings
router.post('/createbooking',booking.createBooking);
router.get('/booking', booking.bookinglist);
router.get('/booking/:_id', booking.bookingView);
router.post('/bookingstatus', booking.status);








module.exports = router;