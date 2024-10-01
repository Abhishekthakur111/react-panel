import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "./admin/Login";
import Layout from "./common/Layout";
import Dashboard from "./Dashboard";
import UserList from "./admin/UserList";
import CategoryList from "./Category/CategoryList";
import Profile from "./admin/Profile";
import Privacy from "./admin/Privacy";
import AboutUs from "./admin/AboutUs";
import Terms from "./admin/Terms";
import Password from "./admin/Password";
import AddCategory from "./Category/AddCategory";
import ListView from "./admin/ListView";
import CategoryView from "./Category/CategoryView";
import SubCategoryList from "./SubCategory/SubCategoryList";
import SubCategoryView from "./SubCategory/SubCategoryView";
import SubCategoryAdd from "./SubCategory/SubCategoryAdd";
import BookingList from "./Booking/BookingList";
import BookingView from "./Booking/BookingView";
import Map from "./Booking/Map";



function App() {
  return (
   <>
   <Router>
   <Routes>
    <Route path='/' element={<Login/>}/>
    <Route element={<Layout/>}>
    <Route path="/dashboard" element={<Dashboard/>}/>
    <Route path='/userlist' element={<UserList/>}/>
    <Route path="/profile" element={<Profile/>}/>
    <Route path='/viewuser/:_id' element={<ListView/>}/>
    <Route path="/categorylist" element={<CategoryList/>}/>
    <Route path='/viewcategeory/:_id' element={<CategoryView/>}/>
    <Route path="/categoryadd" element={<AddCategory/>}/>
    <Route path="/privacy" element={<Privacy/>}/>
    <Route path="/aboutus" element={<AboutUs/>}/>
    <Route path="/terms"element={<Terms/>}/>
    <Route path="/changepassword" element={<Password/>}/>
    <Route path="/services" element={<SubCategoryList/>}/>
    <Route path="/service/:_id" element={<SubCategoryView/>}/>
    <Route path="/subcategoryadd" element={<SubCategoryAdd/>}/>
    <Route path='/bookinglist' element={<BookingList/>}/>
    <Route path="/booking/:_id" element={<BookingView/>}/>
    <Route path='/Map' element={<Map/>}/>
    </Route>
   </Routes>
   </Router>
   </>
  );
}

export default App;
