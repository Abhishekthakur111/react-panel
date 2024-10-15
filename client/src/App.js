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
import PrivateRoute from "./PrivateRoute"; 

function App() {
  return (
    <>
      <Router>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route element={<Layout />}>
            <Route path="/dashboard" element={<PrivateRoute element={<Dashboard />} />} />
            <Route path="/userlist" element={<PrivateRoute element={<UserList />} />} />
            <Route path="/profile" element={<PrivateRoute element={<Profile />} />} />
            <Route path="/viewuser/:_id" element={<PrivateRoute element={<ListView />} />} />
            <Route path="/categorylist" element={<PrivateRoute element={<CategoryList />} />} />
            <Route path="/viewcategeory/:_id" element={<PrivateRoute element={<CategoryView />} />} />
            <Route path="/categoryadd" element={<PrivateRoute element={<AddCategory />} />} />
            <Route path="/privacy" element={<PrivateRoute element={<Privacy />} />} />
            <Route path="/aboutus" element={<PrivateRoute element={<AboutUs />} />} />
            <Route path="/terms" element={<PrivateRoute element={<Terms />} />} />
            <Route path="/changepassword" element={<PrivateRoute element={<Password />} />} />
            <Route path="/services" element={<PrivateRoute element={<SubCategoryList />} />} />
            <Route path="/service/:_id" element={<PrivateRoute element={<SubCategoryView />} />} />
            <Route path="/subcategoryadd" element={<PrivateRoute element={<SubCategoryAdd />} />} />
            <Route path="/bookinglist" element={<PrivateRoute element={<BookingList />} />} />
            <Route path="/booking/:_id" element={<PrivateRoute element={<BookingView />} />} />
            <Route path="/Map" element={<PrivateRoute element={<Map />} />} />
          </Route>
        </Routes>
      </Router>
    </>
  );
}

export default App;
