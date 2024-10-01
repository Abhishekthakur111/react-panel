require('dotenv').config();
const createError = require('http-errors');
const express = require('express');
const mongoose = require('mongoose');
const logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
const path = require('path');
var fileUpload = require('express-fileupload');
const cors = require('cors');
const flash = require('express-flash');

const indexRouter = require('./router/index');

const app = express();
const port = process.env.port 
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(flash());
app.use(fileUpload());
app.use(bodyParser.urlencoded({extended : true}));

app.use(express.static(path.join(__dirname,'public')));
app.use("/", indexRouter);


mongoose.set("strictQuery", true);
mongoose
  .connect(process.env.DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    app.listen(port, () => {
      console.log(
        `Server is connecting to the database and running on port ${port}`
      );
    });
  })
  .catch((err) => {
    console.error("Error connecting to the database:", err);
  });

  module.exports = app