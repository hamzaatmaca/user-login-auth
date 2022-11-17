const express = require("express");
const app = express();
const bodyparser = require("body-parser");
const mongoose = require("mongoose");
const cookieparser = require("cookie-parser");
const User = require("./model/user");
const { auth } = require("./middleware/auth");
const PORT = process.env.PORT || 3030;
const dotenv = require("dotenv");
dotenv.config();

app.use(express.json());
app.use(cookieparser());

try {
  mongoose.connect(process.env.DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  mongoose.set("useFindAndModify", false);
  mongoose.set("useCreateIndex", true);

  mongoose.connection
    .once("open", () => {
      console.log("Connected");
    })
    .on("error", (error) => {
      console.warn("Warning", error);
    });
} catch (error) {
  console.log(error);
}

app.get("/", function (req, res) {
  res.status(200).send("Hi");
});

app.post("/api/register", function (req, res) {
  let newUser = User(req.body);

  if (newUser.password != newUser.password2)
    return res.status(400).json({ message: "Password  not Match" });

  User.findOne({ email: newUser.email }, function (err, user) {
    if (user) return res.status(400).json({ message: "Email already exists" });

    newUser.save((err, doc) => {
      if (err) {
        console.log(err);
        return res.status(400).json({ success: false, err: err });
      }
      res.status(200).json({
        success: true,
        user: doc,
      });
    });
  });
});

app.post("/api/login", (req, res) => {
  let token = req.cookies.auth;

  User.findByToken(token, (err, user) => {
    if (user)
      return res.status(400).json({
        error: true,
        message: "You are already logged-in",
      });
    else {
      User.findOne({ email: req.body.email }, function (err, user) {
        if (!user)
          return res.json({
            isAuth: false,
            message: "Email not found",
          });

        user.comparePassword(req.body.password, (err, isMatch) => {
          if (!isMatch)
            return res.json({
              isAuth: false,
              message: "Password not match",
            });
          user.generateToken((err, user) => {
            if (err) return res.status(400).send(err);
            res.cookie("auth", user.token).json({
              isAuth: true,
              id: user._id,
              email: user.email,
              name: `${user.firstname} ${user.lastname}`,
            });
          });
        });
      });
    }
  });
});

app.get("/api/profile", auth, (req, res) => {
  res.json({
    isAuth: true,
    id: req.user._id,
    email: req.user.email,
    name: `${req.user.firstname} ${req.user.lastname}`,
  });
});

app.get("/api/logout", auth, (req, res) => {
  req.user.deleteToken(req.token, (err, user) => {
    if (err) return res.status(400).send(err);
    res.sendStatus(200);
  });
});

app.listen(PORT, () => {
  console.log("app is running at:", PORT);
});
