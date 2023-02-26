const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const flash = require("connect-flash");
const mongoose = require("mongoose");

mongoose.connect("mongodb://localhost/authentication-system", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const app = express();

app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.set("view engine", "ejs");

const User = require("./models/user");

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (email, password, done) {
      User.findOne({ email: email }, function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "Incorrect email." });
        }
        bcrypt.compare(password, user.password, function (err, res) {
          if (res) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password." });
          }
        });
      });
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

app.get("/", function (req, res) {
  res.render("index", { message: req.flash("message") });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/",
    failureFlash: true,
  })
);

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/");
}

app.get("/dashboard", isLoggedIn, function (req, res) {
  res.render("dashboard", { user: req.user });
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/signup", function (req, res) {
  res.render("signup", { message: req.flash("message") });
});

app.post("/signup", function (req, res) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (user) {
      req.flash("message", "Email already exists");
      res.redirect("/signup");
    } else {
      const newUser = new User();
      newUser.email = req.body.email;
      newUser.password = bcrypt.hashSync(req.body.password, 10);
      newUser.role = "user";
      newUser.save(function (err, user) {
        if (err) {
          console.log(err);
          res.status(500).send();
        } else {
          res.redirect("/");
        }
      });
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000.");
});
