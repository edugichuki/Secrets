//jshint esversion:6
require("dotenv").config({ path: "vars/.env" });
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
//? Use the session package and set it up with some initial configurations
app.use(
  session({
    secret: "Mylittlesecret.",
    resave: false,
    saveUninitialized: false,
  })
);
//! Set up passport for authentication and use passport package
app.use(passport.initialize());
//? Use passport to manage sessions
app.use(passport.session());

mongoose.set("strictQuery", false);
const connectDB = async () => {
  try {
    const url = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@cluster0.1lwat6t.mongodb.net/userDB?retryWrites=true&w=majority`;
    const conn = await mongoose.connect(url);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (err) {
    console.log("Connection failed !!" + err.message);
    process.exit(1);
  }
};
// const url = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@cluster0.1lwat6t.mongodb.net/userDB?retryWrites=true&w=majority`;
// mongoose
//   .connect(url, {
//     useNewUrlParser: true,
//     useUnifiedTopology: true,
//   })
//   .then(() => console.log("Connected to database !!"))
//   .catch((err) => console.log("Connection failed !!" + err.message));

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

// const secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

//! Enable the passportLocalMongoose plugin so as to use the salting and hashing functions
userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

/*
* Set up Mongoose to use the schema with the added plugin
* Use passport local mongoose to create a local log in strategy
! Create a local strategy to authenticate users using their username and password and also to serialize and deserialise our user
*/
passport.use(User.createStrategy());
//? Set passport to serialize and deserialise our user
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

//? Set up Google strategy and configure it to use all the details
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:8080/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//? Configuring Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:8080/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

//?authenticate user locally and save their login session
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

//? Authenticate Requests
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
// app.post("/register", (req, res) => {
//   bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//     const newUser = new User({
//       email: req.body.username,
//       password: hash,
//     });
//     newUser
//       .save()
//       .then(() => {
//         res.render("secrets");
//       })
//       .catch((err) => {
//         console.log(err);
//       });
//   });
// });

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } })
    .then((foundUsers) => {
      res.render("secrets", { usersWithSecrets: foundUsers });
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id)
    .then((foundUser) => {
      foundUser.secret = submittedSecret;
      foundUser
        .save()
        .then(() => {
          res.redirect("/secrets");
        })
        .catch((err) => {
          console.log(err);
        });
    })
    .catch((err) => {
      console.log(err);
    });
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/register", (req, res) => {
  User.register({ username: req.body.username }, req.body.password)
    .then((user) => {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    })
    .catch((err) => {
      console.log(err);
    });
});

// app.post("/login", (req, res) => {
//   const username = req.body.username;
//   //   const password = md5(req.body.password);
//   const password = req.body.password;

//   User.findOne({ email: username })
//     .then((foundUser) => {
//       //   if (foundUser.password === password) {
//       bcrypt.compare(password, foundUser.password, function (err, result) {
//         // result == true
//         if (result === true || result === foundUser.password) {
//           res.render("secrets");
//         }
//       });
//       // res.render("secrets");
//       //   }
//     })
//     .catch((err) => {
//       console.log(err);
//     });
// });

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      return next(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
  });
});
