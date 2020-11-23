//jshint esversion:6
require("dotenv").config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocaleMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;


const app = express();

// Initialising express 
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// Initialising express sesssion
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

// INTIALIZING PASSPORT
app.use(passport.initialize());
// Initialising session using passport
app.use(passport.session());


//Connecting to mongoose
mongoose.connect(process.env.PASSWORD,
{
  useNewUrlParser: true,
  useUnifiedTopology: true
});


const userSecrets = new mongoose.Schema({
  userId : String,
  secrets : String
});

const Secrets = mongoose.model("Secrets", userSecrets); 

//userSecrets.plugin(passportLocaleMongoose);
//userSecrets.plugin(findOrCreate);

 

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String
});

//Enabling our passport-mongoose plugin help hash and store hash to mongoose
userSchema.plugin(passportLocaleMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// Configure passport local
passport.use(User.createStrategy());

//Using passport to serilize and deserialize authentication
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//Using Google Oauth20 for authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Using facebook authenticantion initialise
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google",
  //Intiate authentication with google using passport
  passport.authenticate("google", {
    scope: ["profile"]
  }));


app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect to the secrets page
    res.redirect('/secrets');
  });

//This endpoint connects the User to Facebook
app.get('/auth/facebook', passport.authenticate('facebook'));

//This endpoint is the Facebook Callback URL and on success or failure returns a response to the app
app.get('/auth/facebook/secrets', passport.authenticate('facebook', {
  failureRedirect: '/login'
}), (req, res) => {
  res.redirect('/secrets');
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {

 Secrets.find({}, (err, foundSecrets)=>{
   if (err){
     console.log(err);
   } else {
     if (foundSecrets){
       res.render("secrets", {usersWithSecrets: foundSecrets});
     }
   }
 }); 
  
});

app.get("/submit", (req, res) => {
  // Checks if the user is authenticated 
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  //const submittedSecret = req.body.secret;

  

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        const newSecret = new Secrets({
        userId : req.user.id,
        secrets : req.body.secret});
        newSecret.save(function(){
        res.redirect("/secrets");
        });
      }
    }
  });
});
//Logging out User
app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect('/');
});


/// First level security using password and username to access page ///
app.post("/register", (req, res) => {

  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    // Checks if the user has registered else authenticates and logs them in
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });


});

app.post("/login", (req, res) => {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.logIn(user, (err) => {
    // Checks for authentication on the login page
    if (err) {
      console.log(err);
      res.redirect('/login');
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });

});





let port = process.env.PORT;
if (port == null || port == ""){
  port = 3000;
}


app.listen(port, function () {
  console.log("Sever up and running!");
});
