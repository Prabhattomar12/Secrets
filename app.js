// jshint : esversion:6
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const passportLocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const session = require("express-session");
require("dotenv").config();
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongooseFindOrCreate = require("mongoose-findorcreate");
const GitHubStrategy = require("passport-github2");
const FacebookStrategy = require("passport-facebook");

const app = express();

/////////////////////////////////////// Module Congiguration ///////////////////////////
app.set("view engine", "ejs");
app.use(express.static("public")); 
app.use(bodyParser.urlencoded({extended : true}));
app.use(session({
   secret : process.env.SECRET_KEY,
   resave : false,
   saveUninitialized : false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


 // Github strategy
 passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/github/secrets"
},
function(accessToken, refreshToken, profile, done) {
  User.findOrCreate({ githubId: profile.id }, function (err, user) {
    return done(err, user);
  });
}
));

// facebook strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

 ///////////////////////////////////// Database setup ////////////////////////////////////
 mongoose.connect("mongodb://localhost:27017/UserDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true
});

 const userSchema = mongoose.Schema({
    username : String,
    password : String,
    secret : String
 });
 userSchema.plugin(passportLocalMongoose);
 userSchema.plugin(mongooseFindOrCreate);

 const User = mongoose.model("User", userSchema);



 passport.use(User.createStrategy());
 
 passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
 ///////////////////////////////////// Get Routes ////////////////////////////////////
 
 
 app.get("/", function(req, res){
     res.render("home"); 
 });

 app.get("/register", function(req, res){
  res.render("register"); 
});

app.get("/login", function(req, res){
  res.render("login"); 
});

app.get("/secrets", function(req, res){
      User.find({"secret" : {$ne : null }}, function(err, foundUsers){
            if(err){
              console.log(err);
            }else{
                 if(foundUsers){
          //                console.log(foundUsers)
                    res.render("secrets", {usersWithSecrets : foundUsers});
                 }
            }     
      });
});

app.get("/logout", function(req, res){
     req.logout();
     res.redirect("/");
}); 

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets route.
    res.redirect('/secrets');
  });

  app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get("/submit", function(req, res){
        if(req.isAuthenticated()){
          res.render("submit");
        }else{
           res.redirect("/login");
        }
  })

 ///////////////////////////////////// Post Routes ////////////////////////////////////
 
 app.post("/register", function(req, res){
   
User.register({username:req.body.username, active: false}, req.body.password, function(err, user) {
  if (err) { console.log(err);
   }
 
  var authenticate = User.authenticate("local");
  authenticate(req.body.username, req.body.password, function(err, result) {
    if (err) { console.log(err); }
          if(result){
            res.redirect("/secrets");
          }else{
            res.redirect("/register");
            console.log(result);
          }
    // Value 'result' is set to false. The user could not be authenticated since the user is not active
       
  });
});

    
 });

  
      
  app.post("/login", function(req, res){
      const user = new User({
         username : req.body.username,
         password : req.body.password
      });

       req.login(user, function(err){
            if(err){
              console.log(err);
            }else{
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                });
            }
       });
  }); 


 app.post("/submit", function(req, res){
       const submittedSecret = req.body.secret;
     //       console.log(req.user);
        User.findById(req.user.id, function(err, foundUser){
              if(err){
                console.log(err);
              }else{
                 if(foundUser){
                   foundUser.secret = submittedSecret;
                   foundUser.save(function(){
                      res.redirect("/secrets");
                   });
                 }

                }
                  
                
              
        });
 });

app.listen(process.env.PORT || 3000, function(req, res){
   console.log("Server is running at port 3000");
});