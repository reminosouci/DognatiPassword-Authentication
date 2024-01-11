const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const helper = require("../helpers/helper");

// Set up the Passport strategy:
passport.use(new LocalStrategy(async function (username, password, done) {
  try {
    const user = await helper.findByUsername(username);
    if (!user) {
      // If user is not found, return done(null, false)
      return done(null, false);
    }
    // Compare the provided password with the stored hash
    const isValid = await bcrypt.compare(password, user.password);
    if (isValid) {
      // If password is valid, return done(null, user)
      return done(null, user);
    } else {
      // If password is invalid, return done(null, false)
      return done(null, false);
    }
  } catch (err) {
    // Handle other errors (e.g., database lookup error)
    return done(err);
  }
}));

// Serialize a user
passport.serializeUser((user, done) => {
  done(null, user.id)
})

// Deserialize a user
passport.deserializeUser((id, done) => {
  helper.findById(id, (err, user) => {
    if (err) done(err)
    done(null, user)
  })
})
