const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

module.exports = function (app, passport, db, signToken, setAuthCookie) {
  app.use(passport.initialize());

  // GOOGLE
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID || "MISSING_GOOGLE_CLIENT_ID",
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || "MISSING_GOOGLE_CLIENT_SECRET",
    callbackURL: "/auth/google/callback",
  }, (accessToken, refreshToken, profile, done) => done(null, profile)));

  // FACEBOOK
  passport.use(new FacebookStrategy({
    clientID: process.env.FB_APP_ID || "MISSING_FB_APP_ID",
    clientSecret: process.env.FB_APP_SECRET || "MISSING_FB_APP_SECRET",
    callbackURL: "/auth/facebook/callback",
    profileFields: ["id", "displayName", "emails"]
  }, (accessToken, refreshToken, profile, done) => done(null, profile)));

  function upsertOAuthUser(provider, profile) {
    const oauthId = profile.id;
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
    const name = profile.displayName || null;

    let user = db.prepare("SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?")
      .get(provider, oauthId);
    if (user) return user;

    if (email) {
      const existingByEmail = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
      if (existingByEmail) {
        db.prepare("UPDATE users SET oauth_provider=?, oauth_id=? WHERE id=?")
          .run(provider, oauthId, existingByEmail.id);
        return db.prepare("SELECT * FROM users WHERE id=?").get(existingByEmail.id);
      }
    }

    const fallbackEmail = email ? email.toLowerCase() : `noemail_${provider}_${oauthId}@local`;
    const info = db.prepare(`
      INSERT INTO users (full_name, email, oauth_provider, oauth_id)
      VALUES (?, ?, ?, ?)
    `).run(name, fallbackEmail, provider, oauthId);

    return db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  }

  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

  app.get("/auth/google/callback",
    passport.authenticate("google", { session: false, failureRedirect: "/login.html" }),
    (req, res) => {
      const user = upsertOAuthUser("google", req.user);
      const token = signToken(user);
      setAuthCookie(res, token);
      res.redirect("/blank.html");
    }
  );

  app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email"] }));

  app.get("/auth/facebook/callback",
    passport.authenticate("facebook", { session: false, failureRedirect: "/login.html" }),
    (req, res) => {
      const user = upsertOAuthUser("facebook", req.user);
      const token = signToken(user);
      setAuthCookie(res, token);
      res.redirect("/blank.html");
    }
  );
};
