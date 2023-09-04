import { UserModel } from "db/users";
import express, { Request, Response } from "express";
import { Error } from "mongoose";
import passport from "passport";
import LocalStrategy from "passport-local";

var router = express.Router();

passport.use(
  new LocalStrategy.Strategy(function verify(username, password, done) {
    UserModel.findOne({ username: username }, function (err: Error, user: any) {
      if (err) {
        return done(err);
      }

      if (!user || !user.authenticate(password)) {
        return done(null, false, {
          message: "Incorrect username or password.",
        });
      }
      return done(null, user);
    });
  })
);

module.exports = router;
