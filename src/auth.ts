import { IUser, UserModel } from "users/users.model";
import { Router } from "express";
import { Error } from "mongoose";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import {
  ExtractJwt,
  Strategy as JwtStrategy,
  StrategyOptions,
} from "passport-jwt";

export var router = Router();

passport.use(
  "signup",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async function verify(email: string, password: string, done) {
      try {
        const user = await UserModel.createUser({ email, password });

        return done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  "password",
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async function verify(email: string, password: string, done) {
      try {
        const user = await UserModel.findOne({ email }).select("+password");

        if (!user) {
          return done(null, false, { message: "User not found" });
        }

        const isValid = await user.checkPassword(password);

        if (!isValid) {
          return done(null, false, { message: "Invalid password" });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

passport.use(
  new JwtStrategy(options, function (jwt_payload, done) {
    UserModel.findOne(
      { id: jwt_payload.sub },
      function (err: Error, user: IUser) {
        if (err) {
          return done(err, false);
        }
        if (user) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      }
    );
  })
);
