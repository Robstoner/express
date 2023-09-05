import passport from "passport";

import { IUser, UserModel } from "../users/users.model";
import { Strategy as LocalStrategy } from "passport-local";
import {
  ExtractJwt,
  Strategy as JwtStrategy,
  StrategyOptions,
  VerifiedCallback,
} from "passport-jwt";
import { JwtPayload } from "jsonwebtoken";
import { Request } from "express";

passport.use(
  "signup",
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async function verify(email: string, password: string, done) {
      try {
        const userExists = await UserModel.findOne({ email });

        if (userExists) {
          return done(null, false, { message: "User already exists" });
        }

        const user = await UserModel.createUser({ email, password });

        return done(null, user as IUser);
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

        return done(null, user as IUser);
      } catch (error) {
        return done(error);
      }
    }
  )
);

const options: StrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
  passReqToCallback: true,
};

passport.use(
  new JwtStrategy(options, async function (req: Request, jwt_payload: JwtPayload, done: VerifiedCallback) {
    const user = await UserModel.getUserByEmail(jwt_payload.email);

    if (!user) {
      return done(null, false, { message: "User not found" });
    }

    const headerToken = req.headers.authorization?.split(" ")[1];
    
    const userToken = user.tokens?.find((value) => value.token === headerToken);

    if (!userToken || !userToken.isValid) {
      return done(null, false, { message: "Invalid token" });
    }

    if (userToken.expires < new Date()) {
      userToken.isValid = false;
      user.save();

      return done(null, false, { message: "Token expired" });
    }

    return done(null, user);
  })
);

export default passport;