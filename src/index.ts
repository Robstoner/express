import express, { Request } from "express";
import http from "http";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import compression from "compression";
import cors from "cors";
import mongoose from "mongoose";
import passport from "passport";
import dotenv from "dotenv";

import { IUser, UserModel } from "./users/users.model";
import { Error } from "mongoose";
import { Strategy as LocalStrategy } from "passport-local";
import {
  ExtractJwt,
  Strategy as JwtStrategy,
  StrategyOptions,
  VerifiedCallback,
} from "passport-jwt";

import auth from "./users/authentication.controller";
import { JwtPayload } from "jsonwebtoken";

dotenv.config();

const app = express();

app.use(
  cors({
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(compression());
app.use(cookieParser());

app.use(passport.initialize());

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

const server = http.createServer(app);

app.get("/", passport.authenticate("jwt", { session: false }), (req, res) => {
  res.json({ message: "Hello World" });
});

app.use("/auth", auth);

server.listen(3000, () => {
  console.log("Server is running on port 3000");
});

const MONGO_URL = process.env.DB_URL as string;

mongoose.Promise = Promise;
mongoose.connect(MONGO_URL);
mongoose.connection.on("error", (error: Error) => console.log(error));
