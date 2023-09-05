import express from "express";
import http from "http";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import compression from "compression";
import cors from "cors";
import mongoose from "mongoose";
import passport from "passport";
import dotenv from "dotenv";
import auth from "@/users/authentication.controller"

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

const server = http.createServer(app);

app.use("/auth", auth);

server.listen(3000, () => {
  console.log("Server is running on port 3000");
});

const MONGO_URL = process.env.DB_URL as string;

mongoose.Promise = Promise;
mongoose.connect(MONGO_URL);
mongoose.connection.on("error", (error: Error) => console.log(error));
