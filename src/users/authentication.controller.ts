import { Router } from "express";
import passport from "passport";
import { generateToken } from "@/helpers/jwt";
import { IUser } from "./users.model";

const router = Router();

router.post(
  "/signup",
  passport.authenticate("signup", { session: false }),
  (req, res) => {

    console.log(req.user);
    const user: IUser = req.user as IUser;
    console.log(user);

    const token = generateToken(user.email);

    res.json({ user, token });
  }
);

export default router ;