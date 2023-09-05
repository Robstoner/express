import { Router } from "express";
import passport from "passport";
import { generateToken } from "../helpers/jwt";
import { IUser, UserModel } from "./users.model";

const router = Router();

router.get(
  "/logout",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const user: IUser = req.user as IUser;

    const userObject = await UserModel.getUserByEmail(user.email);

    userObject.tokens?.forEach((token) => {
      token.isValid = false;
    });

    userObject.save();

    res.json({ message: "User logged out" });
  }
);

router.post(
  "/signup",
  passport.authenticate("signup", { session: false }),
  async (req, res) => {
    const user: IUser = req.user as IUser;

    const userObject = await UserModel.getUserByEmail(user.email);

    const token = generateToken(user.email);

    userObject.tokens?.push({
      token,
      expires: new Date(
        Date.now() + Number(process.env.JWT_EXPIRATION_TIME) * 1000
      ),
      isValid: true,
    });

    userObject.save();

    res.json({ user, token });
  }
);

router.post(
  "/login",
  passport.authenticate("password", { session: false }),
  async (req, res) => {
    const user: IUser = req.user as IUser;

    const userObject = await UserModel.getUserByEmail(user.email);

    const token = generateToken(user.email);

    userObject.tokens?.push({
      token,
      expires: new Date(
        Date.now() + Number(process.env.JWT_EXPIRATION_TIME) * 1000
      ),
      isValid: true,
    });

    userObject.save();

    res.json({ user, token });
  }
);

export default router;
