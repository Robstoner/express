import { Router } from "express";
import passport from "passport";

export const router = Router();

router.post(
  "/signup",
  passport.authenticate("signup", { session: false }),
  (req, res) => {
    
  }
);
