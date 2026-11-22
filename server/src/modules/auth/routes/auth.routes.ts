import { Router } from "express";
import {
  register,
  login,
  logout,
  verifyOTP,
  resendOTP,
} from "../controllers/auth.controller";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);

export default router;
