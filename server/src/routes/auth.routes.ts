import { Router } from "express";
import { login, logout, register, resendOTP, verifyOTP } from "../controllers/auth.controller";
const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);
router.post("/verify-otp", verifyOTP);
router.post("/resend-otp", resendOTP);

export default router;
