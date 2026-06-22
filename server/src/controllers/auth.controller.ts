import { Response, Request, NextFunction } from "express";
import { AppError } from "../utils/AppError";
import User from "../models/user.model";
import { asyncHandler } from "../utils/asyncHandler";
import { apiResponse } from "../utils/apiResponse";
import { generateToken } from "../utils/generateToken";
import bcrypt from "bcryptjs";
import { generateOtp } from "../utils/generateOtp";
import { sendOtpEmail } from "../services/email.service";
import { verifyAccountTemplate } from "../utils/mailContent.utils";


export const register = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      throw new AppError("User Already exists", 400);
    }

    const user = await User.create({
      username,
      password,
      email,
    });

    const otp = generateOtp();

    const hashedOtp = await bcrypt.hash(otp, 10);

    user.otp = {
      code: hashedOtp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    };

    await user.save();

    const content = verifyAccountTemplate(user.username, otp);

    await sendOtpEmail(user.email, otp, "Verify Account - OTP", content);

    return res.status(201).json(apiResponse(true, "OTP sent successfully"));
  },
);

export const login = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { emailOrUsername, password } = req.body;

    if (!emailOrUsername?.trim() || !password?.trim()) {
      return next(new AppError("All fields are required", 400));
    }

    const user = await User.findOne({
      $or: [{ email: emailOrUsername }, { username: emailOrUsername }],
    }).select("+password");
    if (!user) {
      return next(new AppError("Invalid Credentials", 404));
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return next(new AppError("Invalid Credentials", 401));
    }

    // if (!user.isVerified) {
    //   return next(new AppError("Please Verify your account", 403));
    // }

    const token = generateToken(user._id.toString());
    console.log("after token");

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json(apiResponse(true, "Logged In", user));
  },
);

export const logout = asyncHandler(async (req: Request, res: Response) => {
  res.cookie("token", "", {
    expires: new Date(0),
  });

  res.status(200).json(apiResponse(true, "Logout Successfull"));
});
