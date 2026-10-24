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
import { validate } from "../utils/helperFuntions";
import { string } from "zod";

export const register = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { username, email, password } = req.body;

    if (
      typeof username !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      !username?.trim() ||
      !email?.trim() ||
      !password.trim()
    ) {
      return next(new AppError("All Fields are Required", 400));
    }

    const normalizedEmail = email.trim().toLowerCase();

    if (!validate.isEmail(normalizedEmail)) {
      return next(new AppError("Please enter valid email id", 400));
    }

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return next(new AppError("User Already exists", 400));
    }

    const user = await User.create({
      username,
      password,
      email: normalizedEmail,
    });

    const otp = generateOtp();

    const hashedOtp = await bcrypt.hash(otp, 10);

    user.otp = {
      code: hashedOtp,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      attempts: 0,
    };

    await user.save();

    const content = verifyAccountTemplate(user.username, otp);

    //Temporarily Stopped for Development

    if (process.env.NODE_ENV != "development") {
      await sendOtpEmail(user.email, "Verify Account - OTP", content);
    } else {
      console.log("The OTP for the User is " + otp);
    }

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

    if (!user.isVerified) {
      return next(new AppError("Please Verify your account", 403));
    }

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

export const verifyOTP = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, otp } = req.body;

    if (!email?.trim() || !otp?.trim()) {
      return next(new AppError("Email and OTP are required", 400));
    }

    if (!validate.isEmail(email)) {
      return next(new AppError("Enter Valid email is", 400));
    }

    const user = await User.findOne({ email });

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    const now = new Date();

    if (user.lockedUntil && user.lockedUntil <= now) {
      user.lockedUntil = null;
      user.otp.attempts = 0;
      await user.save();
    }

    if (user.lockedUntil && user.lockedUntil > now) {
      return next(
        new AppError(
          "Account is temporarily locked. Please try again later.",
          423,
        ),
      );
    }

    if (!user.otp.code) {
      return next(
        new AppError("OTP not found. Please request a new OTP.", 400),
      );
    }

    if (user.otp.expiresAt <= now) {
      user.otp.code = "";
      user.otp.attempts = 0;

      await user.save();

      return next(
        new AppError("OTP has expired. Please request a new OTP.", 400),
      );
    }

    const isValidOtp = await bcrypt.compare(otp, user.otp.code);

    if (!isValidOtp) {
      user.otp.attempts++;

      if (user.otp.attempts >= 3) {
        user.lockedUntil = new Date(Date.now() + 5 * 60 * 1000);

        await user.save();

        return next(
          new AppError(
            "Too many invalid OTP attempts. Your account has been locked for 5 minutes.",
            423,
          ),
        );
      }

      await user.save();

      return next(new AppError("Invalid OTP.", 401));
    }
    user.isVerified = true;

    user.otp = {
      code: "",
      expiresAt: now,
      attempts: 0,
    };

    user.lockedUntil = null;

    await user.save();

    const responseUser = {
      id: user._id,
      username: user.username,
      email: user.email,
      avatar: user.avatar,
      isVerified: user.isVerified,
    };

    return res
      .status(200)
      .json(apiResponse(true, "Account verified successfully.", responseUser));
  },
);

export const resendOTP = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    if (!email?.trim()) {
      return next(new AppError("Email is required.", 400));
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim(),
    });

    if (!user) {
      return next(new AppError("User not found.", 404));
    }

    if (user.isVerified) {
      return next(new AppError("Email is already verified.", 400));
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      return next(
        new AppError("Too many failed attempts. Please try again later.", 429),
      );
    }

    const otp = generateOtp();

    const hashedOTP = await bcrypt.hash(otp, 10);

    user.otp.code = hashedOTP;
    user.otp.expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    user.otp.attempts = 0;

    await user.save();
    const content = verifyAccountTemplate(user.username, otp);

    //Mail services are off for development
    if (process.env.NODE_ENV != "development") {
      await sendOtpEmail(user.email, "Thoodhu OTP verification", content);
    } else {
      console.log("Otp : ", otp);
    }

    return res
      .status(200)
      .json(apiResponse(true, "A new OTP has been sent to your email."));
  },
);
