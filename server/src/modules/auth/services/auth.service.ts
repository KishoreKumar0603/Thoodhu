import bcrypt from "bcryptjs";

import User from "../../../models/user.model";
import { AppError } from "../../../utils/AppError";
import { generateToken } from "../../../utils/generateToken";
import { generateOtp } from "../../../utils/generateOtp";
import { sendOtpEmail } from "../../../services/email.service";
import { verifyAccountTemplate } from "../../../utils/mailContent.utils";

import {
  AUTH_CONSTANTS,
  AUTH_HTTP_STATUS,
  AUTH_MESSAGES,
  ACCOUNT_MESSAGES,
} from "../constants/auth.constants";

import {
  isDuplicateKeyError,
  normalizeEmail,
  toSafeUser,
  validateRegistrationInput,
  validateLoginInput,
  validateOtpInput,
  validateResendInput,
} from "../helpers/auth.helper";

import type { SafeUser, LoginResult } from "../interfaces/auth.interface";

// ─────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────

const OTP_EXPIRY_MS = AUTH_CONSTANTS.OTP.EXPIRY_MINUTES * 60 * 1000;

const OTP_LOCK_DURATION_MS =
  AUTH_CONSTANTS.OTP.LOCK_DURATION_MINUTES * 60 * 1000;

const OTP_MAX_ATTEMPTS = AUTH_CONSTANTS.OTP.MAX_ATTEMPTS;

const BCRYPT_ROUNDS = AUTH_CONSTANTS.PASSWORD.BCRYPT_ROUNDS;

const OTP_SELECT_FIELDS = "+otp.code +otp.expiresAt +otp.attempts +lockedUntil";

const sendVerificationOtp = async (
  username: string,
  email: string,
  otp: string,
): Promise<void> => {
  const content = verifyAccountTemplate(username, otp);

  if (process.env.NODE_ENV === "development") {
    // Development only. Never log real OTPs in production.
    console.info(`[Development OTP] ${email}: ${otp}`);
    return;
  }

  try {
    await sendOtpEmail(email, "Thoodhu - Account Verification", content);
  } catch {
    throw new AppError(
      AUTH_MESSAGES.EMAIL_SEND_FAILED,
      AUTH_HTTP_STATUS.SERVICE_UNAVAILABLE,
    );
  }
};

const createHashedOtp = async (): Promise<string> => {
  const otp = generateOtp();
  return bcrypt.hash(otp, BCRYPT_ROUNDS);
};

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────

export const register = async (input: unknown): Promise<void> => {
  const { username, email, password } = validateRegistrationInput(input);

  const existingUser = await User.findOne({
    $or: [{ email }, { username }],
  });

  if (existingUser) {
    throw new AppError(
      ACCOUNT_MESSAGES.ACCOUNT_ALREADY_EXISTS,
      AUTH_HTTP_STATUS.CONFLICT,
    );
  }

  let user;

  try {
    user = await User.create({
      username,
      email,
      password,
    });
  } catch (error: unknown) {
    if (isDuplicateKeyError(error)) {
      throw new AppError(
        ACCOUNT_MESSAGES.ACCOUNT_ALREADY_EXISTS,
        AUTH_HTTP_STATUS.CONFLICT,
      );
    }

    throw error;
  }

  const otp = generateOtp();
  const hashedOtp = await bcrypt.hash(otp, BCRYPT_ROUNDS);

  user.otp = {
    code: hashedOtp,
    expiresAt: new Date(Date.now() + OTP_EXPIRY_MS),
    attempts: 0,
  };

  await user.save();

  await sendVerificationOtp(user.username, user.email, otp);
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────

export const login = async (input: unknown): Promise<LoginResult> => {
  const { emailOrUsername, password } = validateLoginInput(input);

  const identifier = emailOrUsername;
  const normalizedIdentifier = identifier.toLowerCase();

  const user = await User.findOne({
    $or: [{ email: normalizedIdentifier }, { username: normalizedIdentifier }],
  }).select("+password +lockedUntil");

  if (!user) {
    throw new AppError(
      AUTH_MESSAGES.INVALID_CREDENTIALS,
      AUTH_HTTP_STATUS.UNAUTHORIZED,
    );
  }

  const isPasswordValid = await user.comparePassword(password);

  if (!isPasswordValid) {
    throw new AppError(
      AUTH_MESSAGES.INVALID_CREDENTIALS,
      AUTH_HTTP_STATUS.UNAUTHORIZED,
    );
  }

  // Check account lifecycle after credential verification.
  if (user.isDeleted) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_DELETED,
      AUTH_HTTP_STATUS.FORBIDDEN,
    );
  }

  if (!user.isActive) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_DEACTIVATED,
      AUTH_HTTP_STATUS.FORBIDDEN,
    );
  }

  if (!user.isVerified) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_NOT_VERIFIED,
      AUTH_HTTP_STATUS.FORBIDDEN,
    );
  }

  if (user.lockedUntil && user.lockedUntil > new Date()) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_TEMP_LOCKED,
      AUTH_HTTP_STATUS.LOCKED,
    );
  }

  const token = generateToken(user._id.toString());

  return {
    token,
    user: toSafeUser(user),
  };
};

// ─────────────────────────────────────────────
// VERIFY REGISTRATION OTP
// ─────────────────────────────────────────────

export const verifyOTP = async (input: unknown): Promise<SafeUser> => {
  const { email, otp } = validateOtpInput(input);

  const user = await User.findOne({ email }).select(OTP_SELECT_FIELDS);

  if (!user) {
    throw new AppError(AUTH_MESSAGES.INVALID_OTP, AUTH_HTTP_STATUS.BAD_REQUEST);
  }

  if (user.isDeleted || !user.isActive) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_DEACTIVATED,
      AUTH_HTTP_STATUS.FORBIDDEN,
    );
  }

  if (user.isVerified) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_ALREADY_VERIFIED,
      AUTH_HTTP_STATUS.CONFLICT,
    );
  }

  const now = new Date();

  // Reset expired lockout.
  if (user.lockedUntil && user.lockedUntil <= now) {
    user.lockedUntil = null;
    user.otp.attempts = 0;

    await user.save();
  }

  if (user.lockedUntil && user.lockedUntil > now) {
    throw new AppError(
      AUTH_MESSAGES.TOO_MANY_OTP_ATTEMPTS,
      AUTH_HTTP_STATUS.LOCKED,
    );
  }

  if (!user.otp.code) {
    throw new AppError(
      AUTH_MESSAGES.OTP_NOT_FOUND,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  if (!user.otp.expiresAt || user.otp.expiresAt <= now) {
    user.otp.code = "";
    user.otp.expiresAt = null;
    user.otp.attempts = 0;

    await user.save();

    throw new AppError(AUTH_MESSAGES.EXPIRED_OTP, AUTH_HTTP_STATUS.BAD_REQUEST);
  }

  const isValidOtp = await bcrypt.compare(otp, user.otp.code);

  if (!isValidOtp) {
    user.otp.attempts += 1;

    if (user.otp.attempts >= OTP_MAX_ATTEMPTS) {
      user.lockedUntil = new Date(Date.now() + OTP_LOCK_DURATION_MS);

      await user.save();

      throw new AppError(
        AUTH_MESSAGES.TOO_MANY_OTP_ATTEMPTS,
        AUTH_HTTP_STATUS.LOCKED,
      );
    }

    await user.save();

    throw new AppError(
      AUTH_MESSAGES.INVALID_OTP,
      AUTH_HTTP_STATUS.UNAUTHORIZED,
    );
  }

  // Successfully verified.
  user.isVerified = true;

  user.otp.code = "";
  user.otp.expiresAt = null;
  user.otp.attempts = 0;

  user.lockedUntil = null;

  await user.save();

  return toSafeUser(user);
};

// ─────────────────────────────────────────────
// RESEND REGISTRATION OTP
// ─────────────────────────────────────────────

export const resendOTP = async (input: unknown): Promise<void> => {
  const { email } = validateResendInput(input);

  const user = await User.findOne({ email }).select(OTP_SELECT_FIELDS);

  // Generic response prevents revealing whether an email exists.
  if (!user || user.isVerified || user.isDeleted || !user.isActive) {
    return;
  }

  const now = new Date();

  if (user.lockedUntil && user.lockedUntil > now) {
    throw new AppError(
      AUTH_MESSAGES.ACCOUNT_TEMP_LOCKED,
      AUTH_HTTP_STATUS.LOCKED,
    );
  }

  const otp = generateOtp();
  const hashedOtp = await bcrypt.hash(otp, BCRYPT_ROUNDS);

  user.otp.code = hashedOtp;
  user.otp.expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);
  user.otp.attempts = 0;

  await user.save();

  await sendVerificationOtp(user.username, user.email, otp);
};
