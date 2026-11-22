import { AppError } from "../../../utils/AppError";
import { validate } from "../../../utils/helperFuntions";

import {
  AUTH_CONSTANTS,
  AUTH_HTTP_STATUS,
  AUTH_VALIDATE_MESSAGES,
} from "../constants/auth.constants";

import type {
  RegisterInput,
  LoginInput,
  VerifyOtpInput,
  ResendOtpInput,
  SafeUser,
} from "../interfaces/auth.interface";

import type { IUser } from "../../../models/user.model";

export const normalizeEmail = (email: string): string =>
  email.trim().toLowerCase();

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const parseObject = (input: unknown): Record<string, unknown> => {
  if (!isRecord(input)) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.INVALID_BODY,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  return input;
};

export const isDuplicateKeyError = (error: unknown): boolean =>
  isRecord(error) && error.code === 11000;

export const toSafeUser = (user: IUser): SafeUser => ({
  id: user._id.toString(),
  username: user.username,
  displayName: user.displayName,
  email: user.email,
  avatar: user.avatar ?? "",
  bio: user.bio,
  isVerified: user.isVerified,
  isActive: user.isActive,
  lastSeen: user.lastSeen,
  createdAt: user.createdAt,
});

export const validateRegistrationInput = (input: unknown): RegisterInput => {
  const body = parseObject(input);
  const { username, email, password } = body;

  if (
    typeof username !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string" ||
    !username.trim() ||
    !email.trim() ||
    !password
  ) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.ALL_FIELDS,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  const normalizedUsername = username.trim().toLowerCase();
  const normalizedEmail = normalizeEmail(email);

  if (
    normalizedUsername.length < AUTH_CONSTANTS.USERNAME.MIN_LENGTH ||
    normalizedUsername.length > AUTH_CONSTANTS.USERNAME.MAX_LENGTH
  ) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.USERNAME_LENGTH,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  if (!/^[a-z0-9_]+$/.test(normalizedUsername)) {
    throw new AppError(
      "Username can contain only letters, numbers and underscores.",
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  if (!validate.isEmail(normalizedEmail)) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.VALID_EMAIL,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  if (password.length < AUTH_CONSTANTS.PASSWORD.MIN_LENGTH) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.PASSWORD_LENGTH,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  return {
    username: normalizedUsername,
    email: normalizedEmail,
    password,
  };
};

export const validateLoginInput = (input: unknown): LoginInput => {
  const body = parseObject(input);
  const { emailOrUsername, password } = body;

  if (
    typeof emailOrUsername !== "string" ||
    typeof password !== "string" ||
    !emailOrUsername.trim() ||
    !password
  ) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.ALL_FIELDS,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  return {
    emailOrUsername: emailOrUsername.trim(),
    password,
  };
};

export const validateOtpInput = (input: unknown): VerifyOtpInput => {
  const body = parseObject(input);
  const { email, otp } = body;

  if (
    typeof email !== "string" ||
    typeof otp !== "string" ||
    !email.trim() ||
    !otp.trim()
  ) {
    throw new AppError(
      "Email and OTP are required.",
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  const normalizedEmail = normalizeEmail(email);
  const normalizedOtp = otp.trim();

  if (!validate.isEmail(normalizedEmail)) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.VALID_EMAIL,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  if (!new RegExp(`^\\d{${AUTH_CONSTANTS.OTP.LENGTH}}$`).test(normalizedOtp)) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.INVALID_OTP_FORMAT,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  return {
    email: normalizedEmail,
    otp: normalizedOtp,
  };
};

export const validateResendInput = (input: unknown): ResendOtpInput => {
  const body = parseObject(input);
  const { email } = body;

  if (typeof email !== "string" || !email.trim()) {
    throw new AppError("Email is required.", AUTH_HTTP_STATUS.BAD_REQUEST);
  }

  const normalizedEmail = normalizeEmail(email);

  if (!validate.isEmail(normalizedEmail)) {
    throw new AppError(
      AUTH_VALIDATE_MESSAGES.VALID_EMAIL,
      AUTH_HTTP_STATUS.BAD_REQUEST,
    );
  }

  return { email: normalizedEmail };
};
