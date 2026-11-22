import type { Request, Response } from "express";

import { asyncHandler } from "../../../utils/asyncHandler";
import { apiResponse } from "../../../utils/apiResponse";

import * as authService from "../services/auth.service";

import {
  AUTH_CONSTANTS,
  AUTH_MESSAGES,
  AUTH_HTTP_STATUS,
} from "../constants/auth.constants";

// Cookie configuration
const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/",
});

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────

export const register = asyncHandler(async (req: Request, res: Response) => {
  await authService.register(req.body);

  return res
    .status(AUTH_HTTP_STATUS.CREATED)
    .json(apiResponse(true, AUTH_MESSAGES.REGISTRATION_SUCCESS));
});

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────

export const login = asyncHandler(async (req: Request, res: Response) => {
  const result = await authService.login(req.body);

  const maxAge = AUTH_CONSTANTS.TOKEN.EXPIRY_DAYS * 24 * 60 * 60 * 1000;

  res.cookie(AUTH_CONSTANTS.TOKEN.COOKIE_NAME, result.token, {
    ...getCookieOptions(),
    maxAge,
  });

  return res
    .status(AUTH_HTTP_STATUS.OK)
    .json(apiResponse(true, AUTH_MESSAGES.LOGIN_SUCCESS, result.user));
});

// ─────────────────────────────────────────────
// LOGOUT
// ─────────────────────────────────────────────

export const logout = asyncHandler(async (_req: Request, res: Response) => {
  res.clearCookie(AUTH_CONSTANTS.TOKEN.COOKIE_NAME, getCookieOptions());

  return res
    .status(AUTH_HTTP_STATUS.OK)
    .json(apiResponse(true, AUTH_MESSAGES.LOGOUT_SUCCESS));
});

// ─────────────────────────────────────────────
// VERIFY OTP
// ─────────────────────────────────────────────

export const verifyOTP = asyncHandler(async (req: Request, res: Response) => {
  const user = await authService.verifyOTP(req.body);

  return res
    .status(AUTH_HTTP_STATUS.OK)
    .json(apiResponse(true, AUTH_MESSAGES.ACCOUNT_VERIFIED, user));
});

// ─────────────────────────────────────────────
// RESEND OTP
// ─────────────────────────────────────────────

export const resendOTP = asyncHandler(async (req: Request, res: Response) => {
  await authService.resendOTP(req.body);

  return res
    .status(AUTH_HTTP_STATUS.OK)
    .json(apiResponse(true, AUTH_MESSAGES.OTP_RESEND_GENERIC));
});
