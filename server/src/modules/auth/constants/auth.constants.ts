export const AUTH_CONSTANTS = {
  OTP: {
    LENGTH: 6,
    EXPIRY_MINUTES: 10,
    MAX_ATTEMPTS: 3,
    LOCK_DURATION_MINUTES: 5,
  },

  PASSWORD: {
    MIN_LENGTH: 6,
    BCRYPT_ROUNDS: 12,
  },

  USERNAME: {
    MIN_LENGTH: 5,
    MAX_LENGTH: 30,
  },

  TOKEN: {
    COOKIE_NAME: "token",
    EXPIRY_DAYS: 7,
  },
} as const;

export const AUTH_HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  LOCKED: 423,
  SERVICE_UNAVAILABLE: 503,
} as const;

export const AUTH_MESSAGES = {
  REGISTRATION_SUCCESS: "OTP sent successfully.",
  LOGIN_SUCCESS: "Logged in successfully.",
  LOGOUT_SUCCESS: "Logged out successfully.",
  ACCOUNT_VERIFIED: "Account verified successfully.",
  ACCOUNT_NOT_VERIFIED: "Please verify your account first.",
  ACCOUNT_DEACTIVATED: "Your account is deactivated.",
  ACCOUNT_DELETED: "This account is no longer available.",
  ACCOUNT_ALREADY_VERIFIED: "Account is already verified.",
  ACCOUNT_TEMP_LOCKED: "Account is temporarily locked. Please try again later.",
  INVALID_CREDENTIALS: "Invalid credentials.",
  INVALID_OTP: "Invalid OTP.",
  OTP_NOT_FOUND: "OTP not found. Please request a new OTP.",
  EXPIRED_OTP: "OTP has expired. Please request a new OTP.",
  TOO_MANY_OTP_ATTEMPTS:
    "Too many invalid OTP attempts. Please try again later.",
  OTP_RESEND_GENERIC:
    "If the account requires verification, instructions will be sent.",
  EMAIL_SEND_FAILED:
    "Unable to send verification email. Please try again later.",
} as const;

export const AUTH_VALIDATE_MESSAGES = {
  ALL_FIELDS: "All fields are required.",
  USERNAME_LENGTH: "Username must contain between 5 and 30 characters.",
  PASSWORD_LENGTH: "Password must contain at least 6 characters.",
  VALID_EMAIL: "Please enter a valid email address.",
  INVALID_OTP_FORMAT: "Please enter a valid 6-digit OTP.",
  INVALID_BODY: "Invalid request body.",
} as const;

export const ACCOUNT_MESSAGES = {
  ACCOUNT_ALREADY_EXISTS: "An account with those details already exists.",
} as const;