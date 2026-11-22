export interface RegisterInput {
  username: string;
  email: string;
  password: string;
}

export interface LoginInput {
  emailOrUsername: string;
  password: string;
}

export interface VerifyOtpInput {
  email: string;
  otp: string;
}

export interface ResendOtpInput {
  email: string;
}

export interface SafeUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
  avatar: string;
  bio: string;
  isVerified: boolean;
  isActive: boolean;
  lastSeen: Date;
  createdAt: Date;
}

export interface LoginResult {
  token: string;
  user: SafeUser;
}