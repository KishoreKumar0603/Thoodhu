import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcryptjs";

export interface IOtp {
  code: string;
  expiresAt: Date | null;
  attempts: number;
}

export interface IEmailChangeOtp {
  code: string;
  expiresAt: Date | null;
  attempts: number;
  lockedUntil: Date | null;
}

export interface IUser extends Document {
  username: string;
  displayName: string;
  email: string;
  password: string;

  avatar: string;
  bio: string;

  otp: IOtp;
  emailChangeOtp: IEmailChangeOtp;
  pendingEmail: string | null;

  isVerified: boolean;

  isActive: boolean;
  deactivatedAt: Date | null;

  isDeleted: boolean;
  deletedAt: Date | null;

  lastSeen: Date;

  lockedUntil: Date | null;

  createdAt: Date;
  updatedAt: Date;

  comparePassword(password: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      minlength: 5,
      maxlength: 30,
    },

    displayName: {
      type: String,
      trim: true,
      default: "",
      maxlength: 50,
    },

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
    },

    password: {
      type: String,
      required: true,
      minlength: 6,
      select: false,
    },

    avatar: {
      type: String,
      default: "",
    },

    bio: {
      type: String,
      trim: true,
      default: "",
      maxlength: 160,
    },

    otp: {
      code: {
        type: String,
        default: "",
        select: false,
      },

      expiresAt: {
        type: Date,
        default: null,
        select: false,
      },

      attempts: {
        type: Number,
        default: 0,
        min: 0,
        select: false,
      },
    },

    emailChangeOtp: {
      code: {
        type: String,
        default: "",
        select: false,
      },

      expiresAt: {
        type: Date,
        default: null,
        select: false,
      },

      attempts: {
        type: Number,
        default: 0,
        min: 0,
        select: false,
      },

      lockedUntil: {
        type: Date,
        default: null,
        select: false,
      },
    },

    pendingEmail: {
      type: String,
      default: null,
      trim: true,
      lowercase: true,
      select: false,
    },

    isVerified: {
      type: Boolean,
      default: false,
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    deactivatedAt: {
      type: Date,
      default: null,
    },

    isDeleted: {
      type: Boolean,
      default: false,
    },

    deletedAt: {
      type: Date,
      default: null,
    },

    lastSeen: {
      type: Date,
      default: Date.now,
    },

    lockedUntil: {
      type: Date,
      default: null,
      select: false,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

userSchema.pre("save", async function () {
  if (!this.isModified("password")) {
    return;
  }

  const salt = await bcrypt.genSalt(12);

  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (
  password: string,
): Promise<boolean> {
  return bcrypt.compare(password, this.password);
};

userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ isActive: 1, isDeleted: 1 });
userSchema.index({ lastSeen: -1 });

const User = mongoose.models.User || mongoose.model<IUser>("User", userSchema);

export default User;
