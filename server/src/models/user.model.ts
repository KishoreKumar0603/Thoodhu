import mongoose, { Document, Schema } from "mongoose";
import bcrypt from "bcryptjs";

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  avatar?: string;
  otp: {
    code: string;
    expiresAt: Date;
    attempts: number;
  };
  isVerified: boolean;
  lastSeen: Date;

  lockedUntil: Date | null;
  isLocked: {
    locked: boolean;
    expiresAt: Date;
  };
  comparePassword(password: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      minLength: 5,
      maxLength: 30,
      index:true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      index:true,
    },
    password: {
      type: String,
      required: true,
      minLength: 6,
      select: false,
    },
    avatar: {
      type: String,
      default: "",
    },
    otp: {
      code: {
        type: String,
        default: null,
      },

      expiresAt: {
        type: Date,
        default: null,
      },
      attempts: {
        type: Number,
        default: 0,
      },
    },
    lockedUntil: {
      type: Date,
      default: null,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    lastSeen: {
      type: Date,
      default: Date.now(),
    },
  },
  {
    timestamps: true,
  },
);

userSchema.pre("save", async function () {
  if (!this.isModified("password")) {
    return;
  }

  const salt = await bcrypt.genSalt(10);

  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (password: string) {
  return bcrypt.compare(password, this.password);
};

export default mongoose.model<IUser>("User", userSchema);
