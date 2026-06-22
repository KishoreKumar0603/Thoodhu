import mongoose from "mongoose";

export const connectDB = async (): Promise<void> => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI as string);

    console.log(`MongoDB Connected : ${conn.connection.name}`);
  } catch (error) {
    console.log("MongoDB Connection Failed");

    process.exit(1);
  }
};
