import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { errorHandler } from "./middleware/errorHandler";
import authRoutes from "./routes/auth.routes"

const app = express();

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(helmet());

app.use("/api/auth", authRoutes);

app.get("/", (_req, res) => {
  res.status(200).json({
    success: true,
    message: "Thoodhu API Running",
  });
});

app.use(errorHandler)

export default app;