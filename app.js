import express from "express";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import dotenv from "dotenv";

import {startCleanupJob } from "./jobs/cleanup.js";
import authRoutes from "./routes/auth.routes.js";
import documentRoutes from "./routes/document.routes.js";


dotenv.config();

const app = express();

/* ===============================
   TRUST PROXY (IMPORTANT IN PROD)
================================= */
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

/* ===============================
   SECURITY MIDDLEWARE
================================= */
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false,
  })
);


app.use(hpp()); // Prevent HTTP parameter pollution

/* ===============================
   GLOBAL RATE LIMIT
================================= */
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests, try again later"
});

app.use(globalLimiter);

/* ===============================
   CORS CONFIGURATION
================================= */
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

/* ===============================
   BODY PARSING
================================= */
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(cookieParser());
app.use(compression());

/* ===============================
   ROUTES
================================= */
app.use("/api/auth", authRoutes);
app.use("/api/documents", documentRoutes);
startCleanupJob();


/* ===============================
   HEALTH CHECK
================================= */
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: Date.now()
  });
});

/* ===============================
   404 HANDLER
================================= */
app.use((req, res) => {
  res.status(404).json({
    message: "Route not found"
  });
});

/* ===============================
   GLOBAL ERROR HANDLER
================================= */
app.use((err, req, res, next) => {
  console.error("Error:", err);

  res.status(err.status || 500).json({
    message:
      process.env.NODE_ENV === "production"
        ? "Internal Server Error"
        : err.message
  });
});

export default app;
