import express from "express";
import { register, login, refreshToken, logout, logoutAllDevices, listSessions, revokeSession,forgotPassword, resetPassword} from "../controller/auth.controller.js";
import { authLimiter } from "../middleware/ratelimit.middleware.js";
import { protect } from "../middleware/auth.middleware.js";

const router = express.Router();

/* ===============================
   ROUTES
================================= */

/**
 * Register
 */
router.post(
  "/register",
  authLimiter,
  register
);

/**
 * Login
 */
router.post(
  "/login",
  authLimiter,
  login
);

/**
 * Refresh Access Token (Rotation)
 */
router.post(
  "/refresh",
  authLimiter,
  refreshToken
);

/**
 * Logout (Invalidate Refresh Token)
 */
router.post(
  "/logout",
  protect,
  logout
);

/**
 * Protected test route
 */
router.get(
  "/me",
  protect,
  (req, res) => {
    res.status(200).json({
      userId: req.user
    });
  }
);


router.post("/logout-all", protect, logoutAllDevices);
router.get("/sessions", protect, listSessions);
router.delete("/sessions/:sessionId", protect, revokeSession);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);


export default router;
