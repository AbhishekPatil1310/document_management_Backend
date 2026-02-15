import crypto from "crypto";
import jwt from "jsonwebtoken";
import db from "../config/db.js";
import { logAudit } from "../utils/audit.js";
import { hashPassword, comparePassword } from "../utils/hash.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import { sendPasswordResetEmail, sendSecurityAlert } from "../utils/mailer.js";

/* ===============================
   CONFIG
================================= */

const MAX_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isProduction = process.env.NODE_ENV === "production";

const accessCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  maxAge: 15 * 60 * 1000
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? "none" : "lax",
  maxAge: 7 * 24 * 60 * 60 * 1000
};

const isValidAuthInput = (email, password) => {
  if (typeof email !== "string" || typeof password !== "string") return false;
  if (!EMAIL_REGEX.test(email.trim().toLowerCase())) return false;
  if (password.length < 8 || password.length > 64) return false;
  return true;
};

/* ===============================
   REGISTER
================================= */

export const register = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!isValidAuthInput(email, password)) {
      return res.status(400).json({ message: "Invalid email or password format" });
    }

    const passwordHash = await hashPassword(password);

    await db.user.create({
      data: {
        email: email.trim().toLowerCase(),
        password_hash: passwordHash
      }
    });

    return res.status(201).json({
      message: "Registration successful"
    });

  } catch (error) {
    if (error.code === "P2002") {
      return res.status(400).json({
        message: "User already exists"
      });
    }
    next(error);
  }
};

/* ===============================
   LOGIN
================================= */

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!isValidAuthInput(email, password)) {
      return res.status(400).json({ message: "Invalid email or password format" });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await db.user.findUnique({
      where: { email: normalizedEmail },
      select: {
        id: true,
        email: true,
        password_hash: true,
        failed_login_attempts: true,
        lock_until: true,
        last_security_alert: true,
        token_version: true
      }
    });

    if (!user) {
      await hashPassword(password);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (user.lock_until && user.lock_until > new Date()) {
      return res.status(423).json({
        message: "Account temporarily locked."
      });
    }

    const valid = await comparePassword(password, user.password_hash);

    if (!valid) {
      const attempts = user.failed_login_attempts + 1;

      if (attempts >= MAX_ATTEMPTS) {
        await db.user.update({
          where: { id: user.id },
          data: {
            failed_login_attempts: 0,
            lock_until: new Date(Date.now() + LOCK_TIME_MS)
          }
        });

        await logAudit({
          userId: user.id,
          action: "ACCOUNT_LOCKED",
          req
        });

        return res.status(423).json({
          message: "Account temporarily locked."
        });
      }

      await db.user.update({
        where: { id: user.id },
        data: { failed_login_attempts: attempts }
      });

      return res.status(401).json({ message: "Invalid credentials" });
    }

    /* Reset counters */
    await db.user.update({
      where: { id: user.id },
      data: {
        failed_login_attempts: 0,
        lock_until: null
      }
    });

    const currentIP = req.ip;
    const currentUA = req.headers["user-agent"] || null;

    /* ===============================
       LOGIN ANOMALY DETECTION
    ================================= */

    const recentSessions = await db.session.findMany({
      where: { user_id: user.id },
      orderBy: { created_at: "desc" },
      take: 5,
      select: {
        ip_address: true,
        user_agent: true
      }
    });

    let anomalyDetected = false;

    for (const session of recentSessions) {
      if (
        session.ip_address !== currentIP ||
        session.user_agent !== currentUA
      ) {
        anomalyDetected = true;
        break;
      }
    }

    if (anomalyDetected) {
      const now = new Date();

      const shouldSendAlert =
        !user.last_security_alert ||
        (now - new Date(user.last_security_alert)) > 15 * 60 * 1000;

      await logAudit({
        userId: user.id,
        action: "LOGIN_ANOMALY_DETECTED",
        req
      });

      if (shouldSendAlert) {
        sendSecurityAlert({
          to: user.email,
          ip: currentIP,
          userAgent: currentUA,
          time: now.toISOString()
        });

        await db.user.update({
          where: { id: user.id },
          data: { last_security_alert: now }
        });
      }
    }

    /* ===============================
       ISSUE TOKENS
    ================================= */

    const accessToken = generateAccessToken(user);
    const refreshTokenValue = generateRefreshToken(user.id);

    const hashedRefresh = crypto
      .createHash("sha256")
      .update(refreshTokenValue)
      .digest("hex");

    await db.session.create({
      data: {
        user_id: user.id,
        token_hash: hashedRefresh,
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ip_address: currentIP,
        user_agent: currentUA
      }
    });

    await logAudit({
      userId: user.id,
      action: "USER_LOGIN",
      req
    });

    res.cookie("accessToken", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshTokenValue, refreshCookieOptions);

    return res.status(200).json({ message: "Login successful" });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   REFRESH TOKEN
================================= */

export const refreshToken = async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const storedSession = await db.session.findFirst({
      where: {
        user_id: decoded.userId,
        token_hash: hashedToken
      }
    });

    if (!storedSession) {
      await db.session.deleteMany({
        where: { user_id: decoded.userId }
      });

      return res.status(403).json({
        message: "Session compromised"
      });
    }

    if (new Date(storedSession.expires_at) < new Date()) {
      await db.session.delete({
        where: { id: storedSession.id }
      });

      return res.status(403).json({
        message: "Refresh token expired"
      });
    }

    const user = await db.user.findUnique({
      where: { id: decoded.userId },
      select: { token_version: true }
    });

    if (!user || user.token_version !== decoded.tokenVersion) {
      return res.status(401).json({ message: "Session invalidated" });
    }

    const result = await db.$transaction(async (tx) => {
      await tx.session.delete({
        where: { id: storedSession.id }
      });

      const newAccessToken = generateAccessToken({
        id: decoded.userId,
        token_version: user.token_version
      });

      const newRefreshToken = generateRefreshToken(decoded.userId);

      const newHashedRefresh = crypto
        .createHash("sha256")
        .update(newRefreshToken)
        .digest("hex");

      await tx.session.create({
        data: {
          user_id: decoded.userId,
          token_hash: newHashedRefresh,
          expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          ip_address: storedSession.ip_address,
          user_agent: storedSession.user_agent
        }
      });

      return { newAccessToken, newRefreshToken };
    });

    res.cookie("accessToken", result.newAccessToken, accessCookieOptions);
    res.cookie("refreshToken", result.newRefreshToken, refreshCookieOptions);

    return res.status(200).json({ message: "Token refreshed" });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   LOGOUT
================================= */

export const logout = async (req, res, next) => {
  try {
    const token = req.cookies.refreshToken;

    if (token) {
      const hashedToken = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

      await db.session.deleteMany({
        where: { token_hash: hashedToken }
      });
    }

    res.clearCookie("accessToken", accessCookieOptions);
    res.clearCookie("refreshToken", refreshCookieOptions);

    return res.status(200).json({ message: "Logged out" });

  } catch (error) {
    next(error);
  }
};


export const logoutAllDevices = async (req, res, next) => {
  try {
    const userId = req.user;

    await db.$transaction(async (tx) => {
      // Delete all refresh sessions
      await tx.session.deleteMany({
        where: { user_id: userId }
      });

      // Invalidate all access tokens instantly
      await tx.user.update({
        where: { id: userId },
        data: {
          token_version: {
            increment: 1
          }
        }
      });
    });

    // Clear current cookies
    res.clearCookie("accessToken", accessCookieOptions);
    res.clearCookie("refreshToken", refreshCookieOptions);

    await logAudit({
      userId,
      action: "ALL_SESSIONS_REVOKED",
      req
    });

    return res.status(200).json({
      message: "Logged out from all devices"
    });

  } catch (error) {
    next(error);
  }
};


export const listSessions = async (req, res, next) => {
  try {
    const userId = req.user;

    const sessions = await db.session.findMany({
      where: { user_id: userId },
      orderBy: { created_at: "desc" },
      select: {
        id: true,
        ip_address: true,
        user_agent: true,
        created_at: true,
        expires_at: true
      }
    });

    return res.status(200).json({
      sessions
    });

  } catch (error) {
    next(error);
  }
};


export const revokeSession = async (req, res, next) => {
  try {
    const userId = req.user;
    const { sessionId } = req.params;

    if (!sessionId) {
      return res.status(400).json({
        message: "Session ID required"
      });
    }

    const session = await db.session.findFirst({
      where: {
        id: sessionId,
        user_id: userId
      }
    });

    if (!session) {
      return res.status(404).json({
        message: "Session not found"
      });
    }

    await db.session.delete({
      where: { id: sessionId }
    });

    await logAudit({
      userId,
      action: "SESSION_REVOKED",
      req
    });

    return res.status(200).json({
      message: "Session revoked"
    });

  } catch (error) {
    next(error);
  }
};



export const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    const normalizedEmail = email?.trim()?.toLowerCase();

    if (!normalizedEmail || !EMAIL_REGEX.test(normalizedEmail)) {
      return res.status(200).json({
        message: "If that email exists, a reset link has been sent."
      });
    }

    const user = await db.user.findUnique({
      where: { email: normalizedEmail }
    });

    // Prevent user enumeration
    if (!user) {
      return res.status(200).json({
        message: "If that email exists, a reset link has been sent."
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await db.user.update({
      where: { id: user.id },
      data: {
        password_reset_token: hashedToken,
        password_reset_expires: expiry
      }
    });

    const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${rawToken}`;

    await sendPasswordResetEmail({
      to: user.email,
      resetLink
    });

    return res.status(200).json({
      message: "If that email exists, a reset link has been sent."
    });

  } catch (error) {
    next(error);
  }
};


export const resetPassword = async (req, res, next) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        message: "Invalid request"
      });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const user = await db.user.findFirst({
      where: {
        password_reset_token: hashedToken,
        password_reset_expires: {
          gt: new Date()
        }
      }
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired token"
      });
    }

    const newPasswordHash = await hashPassword(newPassword);

    await db.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: user.id },
        data: {
          password_hash: newPasswordHash,
          password_reset_token: null,
          password_reset_expires: null,
          failed_login_attempts: 0,
          lock_until: null,
          token_version: {
            increment: 1
          }
        }
      });

      await tx.session.deleteMany({
        where: { user_id: user.id }
      });
    });

    await logAudit({
      userId: user.id,
      action: "PASSWORD_RESET",
      req
    });

    return res.status(200).json({
      message: "Password reset successful"
    });

  } catch (error) {
    next(error);
  }
};
