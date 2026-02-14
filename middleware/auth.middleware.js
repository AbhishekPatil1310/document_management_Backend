import jwt from "jsonwebtoken";
import db from "../config/db.js";

/* ===============================
   AUTHENTICATION MIDDLEWARE
   Verifies Access Token + token_version
================================= */

export const protect = async (req, res, next) => {
  try {
    const token = req.cookies?.accessToken;

    if (!token) {
      return res.status(401).json({
        message: "Unauthorized"
      });
    }

    let decoded;

    try {
      decoded = jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET
      );
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "Access token expired"
        });
      }

      return res.status(403).json({
        message: "Invalid token"
      });
    }

    // Validate user existence + token_version
    const user = await db.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        token_version: true
      }
    });

    if (!user) {
      return res.status(401).json({
        message: "User no longer exists"
      });
    }

    // Instant invalidation check
    if (user.token_version !== decoded.tokenVersion) {
      return res.status(401).json({
        message: "Session invalidated"
      });
    }

    // Attach minimal safe data
    req.user = user.id;

    return next();

  } catch (error) {
    return res.status(500).json({
      message: "Authentication failed"
    });
  }
};
