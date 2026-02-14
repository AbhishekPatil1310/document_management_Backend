import rateLimit from "express-rate-limit";

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: "Too many authentication attempts"
});



export const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // 30 upload URL requests per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many upload attempts. Try again later."
});
