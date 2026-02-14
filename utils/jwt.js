import jwt from "jsonwebtoken";

/* ===============================
   ACCESS TOKEN
   Includes tokenVersion for instant invalidation
================================= */

export const generateAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      tokenVersion: user.token_version
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRE
    }
  );
};

/* ===============================
   REFRESH TOKEN
   Only contains userId
   (validated via session table)
================================= */

export const generateRefreshToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRE
    }
  );
};
