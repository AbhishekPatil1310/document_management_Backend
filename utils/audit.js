import db from "../config/db.js";

export const logAudit = async ({
  userId,
  action,
  documentId = null,
  req
}) => {
  try {
    await db.auditLog.create({
      data: {
        user_id: userId,
        action,
        document_id: documentId,
        ip_address: req.ip,
        user_agent: req.headers["user-agent"] || null
      }
    });
  } catch (error) {
    // Do not break main request if audit fails
    console.error("Audit log error:", error);
  }
};
