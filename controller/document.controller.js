import {
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand
} from "@aws-sdk/client-s3";

import { logAudit } from "../utils/audit.js";

import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import crypto from "crypto";
import db from "../config/db.js";
import s3 from "../config/s3.js";

/* ===============================
   CONFIG
================================= */

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const ALLOWED_TYPES = [
  "application/pdf",
  "image/jpeg",
  "image/png"
];

const UPLOAD_WINDOW_MS = 15 * 60 * 1000;
const MAX_UPLOADS_PER_WINDOW = 20;

/* ===============================
   GENERATE SIGNED UPLOAD URL
================================= */

export const generateUploadUrl = async (req, res, next) => {
  try {
    const { file_name, mime_type, file_size } = req.body;

    if (!file_name || !mime_type || !file_size) {
      return res.status(400).json({ message: "Invalid input" });
    }

    if (!ALLOWED_TYPES.includes(mime_type)) {
      return res.status(400).json({ message: "File type not allowed" });
    }

    if (file_size > MAX_FILE_SIZE) {
      return res.status(400).json({ message: "File too large" });
    }

    /* -------------------------------
       PER-USER RATE LIMIT
    --------------------------------*/
    const recentUploads = await db.document.count({
      where: {
        user_id: req.user,
        created_at: {
          gte: new Date(Date.now() - UPLOAD_WINDOW_MS)
        }
      }
    });

    if (recentUploads >= MAX_UPLOADS_PER_WINDOW) {
      return res.status(429).json({
        message: "Upload limit exceeded"
      });
    }

    /* -------------------------------
       STORAGE QUOTA CHECK
    --------------------------------*/
    const user = await db.user.findUnique({
      where: { id: req.user },
      select: {
        storage_used: true,
        storage_limit: true
      }
    });

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (
      BigInt(user.storage_used) + BigInt(file_size) >
      BigInt(user.storage_limit)
    ) {
      return res.status(403).json({
        message: "Storage quota exceeded"
      });
    }

    /* -------------------------------
       GENERATE STORAGE KEY
    --------------------------------*/
    const uniqueId = crypto.randomUUID();
    const storageKey = `users/${req.user}/${uniqueId}`;

    const command = new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: storageKey,
      ContentType: mime_type,
      ContentLength: file_size
    });

    const uploadUrl = await getSignedUrl(s3, command, {
      expiresIn: 300
    });

    return res.status(200).json({
      uploadUrl,
      storageKey
    });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   CONFIRM UPLOAD
================================= */

export const confirmUpload = async (req, res, next) => {
  try {
    const { storageKey, file_name, mime_type, file_size } = req.body;

    if (!storageKey || !file_name || !mime_type || !file_size) {
      return res.status(400).json({ message: "Invalid input" });
    }

    // Prevent storageKey tampering
    if (!storageKey.startsWith(`users/${req.user}/`)) {
      return res.status(403).json({ message: "Invalid storage key" });
    }

    /* -------------------------------
       VERIFY OBJECT EXISTS IN S3
    --------------------------------*/
    try {
      await s3.send(
        new HeadObjectCommand({
          Bucket: process.env.S3_BUCKET,
          Key: storageKey
        })
      );
    } catch {
      return res.status(400).json({
        message: "Uploaded file not found in storage"
      });
    }

    /* -------------------------------
       ATOMIC TRANSACTION
    --------------------------------*/
    const document = await db.$transaction(async (tx) => {

      const created = await tx.document.create({
        data: {
          user_id: req.user,
          file_name,
          mime_type,
          file_size,
          storage_key: storageKey
        }
      });

      await tx.user.update({
        where: { id: req.user },
        data: {
          storage_used: {
            increment: file_size
          }
        }
      });

      return created;
    });
    await logAudit({
      userId: req.user,
      action: "DOCUMENT_UPLOAD",
      documentId: document.id,
      req
    });

    return res.status(201).json({
      id: document.id,
      file_name: document.file_name,
      mime_type: document.mime_type,
      file_size: document.file_size,
      created_at: document.created_at
    });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   LIST DOCUMENTS
================================= */

export const listDocuments = async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 10, 50);

    if (page < 1) {
      return res.status(400).json({ message: "Invalid page number" });
    }

    const skip = (page - 1) * limit;

    const [documents, total] = await db.$transaction([
      db.document.findMany({
        where: { user_id: req.user },
        orderBy: { created_at: "desc" },
        skip,
        take: limit,
        select: {
          id: true,
          file_name: true,
          mime_type: true,
          file_size: true,
          created_at: true
        }
      }),
      db.document.count({
        where: { user_id: req.user }
      })
    ]);

    return res.status(200).json({
      page,
      total,
      totalPages: Math.ceil(total / limit),
      documents
    });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   GENERATE SIGNED DOWNLOAD URL
================================= */

export const generateDownloadUrl = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ message: "Document ID required" });
    }

    const document = await db.document.findFirst({
      where: {
        id,
        user_id: req.user
      },
      select: {
        storage_key: true,
        mime_type: true,
        file_name: true
      }
    });

    if (!document) {
      return res.status(404).json({ message: "Document not found" });
    }

    const command = new GetObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: document.storage_key,
      ResponseContentType: document.mime_type,
      ResponseContentDisposition: `attachment; filename="${document.file_name}"`
    });

    const downloadUrl = await getSignedUrl(s3, command, {
      expiresIn: 120
    });
    await logAudit({
      userId: req.user,
      action: "DOCUMENT_DOWNLOAD",
      documentId: id,
      req
    });

    return res.status(200).json({ downloadUrl });

  } catch (error) {
    next(error);
  }
};

/* ===============================
   DELETE DOCUMENT
================================= */

export const deleteDocument = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ message: "Document ID required" });
    }

    const document = await db.document.findFirst({
      where: {
        id,
        user_id: req.user
      },
      select: {
        id: true,
        storage_key: true,
        file_size: true
      }
    });

    if (!document) {
      return res.status(404).json({ message: "Document not found" });
    }

    // Delete from S3 first
    try {
      await s3.send(
        new DeleteObjectCommand({
          Bucket: process.env.S3_BUCKET,
          Key: document.storage_key
        })
      );
    } catch {
      return res.status(500).json({
        message: "Failed to delete file from storage"
      });
    }

    // Atomic DB cleanup
    await db.$transaction(async (tx) => {
      await tx.document.delete({
        where: { id: document.id }
      });

      await tx.user.update({
        where: { id: req.user },
        data: {
          storage_used: {
            decrement: document.file_size
          }
        }
      });
    });
    await logAudit({
      userId: req.user,
      action: "DOCUMENT_DELETE",
      documentId: document.id,
      req
    });

    return res.status(200).json({
      message: "Document deleted successfully"
    });

  } catch (error) {
    next(error);
  }
};
