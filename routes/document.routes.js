import express from "express";
import { protect } from "../middleware/auth.middleware.js";
import {
  generateUploadUrl,
  confirmUpload,
  listDocuments,
  generateDownloadUrl,
  generatePreviewUrl,
  deleteDocument
} from "../controller/document.controller.js";
import {uploadLimiter} from "../middleware/ratelimit.middleware.js";


const router = express.Router();

router.get("/", protect, listDocuments);
router.post("/upload-url", protect,uploadLimiter, generateUploadUrl);
router.post("/confirm", protect, confirmUpload);
router.get("/:id/download", protect, generateDownloadUrl);
router.get("/:id/preview", protect, generatePreviewUrl);
router.delete("/:id", protect, deleteDocument);



export default router;
