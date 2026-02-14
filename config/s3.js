import { S3Client } from "@aws-sdk/client-s3";

const endpoint = process.env.S3_ENDPOINT?.replace(/\/+$/, "");
const accessKeyId = process.env.S3_ACCESS_KEY;
const secretAccessKey = process.env.S3_SECRET_KEY;

if (!endpoint || !accessKeyId || !secretAccessKey) {
  throw new Error("S3 configuration is incomplete. Check S3_ENDPOINT, S3_ACCESS_KEY, and S3_SECRET_KEY.");
}

if (accessKeyId.includes(".") || secretAccessKey.includes(".")) {
  throw new Error(
    "S3 credentials look like JWTs. Use Supabase Storage S3 Access Key ID and Secret, not anon/service_role API keys."
  );
}

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint,
  credentials: {
    accessKeyId,
    secretAccessKey,
  },
  forcePathStyle: true,
  requestChecksumCalculation: "WHEN_REQUIRED",
  responseChecksumValidation: "WHEN_REQUIRED"
});

export default s3;
