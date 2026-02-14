-- DropIndex
DROP INDEX "Session_expires_at_idx";

-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "ip_address" TEXT,
ADD COLUMN     "user_agent" TEXT;
