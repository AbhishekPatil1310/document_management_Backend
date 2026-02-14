import "dotenv/config";
import pkg from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
const { PrismaClient } = pkg;

/*
  Prevent multiple Prisma instances during development
  (important for nodemon / hot reload)
*/

const globalForPrisma = globalThis;
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("DATABASE_URL is not set");
}

const adapter = new PrismaPg({ connectionString });

const db =
  globalForPrisma.prisma ||
  new PrismaClient({
    adapter,
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "warn", "error"]
        : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = db;
}

/*
  Optional: Graceful shutdown handling
  Prevents hanging connections in production
*/

process.on("SIGTERM", async () => {
  await db.$disconnect();
  process.exit(0);
});

process.on("SIGINT", async () => {
  await db.$disconnect();
  process.exit(0);
});

export default db;
