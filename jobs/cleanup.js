import cron from "node-cron";
import db from "../config/db.js";

export const startCleanupJob = () => {
  cron.schedule("0 * * * *", async () => {
    await db.session.deleteMany({
      where: {
        expires_at: { lt: new Date() }
      }
    });
  });
};
