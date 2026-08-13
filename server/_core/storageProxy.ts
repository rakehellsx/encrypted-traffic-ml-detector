import type { Express } from "express";
import { storageGetSignedUrl } from "../storage";

/** Redirects file requests to short-lived object-store URLs without exposing credentials. */
export function registerStorageProxy(app: Express) {
  app.get(["/manus-storage/*", "/api/storage/*"], async (req, res) => {
    const key = (req.params as Record<string, string>)[0];
    if (!key) {
      res.status(400).send("Missing storage key");
      return;
    }
    try {
      const url = await storageGetSignedUrl(decodeURIComponent(key));
      res.set("Cache-Control", "no-store");
      res.redirect(307, url);
    } catch (error) {
      console.error("[StorageProxy] failed:", error);
      res.status(502).send("Storage backend error");
    }
  });
}
