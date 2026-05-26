import { ACCOUNTS, TG } from "./config.ts";
// import {} from "./scraper.ts";
import { TG_Bot } from "./tg.ts";
if (!ACCOUNTS) throw new Error("No accounts provided");

if (TG) {
  const a = TG.replace("；", ";").split(";").filter(Boolean);
  if (a.length != 2 || !a[0] || !a[1]) throw new Error("Invalid TG config");
  const tg = new TG_Bot(a[0], a[1]);
  tg.text("test");
}
