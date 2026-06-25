import "dotenv/config";

export const TG = process.env.TG;
export const ACCOUNTS = process.env.ACCOUNTS;
export const Throw = (() => {
  switch (process.env.Throw) {
    case "true":
      return true;
    case "false":
      return false;
    default:
      return true;
  }
})();
export const MAX_TRY = Number(process.env.MAX_TRY) || 5;
// reserved
