import { ACCOUNTS, TG, Throw, MAX_TRY } from "./config.ts";
import { TG_Bot } from "./tg.ts";
import { Ecloud } from "./ecloud.ts";
// import type { UserSizeInfoResponse } from "cloud189-sdk";

async function sign(acc: string[], index: number): Promise<[string, boolean]> {
  let res = "",
    err = false;
  try {
    const [username, password] = acc;
    if (!username || !password) throw new Error("Missing Account Or Password");
    if (!new RegExp(/^(?:(?:\+|00)86)?1\d{10}$/).test(username)) throw new Error("Invalid Account");
    const ecloud = new Ecloud(username, password);
    const r1 = await ecloud.userSign(MAX_TRY);
    const r2 = await ecloud.info();
    const data = {
      index: index + 1,
      isSign: r1.isSign,
      bonus: r1.netdiskBonus,
      id: ((r2 as any).account as string).split("@")[0]?.replace(/\*/g, "\\*"),
      total: r2.cloudCapacityInfo.totalSize,
    };
    res =
      `🙍🏻‍♂️ 第${data.index}个账号 ${data.id}\n` + `${data.isSign ? "✅" : "☑️"} 已签到，获得 ${data.bonus}M 空间\n` + `🍺 总共 ${generateTotal(data.total)} 容量`;
  } catch (e) {
    res = `❌ 第${index + 1}个账号 出错\n` + `⁉️ ${e}`;
    err = true;
  } finally {
    console.log(res);
    return [res, err];
  }
}

function generateTotal(size: number) {
  if (size > 1024 * 1024 * 1024 * 1024) {
    return (size / (1024 * 1024 * 1024 * 1024)).toFixed(2) + "TB";
  } else if (size > 1024 * 1024 * 1024) {
    return (size / (1024 * 1024 * 1024)).toFixed(2) + "GB";
  } else if (size > 1024 * 1024) {
    return ((size / 1024) * 1024).toFixed(2) + "MB";
  } else {
    return size + "KB";
  }
}

async function main(ACCOUNTS: string): Promise<{ len: number; msg: string[]; err: Boolean }> {
  let len = 0,
    msg: string[] = [],
    err = false;
  const accs = ACCOUNTS.replace("；", ";")
    .replace("&&", "\n")
    .split("\n")
    .map((i) => i.split(";"));
  // console.log(accs);
  len = accs.length;
  if (len == 0)
    return {
      len,
      msg,
      err,
    };
  for (let i = 0; i < len; i++) {
    const r = await sign(accs[i]!, i);
    msg.push(r[0]);
    if (r[1]) err = true;
  }
  return {
    len,
    msg,
    err,
  };
}

function generateMsg(msg: string[], len: number): string {
  const now = new Date().toLocaleString("zh-CN", { hour12: false, timeZone: "Asia/Shanghai" });
  const t = (() => `
#ecloud *天翼云盘自动签到*\n
${msg.join("\n")}\n
📅 *时间*：${now}
`)();
  return t;
}

async function push(msg: string[], len: number): Promise<{ [x: string]: any }> {
  // if (TG || WX)
  if (TG) {
    const text = generateMsg(msg, len);
    console.log(text);
    const err: { [x: string]: Boolean | any } = {};
    if (TG) {
      try {
        const a = TG.replace("；", ";").split(";").filter(Boolean);
        if (a.length != 2 || !a[0] || !a[1]) throw new Error("Invalid TG config");
        const tg = new TG_Bot(a[0], a[1]);
        await tg.md(text).then((v) => {
          if (v.error) err["tg"] = v.error;
        });
      } catch (e) {
        err["tg"] = e;
      }
    }
    return err;
  }
  return {};
}

async function run() {
  const err: { [x: string]: Boolean | any } = {};
  if (!ACCOUNTS) throw new Error("No accounts provided");
  const r = await main(ACCOUNTS).then((v) => {
    if (v.err) err["main"] = true;
    return v;
  });
  await push(r.msg, r.len).then((v) => Object.assign(err, v));
  //
  if (Object.keys(err).length) {
    console.log(Object.entries(err).join("\n"));
    if (Throw) throw new Error("Some Error Occured");
  }
}

(async () => {
  await run();
})();
