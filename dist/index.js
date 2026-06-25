// src/config.ts
import "dotenv/config";
var l = process.env.TG, h = process.env.ACCOUNTS, d = (() => {
  switch (process.env.Throw) {
    case "true":
      return !0;
    case "false":
      return !1;
    default:
      return !0;
  }
})(), y = Number(process.env.MAX_TRY) || 5;

// src/tg.ts
import b from "axios";
var u = class {
  token;
  chat_id;
  max_try = 3;
  timeout = 5e3;
  base_url;
  constructor(r, t, e = 3, s = 5e3) {
    this.token = r, this.chat_id = t, this.max_try = e, this.timeout = s, this.base_url = `https://api.telegram.org/bot${this.token}/`;
  }
  async post(r, t) {
    let e = this.base_url + r, s = b.create({
      baseURL: e,
      timeout: this.timeout
    });
    for (let o = 0; o < this.max_try; o++)
      try {
        return { ok: !0, result: (await s.post("", t)).data };
      } catch (i) {
        if (o === this.max_try)
          return console.log(`Telegram API 请求失败,${i}`), { ok: !1, error: i };
        console.log(`${i}
Telegram API 请求失败，正在第 ${o + 1} 次重试...`), await new Promise((c) => setTimeout(c, 1e3));
      }
    return { ok: !1, error: "Telegram API 请求失败" };
  }
  async text(r, t) {
    let e = {
      chat_id: this.chat_id,
      text: r
    };
    return t && (e.parse_mode = t), this.post("sendMessage", e);
  }
  async md(r) {
    return this.text(r, "Markdown");
  }
};

// src/ecloud.ts
import { CloudClient as x } from "cloud189-sdk";
var g = class {
  username;
  password;
  client;
  constructor(r, t) {
    this.username = r, this.password = t, this.client = new x({ username: r, password: t });
  }
  async userSign(r = 5) {
    let t = null;
    for (let e = 1; e < r + 1; e++)
      try {
        if (t = await this.client.userSign(), t.isSign) break;
      } catch (s) {
        if (console.log(`第${e}次尝试签到失败，${s.message}`), e === r) throw s;
        await new Promise((o) => setTimeout(o, 400 * e));
      }
    if (!t) throw new Error("签到失败");
    return t;
  }
  async info() {
    return await this.client.getUserSizeInfo();
  }
};

// src/index.ts
async function T(n, r) {
  var s;
  let t = "", e = !1;
  try {
    let [o, i] = n;
    if (!o || !i) throw new Error("Missing Account Or Password");
    if (!new RegExp(/^(?:(?:\+|00)86)?1\d{10}$/).test(o)) throw new Error("Invalid Account");
    let c = new g(o, i), f = await c.userSign(y), w = await c.info(), a = {
      index: r + 1,
      isSign: f.isSign,
      bonus: f.netdiskBonus,
      id: (s = w.account.split("@")[0]) == null ? void 0 : s.replace(/\*/g, "\\*"),
      total: w.cloudCapacityInfo.totalSize
    };
    t = `🙍🏻‍♂️ 第${a.index}个账号 ${a.id}
${a.isSign ? "✅" : "☑️"} 已签到，获得 ${a.bonus}M 空间
🍺 总共 ${S(a.total)} 容量`;
  } catch (o) {
    t = `❌ 第${r + 1}个账号 出错
⁉️ ${o}`, e = !0;
  } finally {
    return console.log(t), [t, e];
  }
}
function S(n) {
  return n > 1024 * 1024 * 1024 * 1024 ? (n / (1024 * 1024 * 1024 * 1024)).toFixed(2) + "TB" : n > 1024 * 1024 * 1024 ? (n / (1024 * 1024 * 1024)).toFixed(2) + "GB" : n > 1024 * 1024 ? (n / 1024 * 1024).toFixed(2) + "MB" : n + "KB";
}
async function $(n) {
  let r = 0, t = [], e = !1, s = n.replace("；", ";").replace("&&", `
`).split(`
`).map((o) => o.split(";"));
  if (r = s.length, r == 0)
    return {
      len: r,
      msg: t,
      err: e
    };
  for (let o = 0; o < r; o++) {
    let i = await T(s[o], o);
    t.push(i[0]), i[1] && (e = !0);
  }
  return {
    len: r,
    msg: t,
    err: e
  };
}
function _(n, r) {
  let t = (/* @__PURE__ */ new Date()).toLocaleString("zh-CN", { hour12: !1, timeZone: "Asia/Shanghai" });
  return `
#ecloud *天翼云盘自动签到*

${n.join(`
`)}

📅 *时间*：${t}
`;
}
async function v(n, r) {
  if (l) {
    let t = _(n, r);
    console.log(t);
    let e = {};
    if (l)
      try {
        let s = l.replace("；", ";").split(";").filter(Boolean);
        if (s.length != 2 || !s[0] || !s[1]) throw new Error("Invalid TG config");
        await new u(s[0], s[1]).md(t).then((i) => {
          i.error && (e.tg = i.error);
        });
      } catch (s) {
        e.tg = s;
      }
    return e;
  }
  return {};
}
async function A() {
  let n = {};
  if (!h) throw new Error("No accounts provided");
  let r = await $(h).then((t) => (t.err && (n.main = !0), t));
  if (await v(r.msg, r.len).then((t) => Object.assign(n, t)), Object.keys(n).length && (console.log(Object.entries(n).join(`
`)), d))
    throw new Error("Some Error Occured");
}
(async () => await A())();
