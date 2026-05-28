// src/config.ts
import "dotenv/config";
var l = process.env.TG, h = process.env.ACCOUNTS, w = (() => {
  switch (process.env.Throw) {
    case "true":
      return !0;
    case "false":
      return !1;
    default:
      return !0;
  }
})();

// src/tg.ts
import y from "axios";
var u = class {
  token;
  chat_id;
  max_try = 3;
  timeout = 5e3;
  base_url;
  constructor(r, t, n = 3, s = 5e3) {
    this.token = r, this.chat_id = t, this.max_try = n, this.timeout = s, this.base_url = `https://api.telegram.org/bot${this.token}/`;
  }
  async post(r, t) {
    let n = this.base_url + r, s = y.create({
      baseURL: n,
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
    let n = {
      chat_id: this.chat_id,
      text: r
    };
    return t && (n.parse_mode = t), this.post("sendMessage", n);
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
  constructor(r, t, n, s) {
    this.username = r, this.password = t, this.client = new x({ username: r, password: t });
  }
  async userSign() {
    return await this.client.userSign();
  }
  async info() {
    return await this.client.getUserSizeInfo();
  }
};

// src/index.ts
async function b(e, r) {
  var s;
  let t = "", n = !1;
  try {
    let [o, i] = e;
    if (!o || !i) throw new Error("Missing Account Or Password");
    if (!new RegExp(/^(?:(?:\+|00)86)?1\d{10}$/).test(o)) throw new Error("Invalid Account");
    let c = new g(o, i), f = await c.userSign(), d = await c.info(), a = {
      index: r + 1,
      isSign: f.isSign,
      bonus: f.netdiskBonus,
      id: (s = d.account.split("@")[0]) == null ? void 0 : s.replace(/\*/g, "\\*"),
      total: d.cloudCapacityInfo.totalSize
    };
    t = `🙍🏻‍♂️ 第${a.index}个账号 ${a.id}
${a.isSign ? "✅" : "☑️"} 已签到，获得 ${a.bonus}M 空间
🍺 总共 ${S(a.total)} 容量`;
  } catch (o) {
    t = `❌ 第${r + 1}个账号 出错
⁉️ ${o}`, n = !0;
  } finally {
    return console.log(t), [t, n];
  }
}
function S(e) {
  return e > 1024 * 1024 * 1024 * 1024 ? (e / (1024 * 1024 * 1024 * 1024)).toFixed(2) + "TB" : e > 1024 * 1024 * 1024 ? (e / (1024 * 1024 * 1024)).toFixed(2) + "GB" : e > 1024 * 1024 ? (e / 1024 * 1024).toFixed(2) + "MB" : e + "KB";
}
async function T(e) {
  let r = 0, t = [], n = !1, s = e.replace("；", ";").replace("&&", `
`).split(`
`).map((o) => o.split(";"));
  if (r = s.length, r == 0)
    return {
      len: r,
      msg: t,
      err: n
    };
  for (let o = 0; o < r; o++) {
    let i = await b(s[o], o);
    t.push(i[0]), i[1] && (n = !0);
  }
  return {
    len: r,
    msg: t,
    err: n
  };
}
function $(e, r) {
  let t = (/* @__PURE__ */ new Date()).toLocaleString("zh-CN", { hour12: !1, timeZone: "Asia/Shanghai" });
  return `
#ecloud *天翼云盘自动签到*

${e.join(`
`)}

📅 *时间*：${t}
`;
}
async function v(e, r) {
  if (l) {
    let t = $(e, r);
    console.log(t);
    let n = {};
    if (l)
      try {
        let s = l.replace("；", ";").split(";").filter(Boolean);
        if (s.length != 2 || !s[0] || !s[1]) throw new Error("Invalid TG config");
        await new u(s[0], s[1]).md(t).then((i) => {
          i.error && (n.tg = i.error);
        });
      } catch (s) {
        n.tg = s;
      }
    return n;
  }
  return {};
}
async function C() {
  let e = {};
  if (!h) throw new Error("No accounts provided");
  let r = await T(h).then((t) => (t.err && (e.main = !0), t));
  if (await v(r.msg, r.len).then((t) => Object.assign(e, t)), Object.keys(e).length && (console.log(Object.entries(e).join(`
`)), w))
    throw new Error("Some Error Occured");
}
C();
