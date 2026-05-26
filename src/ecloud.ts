import axios from "axios";
import { CookieJar } from "tough-cookie";
import { wrapper } from "axios-cookiejar-support";
import * as cheerio from "cheerio";
import { UA } from "./config.ts";

const Referer = "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp"; // https://m.cloud.189.cn/zt/2024/grow-guide/index.html#/
const CaptchaGet = "https://open.e.189.cn/gw/captcha/get.do";
const CaptchaCheck = "https://open.e.189.cn/gw/captcha/check.do";
const Login = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do";
const B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz".split("");

export class Ecloud {
  private readonly username: string;
  private readonly password: string;
  private client;
  constructor(username: string, password: string) {
    this.username = username;
    this.password = password;
    const jar = new CookieJar();
    this.client = wrapper(axios.create({ jar, withCredentials: true, headers: { "User-Agent": UA, "Accept-Encoding": "gzip, deflate" } }));
  }

  async login() {
    const r1 = await this.client.get(`https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=${Referer}`);
    console.log(r1.data);
    const redirect = (r1.data as string).match(/https?:\/\/[^\s'\"]+/gm);
    if (!redirect) throw new Error("Get Login URL Failed");
    const redirect_to = redirect[0];
    const redirect_to_B = new URL(redirect_to);
    if (redirect_to_B.pathname === "/api/logbox/oauth2/wap/autoLogin.do") redirect_to_B.pathname = "/api/logbox/separate/wap/login.html";
    redirect_to_B.searchParams.set("protocol", "https");
    redirect_to_B.searchParams.set("netType", "");
    console.log(redirect_to, redirect_to_B);
    const r2 = await this.client.get(redirect_to);
    console.log(r2.data);
  }
}
