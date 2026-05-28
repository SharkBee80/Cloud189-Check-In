import axios from "axios";

export class TG_Bot {
  private readonly token: string;
  private readonly chat_id: string;
  private readonly max_try: number = 3;
  private readonly timeout: number = 5000;
  private base_url: string;
  constructor(token: string, chat_id: string, max_try: number = 3, timeout: number = 5000) {
    this.token = token;
    this.chat_id = chat_id;
    this.max_try = max_try;
    this.timeout = timeout;
    this.base_url = `https://api.telegram.org/bot${this.token}/`;
  }

  private async post(method: string, data?: any): Promise<{ ok: Boolean; result?: any; error?: any }> {
    const url = this.base_url + method;
    const http = axios.create({
      baseURL: url,
      timeout: this.timeout,
    });
    for (let i = 0; i < this.max_try; i++) {
      try {
        const response = await http.post("", data);
        console.log(response.data);
        return { ok: true, result: response.data };
      } catch (error) {
        if (i === this.max_try) {
          console.log(`Telegram API 请求失败,${error}`);
          return { ok: false, error: error };
        }
        console.log(`${error}\nTelegram API 请求失败，正在第 ${i + 1} 次重试...`);
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    return { ok: false, error: "Telegram API 请求失败" };
  }

  async text(text: string, mode?: string) {
    const data = {
      chat_id: this.chat_id,
      text,
    } as any;
    if (mode) data["parse_mode"] = mode;
    return this.post("sendMessage", data);
  }

  async md(text: string) {
    return this.text(text, "Markdown");
  }
}
