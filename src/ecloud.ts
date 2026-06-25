import { CloudClient, type UserSignResponse } from "cloud189-sdk";
export class Ecloud {
  private readonly username: string;
  private readonly password: string;
  private client: CloudClient;

  constructor(username: string, password: string) {
    this.username = username;
    this.password = password;
    this.client = new CloudClient({ username, password });
  }

  async userSign(retry: number = 5): Promise<UserSignResponse> {
    let sign: UserSignResponse | null = null;
    for (let i = 1; i < retry + 1; i++) {
      try {
        sign = await this.client.userSign();
        if (sign.isSign) break;
      } catch (e: any) {
        console.log(`第${i}次尝试签到失败，${e.message}`);
        if (i === retry) throw e;
        await new Promise((resolve) => setTimeout(resolve, 400 * i));
      }
    }
    if (!sign) throw new Error("签到失败");
    return sign;
  }

  async info() {
    return await this.client.getUserSizeInfo();
  }
}
