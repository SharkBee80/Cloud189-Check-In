import { CloudClient, type UserSignResponse } from "cloud189-sdk";
export class Ecloud {
  private readonly username: string;
  private readonly password: string;
  private client: CloudClient;

  constructor(username: string, password: string, UA?: string, module?: string) {
    this.username = username;
    this.password = password;
    this.client = new CloudClient({ username, password });
  }

  async userSign() {
    const sign: UserSignResponse = await this.client.userSign();
    return sign;
  }

  async info() {
    return await this.client.getUserSizeInfo();
  }
}
