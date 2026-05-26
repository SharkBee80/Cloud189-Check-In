import time

import requests


class TG:
    def __init__(self, token, chat_id, retry=2, timeout=5):
        # 检测是否为空
        if not token or not chat_id:
            raise ValueError("Token and chat_id cannot be empty")

        self.token = token
        self.chat_id = chat_id
        self.retry = retry
        self.timeout = timeout
        self.base = f"https://api.telegram.org/bot{token}"

    # 基础请求函数（带自动重试）
    def _post(self, method, data=None, files=None):
        url = f"{self.base}/{method}"
        for i in range(self.retry + 1):
            try:
                resp = requests.post(url, data=data, files=files, timeout=self.timeout)
                # return resp.json()
                return {"ok": True, "result": resp.json()}
            except Exception as e:
                if i == self.retry:
                    print(f"Telegram API 请求失败,{e}")
                    return {"ok": False, "error": str(e)}
                print(f"{e}\nTelegram API 请求失败，正在第 {i + 1} 次重试...")
                time.sleep(1)
        return {"ok": False}

    # 发文字
    def send_text(self, text, parse_mode=None):
        data = {
            "chat_id": self.chat_id,
            "text": text
        }
        if parse_mode:
            data["parse_mode"] = parse_mode
        return self._post("sendMessage", data=data)

    def send_markdown(self, text):
        return self.send_text(text, "Markdown")
