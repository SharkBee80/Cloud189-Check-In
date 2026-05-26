import time

max = 3


def main():
    for i in range(max+1):
        try:
            print(i + 1)
            if i <= 5:
                raise Exception("打断！")
            if i + 1 == 5:
                return {"ok": True}
        except Exception as e:
            if i == max:
                print(f"Telegram API 请求失败,超过最大值,{e}")
                return {"ok": False, "error": str(e)}
            print(f"{e}\nTelegram API 请求失败，正在第 {i + 1} 次重试...")
            time.sleep(0.3)
    print("结束")
    return {"ok": False}


if __name__ == "__main__":
    # c = "" or 444
    a = main()
    a["platform"] = "a"
    print(a)
