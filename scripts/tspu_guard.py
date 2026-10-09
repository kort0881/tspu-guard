#!/usr/bin/env python3
"""
Сторож контура ТСПУ — запускается из GitHub Actions по расписанию (0 ₽, работает всегда).
Проверяет: сквозной канал (мост→выход), срок сертификата, DNS-туннель. Алертит в Telegram.
Секреты (Settings → Secrets → Actions): TG_TOKEN, TG_CHAT, CLIENT_JSON (клиентский конфиг xray).
"""
import os, json, subprocess, time, socket, ssl, sys, urllib.request, tempfile

TG_TOKEN = os.getenv("TG_TOKEN", "")
TG_CHAT  = os.getenv("TG_CHAT", "")
EXPECT_EXIT = os.getenv("EXPECT_EXIT", "")
DOMAIN = os.getenv("DOMAIN", "")
TUNNEL_DOMAIN = os.getenv("TUNNEL_DOMAIN", "")
SOCKS = "127.0.0.1:10808"

problems = []

def note(ok, text):
    print(("OK   " if ok else "ПРОБЛЕМА ") + text)
    if not ok:
        problems.append(text)

def tg(msg):
    if not (TG_TOKEN and TG_CHAT):
        return
    data = json.dumps({"chat_id": TG_CHAT, "text": msg, "parse_mode": "HTML"}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                                 data=data, headers={"Content-Type": "application/json"})
    try: urllib.request.urlopen(req, timeout=15)
    except Exception as ex: print("tg error", ex)

def cert_days(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            import datetime
            exp = ss.getpeercert()["notAfter"]
            d = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
            return (d - datetime.datetime.utcnow()).days

def check_tunnel():
    try:
        out = subprocess.run(["dig","+short","NS",TUNNEL_DOMAIN,"@8.8.8.8"],
                             capture_output=True, text=True, timeout=25).stdout.strip()
        note(bool(out), f"DNS-туннель {TUNNEL_DOMAIN}: NS → {out or 'НЕ отвечает'}")
    except Exception as ex:
        note(False, f"DNS-туннель проверка упала: {ex}")

def check_contour():
    cfg = os.getenv("CLIENT_JSON", "")
    if not cfg:
        note(False, "не задан CLIENT_JSON (клиентский конфиг в секретах)")
        return
    p = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    p.write(cfg); p.close()
    proc = subprocess.Popen(["xray","run","-c",p.name],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(5)
        out = subprocess.run(["curl","-s","--max-time","30","--socks5-hostname",SOCKS,
                              "https://api.ipify.org"], capture_output=True, text=True, timeout=45).stdout.strip()
        note(out == EXPECT_EXIT, f"сквозной канал: выход={out or 'ПУСТО'} (ожидали {EXPECT_EXIT})")
    finally:
        proc.terminate()

def main():
    print("=== сторож контура ТСПУ ===")
    try:
        d = cert_days(DOMAIN); note(d > 7, f"сертификат {DOMAIN}: осталось {d} дн.")
    except Exception as ex:
        note(False, f"сертификат не читается: {ex}")
    check_tunnel()
    check_contour()
    if problems:
        tg("⚠️ <b>Сторож ТСПУ: проблема</b>\n" + "\n".join("• " + p for p in problems))
        print("АЛЕРТ отправлен"); sys.exit(1)
    print("всё в норме"); 

if __name__ == "__main__":
    main()
