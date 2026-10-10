#!/usr/bin/env python3
"""
Сторож контура ТСПУ — запускается из GitHub Actions по расписанию.
Проверяет: срок сертификата, DNS-туннель (через сам туннель),
сквозной канал (мост→выход). Алертит в Telegram.

Секреты (Settings → Secrets → Actions):
  TG_TOKEN, TG_CHAT, CLIENT_JSON
  DOMAIN, EXPECT_EXIT, TUNNEL_DOMAIN
Опционально:
  SOCKS         — по умолчанию 127.0.0.1:10808
  XRAY_BIN      — по умолчанию xray
  CERT_MIN_DAYS — по умолчанию 7
"""

import os
import sys
import json
import time
import socket
import ssl
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone

TG_TOKEN      = os.getenv("TG_TOKEN", "")
TG_CHAT       = os.getenv("TG_CHAT", "")
EXPECT_EXIT   = os.getenv("EXPECT_EXIT", "")
DOMAIN        = os.getenv("DOMAIN", "")
TUNNEL_DOMAIN = os.getenv("TUNNEL_DOMAIN", "")
SOCKS         = os.getenv("SOCKS", "127.0.0.1:10808")
XRAY_BIN      = os.getenv("XRAY_BIN", "xray")
CERT_MIN_DAYS = int(os.getenv("CERT_MIN_DAYS", "7"))

problems = []


def note(ok: bool, text: str) -> None:
    print(("OK   " if ok else "ПРОБЛЕМА ") + text)
    if not ok:
        problems.append(text)


def tg(msg: str) -> None:
    if not (TG_TOKEN and TG_CHAT):
        print("tg: пропущено — нет TG_TOKEN/TG_CHAT")
        return
    data = json.dumps({
        "chat_id": TG_CHAT,
        "text": msg,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception as ex:
        print("tg error:", ex)


def cert_days(host: str) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname=host) as ss:
            exp = ss.getpeercert()["notAfter"]
            d = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            return (d - datetime.now(timezone.utc)).days


def check_cert() -> None:
    if not DOMAIN:
        note(False, "не задан DOMAIN")
        return
    try:
        d = cert_days(DOMAIN)
        note(d > CERT_MIN_DAYS, f"сертификат {DOMAIN}: осталось {d} дн.")
    except Exception as ex:
        note(False, f"сертификат {DOMAIN} не читается: {ex}")


def wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def curl_socks(url: str, timeout: int = 30, want_body: bool = False) -> tuple[str, str, str]:
    """
    GET через SOCKS5 с удалённым DNS.
    Возвращает (http_code, body_or_empty, stderr_snippet).
    """
    args = [
        "curl", "-sS",                 # silent, но показывать ошибки
        "-o", "/dev/stdout" if want_body else "/dev/null",
        "-w", "\n%{http_code}",
        "--max-time", str(timeout),
        "--socks5-hostname", SOCKS,
        url,
    ]
    res = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 15)
    out = res.stdout or ""
    code = ""
    body = ""
    if "\n" in out:
        body, _, code = out.rpartition("\n")
        code = code.strip()
    else:
        code = out.strip()
    return code, body.strip(), (res.stderr or "").strip()[:300]


def check_contour() -> None:
    cfg = os.getenv("CLIENT_JSON", "")
    if not cfg:
        note(False, "не задан CLIENT_JSON (клиентский конфиг в секретах)")
        return

    try:
        json.loads(cfg)
    except json.JSONDecodeError as ex:
        note(False, f"CLIENT_JSON не парсится как JSON: {ex}")
        return

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False, encoding="utf-8")
    proc = None
    try:
        tmp.write(cfg)
        tmp.close()

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", tmp.name],
            stdout=log, stderr=subprocess.STDOUT,
        )

        host, port = SOCKS.split(":")
        if not wait_for_port(host, int(port), timeout=15):
            log.flush(); log.seek(0)
            tail = log.read()[-500:].strip()
            note(False, f"xray не поднял SOCKS {SOCKS} за 15с. Лог: {tail[:400]}")
            return

        # 1) DNS-туннель: резолвится ли TUNNEL_DOMAIN ЧЕРЕЗ туннель.
        #    --socks5-hostname резолвит домен на стороне xray.
        if TUNNEL_DOMAIN:
            code, _, err = curl_socks(f"https://{TUNNEL_DOMAIN}/", timeout=20)
            ok = bool(code) and code != "000"
            msg = f"DNS-туннель {TUNNEL_DOMAIN} через туннель: HTTP {code or 'нет ответа'}"
            if err and not ok:
                msg += f" | {err}"
            note(ok, msg)

        # 2) Сквозной канал: реальный исходящий IP через туннель.
        code, body, err = curl_socks("https://api.ipify.org", timeout=30, want_body=True)
        out = body
        ok = (out == EXPECT_EXIT)
        msg = f"сквозной канал: выход={out or 'ПУСТО'} (ожидали {EXPECT_EXIT})"
        if err and not ok:
            msg += f" | {err}"
        note(ok, msg)
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()
        for path in (tmp.name, log.name):
            try:
                os.unlink(path)
            except OSError:
                pass


def main() -> None:
    print("=== сторож контура ТСПУ ===")
    check_cert()
    check_contour()

    if problems:
        tg("⚠️ <b>Сторож ТСПУ: проблема</b>\n" + "\n".join("• " + p for p in problems))
        print("АЛЕРТ отправлен")
        sys.exit(1)
    print("всё в норме")


if __name__ == "__main__":
    main()
