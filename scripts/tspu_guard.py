#!/usr/bin/env python3
"""
Сторож контура ТСПУ — запускается из GitHub Actions по расписанию.
Проверяет: сквозной канал (мост→выход), срок сертификата, DNS-туннель.
Алертит в Telegram.

Секреты (Settings → Secrets → Actions):
  TG_TOKEN, TG_CHAT, CLIENT_JSON
  DOMAIN, EXPECT_EXIT, TUNNEL_DOMAIN
Опционально:
  TUNNEL_DNS_SERVER — IP:порт DNS на стороне туннеля (для точной проверки)
  SOCKS             — по умолчанию 127.0.0.1:10808
  XRAY_BIN          — по умолчанию xray
  CERT_MIN_DAYS     — по умолчанию 7
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

TG_TOKEN          = os.getenv("TG_TOKEN", "")
TG_CHAT           = os.getenv("TG_CHAT", "")
EXPECT_EXIT       = os.getenv("EXPECT_EXIT", "")
DOMAIN            = os.getenv("DOMAIN", "")
TUNNEL_DOMAIN     = os.getenv("TUNNEL_DOMAIN", "")
TUNNEL_DNS_SERVER = os.getenv("TUNNEL_DNS_SERVER", "")
SOCKS             = os.getenv("SOCKS", "127.0.0.1:10808")
XRAY_BIN          = os.getenv("XRAY_BIN", "xray")
CERT_MIN_DAYS     = int(os.getenv("CERT_MIN_DAYS", "7"))

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
            # notAfter всегда в GMT
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


def _dig(args: list[str], timeout: int = 20) -> str:
    try:
        res = subprocess.run(
            ["dig", "+short", *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return res.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError("утилита dig не найдена (нужен пакет dnsutils)")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"dig таймаут: {' '.join(args)}")


def check_tunnel() -> None:
    if not TUNNEL_DOMAIN:
        note(False, "не задан TUNNEL_DOMAIN")
        return

    # 1) NS-делегация — информационно. Если её нет, это НЕ проблема:
    # для поддомена с A-записью NS-записей быть и не должно.
    try:
        ns = _dig(["NS", TUNNEL_DOMAIN, "@8.8.8.8"])
    except Exception as ex:
        print(f"INFO dig NS упал: {ex}")
        ns = ""

    if ns:
        print(f"INFO NS-делегация: {ns.replace(chr(10), ', ')}")
        for ns_host in ns.splitlines():
            ns_host = ns_host.strip().rstrip(".")
            if not ns_host:
                continue
            try:
                a = _dig(["A", TUNNEL_DOMAIN, f"@{ns_host}"], timeout=15)
                note(bool(a), f"NS {ns_host} → A {a or 'НЕ отвечает'}")
            except Exception as ex:
                note(False, f"NS {ns_host} → ошибка: {ex}")
    else:
        print("INFO NS-делегации нет (норма для поддомена)")

    # 2) Основная проверка: резолвится ли домен в A-запись через нужный DNS.
    # Если задан TUNNEL_DNS_SERVER — спрашиваем его (это и есть проверка
    # работоспособности DNS-туннеля). Иначе — через публичный 8.8.8.8.
    resolver = TUNNEL_DNS_SERVER or "8.8.8.8"
    try:
        a = _dig(["A", TUNNEL_DOMAIN, f"@{resolver}"], timeout=15)
    except Exception as ex:
        note(False, f"DNS-туннель {TUNNEL_DOMAIN}: dig A @{resolver} упал: {ex}")
        return

    note(bool(a), f"DNS-туннель {TUNNEL_DOMAIN} via {resolver} → A {a or 'НЕ отвечает'}")


def wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


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
            stdout=log,
            stderr=subprocess.STDOUT,
        )

        host, port = SOCKS.split(":")
        if not wait_for_port(host, int(port), timeout=15):
            log.flush()
            log.seek(0)
            tail = log.read()[-500:].strip()
            note(False, f"xray не поднял SOCKS {SOCKS} за 15с. Лог: {tail[:400]}")
            return

        res = subprocess.run(
            ["curl", "-s", "--max-time", "30", "--socks5-hostname", SOCKS,
             "https://api.ipify.org"],
            capture_output=True, text=True, timeout=45,
        )
        out = res.stdout.strip()
        note(out == EXPECT_EXIT,
             f"сквозной канал: выход={out or 'ПУСТО'} (ожидали {EXPECT_EXIT})")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        log.close()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        try:
            os.unlink(log.name)
        except OSError:
            pass


def main() -> None:
    print("=== сторож контура ТСПУ ===")
    check_cert()
    check_tunnel()
    check_contour()

    if problems:
        tg("⚠️ <b>Сторож ТСПУ: проблема</b>\n" + "\n".join("• " + p for p in problems))
        print("АЛЕРТ отправлен")
        sys.exit(1)
    print("всё в норме")


if __name__ == "__main__":
    main()
