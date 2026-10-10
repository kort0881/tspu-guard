#!/usr/bin/env python3
"""
Сторож контура ТСПУ — запускается из GitHub Actions по расписанию.
Проверяет: срок сертификата, доступность DNS-туннеля (резолв + TCP
через сам туннель), сквозной канал (мост→выход). Алертит в Telegram.

Секреты (Settings → Secrets → Actions):
  TG_TOKEN, TG_CHAT, CLIENT_JSON
  DOMAIN, EXPECT_EXIT, TUNNEL_DOMAIN
Опционально:
  TUNNEL_PORT   — порт для проверки DNS-туннеля, по умолчанию 443
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
TUNNEL_PORT   = int(os.getenv("TUNNEL_PORT", "443"))
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


SOCKS_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def socks5_tcp_connect(host: str, port: int, timeout: int = 15) -> tuple[bool, str]:
    """
    Проверяет: может ли SOCKS5-прокси (xray) установить TCP-соединение
    до host:port. DNS-резолв делает сторона прокси (ATYP=domain).
    Возвращает (ok, сообщение об ошибке).
    """
    socks_host, socks_port_s = SOCKS.split(":")
    socks_port = int(socks_port_s)

    try:
        s = socket.create_connection((socks_host, socks_port), timeout=timeout)
    except OSError as ex:
        return False, f"нет соединения с SOCKS {SOCKS}: {ex}"

    try:
        s.settimeout(timeout)
        # Приветствие: SOCKS5, метод 0x00 (no auth)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            return False, f"SOCKS5 greeting failed: {resp!r}"

        # Запрос CONNECT с доменом (ATYP=0x03)
        host_b = host.encode("idna") if host.isascii() else host.encode("utf-8")
        if len(host_b) > 255:
            return False, "домен длиннее 255 байт"
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + port.to_bytes(2, "big")
        s.sendall(req)

        resp = s.recv(10)
        if len(resp) < 2 or resp[0] != 0x05:
            return False, f"SOCKS5 ответ мусорный: {resp!r}"
        code = resp[1]
        if code != 0x00:
            return False, SOCKS_ERRORS.get(code, f"код 0x{code:02x}")
        return True, ""
    except socket.timeout:
        return False, "таймаут SOCKS5"
    except OSError as ex:
        return False, f"ошибка SOCKS5: {ex}"
    finally:
        try:
            s.close()
        except OSError:
            pass


def curl_socks(url: str, timeout: int = 30, want_body: bool = False) -> tuple[str, str, str]:
    """GET через SOCKS5 с удалённым DNS. -> (http_code, body, stderr)."""
    args = [
        "curl", "-sS",
        "-o", "/dev/stdout" if want_body else "/dev/null",
        "-w", "\n%{http_code}",
        "--max-time", str(timeout),
        "--socks5-hostname", SOCKS,
        url,
    ]
    res = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 15)
    out = res.stdout or ""
    body, code = "", ""
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

        # 1) Сквозной канал: реальный исходящий IP через туннель.
        #    Это единственная надёжная проверка: если выходной IP совпадает
        #    с EXPECT_EXIT, значит весь контур (мост→туннель→выход) работает.
        #    Отдельная проверка DNS-туннеля через TCP убрана: dnstt использует
        #    UDP:53 + SOCKS:1080, а порт 443 на мосту занят xray xhttp-in
        #    (VLESS/XHTTP, не TLS), поэтому TCP+TLS к нему всегда падает.
        _, body, err = curl_socks("https://api.ipify.org", timeout=30, want_body=True)
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
