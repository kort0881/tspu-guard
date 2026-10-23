#!/usr/bin/env python3
"""
Сторож контура ТСПУ — запускается из GitHub Actions по расписанию.
Проверяет: срок сертификата, сквозной канал (мост→выход) через SOCKS.
При падении канала — триада диагностики (direct, bridge-reach по
CLIENT_JSON, socks-tcp, plain-HTTP, TLS 1.2) с классификацией RST/timeout,
и хвост лога xray в алерте.

Секреты:
  TG_TOKEN, TG_CHAT, CLIENT_JSON
  DOMAIN, EXPECT_EXIT
Опционально:
  TUNNEL_DOMAIN — адрес моста (fallback, если из CLIENT_JSON не извлеклось)
  TUNNEL_PORT   — порт моста, по умолчанию 443
  SOCKS         — по умолчанию 127.0.0.1:10808
  XRAY_BIN      — по умолчанию xray
  CERT_MIN_DAYS — по умолчанию 7
  ROUNDS        — кругов по эхо при проверке канала, по умолчанию 3
  ROUND_PAUSE   — пауза между кругами, сек, по умолчанию 12
  CONTOUR_OFF   — 1 = пропустить сквозную проверку (рубильник)
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

IP_ECHO = [
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
]

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


def _tcp_connect(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except OSError as ex:
        return False, str(ex)


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


def socks5_tcp_connect(host: str, port: int, timeout: int = 8) -> tuple[bool, str]:
    socks_host, socks_port_s = SOCKS.split(":")
    try:
        s = socket.create_connection((socks_host, int(socks_port_s)), timeout=timeout)
    except OSError as ex:
        return False, f"нет соединения с SOCKS {SOCKS}: {ex}"
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            return False, f"SOCKS5 greeting failed: {resp!r}"
        host_b = host.encode("idna") if host.isascii() else host.encode("utf-8")
        if len(host_b) > 255:
            return False, "домен длиннее 255 байт"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + port.to_bytes(2, "big"))
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


def _curl(url: str, prefix: list[str], timeout: int, want_body: bool,
          tls_max: str | None = None) -> tuple[str, str, str]:
    args = ["curl", "-sS",
            "-o", "/dev/stdout" if want_body else "/dev/null",
            "-w", "\n%{http_code}",
            "--max-time", str(timeout),
            "--connect-timeout", "5"]
    if tls_max:
        args += ["--tls-max", tls_max]
    args += prefix
    args.append(url)
    try:
        res = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 15)
    except subprocess.TimeoutExpired:
        return "000", "", "curl timeout (subprocess)"
    out = res.stdout or ""
    if "\n" in out:
        body, _, code = out.rpartition("\n")
    else:
        body, code = "", out
    return code.strip(), body.strip(), (res.stderr or "").strip()[:300]


def curl_socks(url: str, timeout: int = 30, want_body: bool = False,
               tls_max: str | None = None) -> tuple[str, str, str]:
    return _curl(url, ["--socks5-hostname", SOCKS], timeout, want_body, tls_max)


def curl_direct(url: str, timeout: int = 10, want_body: bool = True,
                tls_max: str | None = None) -> tuple[str, str, str]:
    return _curl(url, ["-4"], timeout, want_body, tls_max)


def _classify_fail(err: str, code: str) -> str:
    """Короткая метка причины сбоя curl — для чтения алерта без разбора."""
    e = err.lower()
    if "ssl_error_syscall" in e:
        return "RST на TLS (DPI/обрыв)"
    if "empty reply" in e:
        return "RST на HTTP (DPI/обрыв)"
    if "timed out" in e or "timeout" in e:
        return "timeout (drop/blackhole — возможен MTU)"
    if "connection refused" in e:
        return "refused"
    if "name or service" in e or "could not resolve" in e:
        return "DNS fail"
    if "connection reset" in e:
        return "RST"
    return f"code={code}" if code and code != "000" else (err[:60] or "unknown")


def extract_servers(cfg: str) -> list[tuple[str, int]]:
    """Best-effort: (host, port) из outbounds CLIENT_JSON (vnext/servers)."""
    try:
        data = json.loads(cfg)
    except Exception:
        return []
    result: list[tuple[str, int]] = []
    for ob in data.get("outbounds") or []:
        st = ob.get("settings") or {}
        for key in ("vnext", "servers"):
            for e in st.get(key) or []:
                addr, port = e.get("address"), e.get("port")
                if addr and port:
                    tup = (addr, int(port))
                    if tup not in result:
                        result.append(tup)
    return result


def _bridge_reach(cfg: str) -> str:
    servers = extract_servers(cfg)
    if servers:
        host, port = servers[0]
        label = f"bridge-reach {host}:{port}"
    elif TUNNEL_DOMAIN:
        host, port = TUNNEL_DOMAIN, TUNNEL_PORT
        label = f"bridge-reach {host}:{port}"
    else:
        return "bridge-reach=SKIP (нет адреса)"

    ok, err = _tcp_connect(host, port, timeout=5)
    if ok:
        return f"{label}=OK"
    el = err.lower()
    if "name or service" in el or "temporary failure" in el:
        return f"{label}=SKIP (нет публичного DNS)"
    return f"{label}=FAIL ({err[:60]})"


def diag_tunnel(cfg: str) -> str:
    """
    Пошаговая триада, отличающая «мост мёртв» от «мост принимает TCP,
    но данные не форвардит» и от «режут только TLS»:
      1) direct        — у раннера вообще есть интернет;
      2) bridge-reach  — мост принимает TCP (по адресу из CLIENT_JSON);
      3) socks-tcp     — xray дотягивается до target:443 через мост;
      4) tunnel-http   — данные проходят через туннель без TLS;
      5) tunnel-tls1.2 — TLS 1.2 через туннель.
    """
    parts: list[str] = []

    code, body, err = curl_direct("https://api.ipify.org", timeout=8)
    parts.append(f"direct=OK ({body[:40]})" if code == "200" and body
                 else f"direct=FAIL ({_classify_fail(err, code)})")

    parts.append(_bridge_reach(cfg))

    ok, err = socks5_tcp_connect("api.ipify.org", 443, timeout=8)
    parts.append("socks-tcp:443=OK" if ok else f"socks-tcp:443=FAIL ({err[:60]})")

    code, body, err = curl_socks("http://api.ipify.org", timeout=8, want_body=True)
    parts.append(f"tunnel-http=OK ({body[:40]})" if code == "200" and body
                 else f"tunnel-http=FAIL ({_classify_fail(err, code)})")

    code, body, err = curl_socks("https://api.ipify.org", timeout=10,
                                 want_body=True, tls_max="1.2")
    parts.append(f"tunnel-tls1.2=OK ({body[:40]})" if code == "200" and body
                 else f"tunnel-tls1.2=FAIL ({_classify_fail(err, code)})")

    return " || ".join(parts)


def check_contour() -> None:
    if os.getenv("CONTOUR_OFF", "0").strip() == "1":
        print("     контур выключен намеренно (CONTOUR_OFF=1) — сквозную проверку пропускаем", flush=True)
        return

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

        socks_host, socks_port_s = SOCKS.split(":")
        if not wait_for_port(socks_host, int(socks_port_s), timeout=15):
            note(False, f"xray не поднял SOCKS {SOCKS} за 15с.")
            return

        rounds = int(os.getenv("ROUNDS", "3"))
        pause = int(os.getenv("ROUND_PAUSE", "12"))
        last_errs: list[str] = []
        for rnd in range(1, rounds + 1):
            for url in IP_ECHO:
                _, body, err = curl_socks(url, timeout=20, want_body=True)
                out = body.strip()
                ep_host = url.split("//", 1)[1]
                if out == EXPECT_EXIT:
                    note(True, f"сквозной канал: выход={EXPECT_EXIT} ({ep_host}, круг {rnd}/{rounds})")
                    return
                if out:
                    last_errs.append(f"{ep_host}: вышел {out}, ожидали {EXPECT_EXIT}")
                else:
                    last_errs.append(f"{ep_host}: {err or 'пустой ответ'}")
                time.sleep(1)
            print(f"     круг {rnd}/{rounds} без успеха", flush=True)
            if rnd < rounds:
                time.sleep(pause)

        note(False,
             f"сквозной канал: выход=ПУСТО после {rounds} кругов по {len(IP_ECHO)} эхо "
             f"(ожидали {EXPECT_EXIT}) | " + "; ".join(last_errs[-3:])
             + " || diag: " + diag_tunnel(cfg))
    finally:
        # Останавливаем xray до чтения лога: Go-логгер сбрасывает буфер
        # только на завершении процесса.
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        # Хвост лога — только при проблемах, чтобы не шуметь в алерте.
        if problems:
            try:
                log.flush(); log.seek(0)
                tail = log.read()[-1200:].strip()
            except Exception as ex:
                tail = f"(read error: {ex})"
            if not tail:
                tail = "(empty — loglevel в CLIENT_JSON может быть none/error, xray не пишет ошибок)"
            problems.append("xray tail: " + tail.replace("\n", " ⏎ ")[:800])

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

    # сквозная проверка из CI ненадёжна (раннер Azure, чужой маршрут): это ИНФО, не тревога.
    # В Telegram уходит только то, что действительно требует вмешательства: сертификат.
    critical = [p for p in problems if "сертификат" in p or "серт" in p]
    channel = [p for p in problems if p not in critical]

    for p in channel:
        print("::notice::канал (инфо, без тревоги): " + p.replace("\n", " ")[:900], flush=True)

    if critical:
        tg("⚠️ <b>Сторож ТСПУ: проблема</b>\n" + "\n".join("• " + p for p in critical))
        for p in critical:
            print("::warning::" + p.replace("\n", " ")[:900], flush=True)
        print("АЛЕРТ отправлен (только по сертификату); выход 0")
        return

    print("всё в норме" if not channel else "тревоги нет: канал/лог — только инфо в CI")


if __name__ == "__main__":
    main()
