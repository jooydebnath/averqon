"""Telegram, Email and Webhook channels."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import smtplib
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

from app.core.config import EmailSettings, TelegramSettings, WebhookSettings
from app.core.errors import ConfigError, ValidationFailed
from app.notifications.base import Notification

TIMEOUT = 10.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # type: ignore[no-untyped-def]
        return None  # redirects could bounce a request to an internal host


_opener = urllib.request.build_opener(_NoRedirect)


def _post(url: str, data: bytes, headers: dict[str, str]) -> None:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            r.read(4096)
    except urllib.error.HTTPError as exc:
        raise OSError(f"HTTP {exc.code}") from None  # never include the URL (may contain a bot token)


def check_target(url: str, *, allow_private: bool) -> None:
    """SSRF guard: https only (http allowed only with allow_private), no private/loopback IPs."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password:
        raise ValidationFailed("webhook url must be http(s) without credentials")
    if p.scheme == "http" and not allow_private:
        raise ValidationFailed("webhook url must use https")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationFailed("webhook host does not resolve") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValidationFailed("webhook target resolves to a private address")


class TelegramChannel:
    name = "telegram"

    def __init__(self, cfg: TelegramSettings) -> None:
        if not cfg.bot_token or not cfg.chat_id:
            raise ConfigError("telegram requires bot_token and chat_id")
        self.cfg = cfg

    def send(self, n: Notification) -> None:
        url = f"{self.cfg.api_base}/bot{self.cfg.bot_token.get_secret_value()}/sendMessage"  # type: ignore[union-attr]
        body = json.dumps({"chat_id": self.cfg.chat_id, "text": n.text()[:4000], "disable_web_page_preview": True})
        _post(url, body.encode(), {"Content-Type": "application/json"})


class WebhookChannel:
    name = "webhook"

    def __init__(self, cfg: WebhookSettings) -> None:
        if not cfg.url:
            raise ConfigError("webhook requires url")
        self.cfg = cfg

    def payload(self, n: Notification) -> bytes:
        return json.dumps({"title": n.title, "body": n.body, "severity": n.severity, "fields": n.fields,
                           "ts": n.ts.isoformat()}, separators=(",", ":")).encode()

    def send(self, n: Notification) -> None:
        check_target(self.cfg.url, allow_private=self.cfg.allow_private)  # re-checked per send (DNS can change)
        body = self.payload(n)
        headers = {"Content-Type": "application/json", "User-Agent": "averqon"}
        if self.cfg.secret:
            headers["X-Averqon-Signature"] = "sha256=" + hmac.new(
                self.cfg.secret.get_secret_value().encode(), body, hashlib.sha256).hexdigest()
        _post(self.cfg.url, body, headers)


def _clean_header(v: str) -> str:
    return " ".join(v.replace("\r", " ").replace("\n", " ").split())[:200]


class EmailChannel:
    name = "email"

    def __init__(self, cfg: EmailSettings) -> None:
        if not cfg.to_addrs or not cfg.from_addr:
            raise ConfigError("email requires from_addr and to_addrs")
        for a in [cfg.from_addr, *cfg.to_addrs]:
            if any(c in a for c in "\r\n,;<> ") or "@" not in a:
                raise ConfigError("invalid email address")
        self.cfg = cfg

    def message(self, n: Notification) -> EmailMessage:
        m = EmailMessage()
        m["Subject"] = _clean_header(f"[Averqon {n.severity}] {n.title}")
        m["From"], m["To"] = self.cfg.from_addr, ", ".join(self.cfg.to_addrs)
        m.set_content(n.text())
        return m

    def send(self, n: Notification) -> None:
        c = self.cfg
        if c.security == "ssl":
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(c.host, c.port, timeout=TIMEOUT, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(c.host, c.port, timeout=TIMEOUT)
        with smtp:
            if c.security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if c.username and c.password:
                smtp.login(c.username, c.password.get_secret_value())
            smtp.send_message(self.message(n))
