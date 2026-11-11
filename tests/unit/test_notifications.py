import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest
from pydantic import SecretStr

from app.core.config import EmailSettings, NotificationSettings, TelegramSettings, WebhookSettings
from app.core.errors import ConfigError, ValidationFailed
from app.detection.events import SecurityEvent
from app.monitoring.alerts import ResourceMonitor
from app.notifications import channels as ch
from app.notifications.base import Notification
from app.notifications.dispatcher import Dispatcher, build_channels


class Capture(BaseHTTPRequestHandler):
    seen: ClassVar[list] = []
    status = 200

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        Capture.seen.append((self.path, dict(self.headers), self.rfile.read(n)))
        self.send_response(Capture.status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def http():
    Capture.seen, Capture.status = [], 200
    srv = HTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_webhook_signed_payload(http):
    c = ch.WebhookChannel(WebhookSettings(enabled=True, url=http + "/hook", secret=SecretStr("k"), allow_private=True))
    c.send(Notification("t", "b", "high", {"ip": "1.2.3.4"}))
    path, headers, body = Capture.seen[0]
    assert path == "/hook" and json.loads(body)["fields"] == {"ip": "1.2.3.4"}
    assert headers["X-Averqon-Signature"] == "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest", "https://127.0.0.1/x", "https://localhost/x", "https://[::1]/x",
                                 "https://10.0.0.5/x", "http://example.com/x", "file:///etc/passwd", "ftp://x", "https://u:p@example.com/",
                                 "https:///nohost"])
def test_ssrf_guard(url):
    with pytest.raises(ValidationFailed):
        ch.check_target(url, allow_private=False)


def test_webhook_does_not_follow_redirects(http):
    class Redirect(Capture):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/")
            self.end_headers()
    srv = HTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = ch.WebhookChannel(WebhookSettings(enabled=True, url=f"http://127.0.0.1:{srv.server_address[1]}/", allow_private=True))
    with pytest.raises(OSError, match="HTTP 302"):
        c.send(Notification("t", "b"))
    srv.shutdown()


def test_telegram_request_and_error_hides_token(http):
    cfg = TelegramSettings(enabled=True, bot_token=SecretStr("123:SECRET"), chat_id="42", api_base=http)
    ch.TelegramChannel(cfg).send(Notification("T", "B", "high"))
    path, _, body = Capture.seen[0]
    assert path == "/bot123:SECRET/sendMessage" and json.loads(body)["chat_id"] == "42" and "[HIGH] T" in json.loads(body)["text"]
    Capture.status = 401
    with pytest.raises(OSError) as e:
        ch.TelegramChannel(cfg).send(Notification("T", "B"))
    assert "SECRET" not in str(e.value)
    with pytest.raises(ConfigError):
        ch.TelegramChannel(TelegramSettings(enabled=True))


def test_email_header_injection_and_smtp(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            sent["conn"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): sent["tls"] = True
        def login(self, u, p): sent["login"] = (u, p)
        def send_message(self, m): sent["msg"] = m

    monkeypatch.setattr(ch.smtplib, "SMTP", FakeSMTP)
    cfg = EmailSettings(enabled=True, host="mail", from_addr="a@x.org", to_addrs=["b@x.org"], username="u", password=SecretStr("p"))
    c = ch.EmailChannel(cfg)
    c.send(Notification("evil\r\nBcc: attacker@evil.org", "body", "high"))
    m = sent["msg"]
    assert sent["tls"] and sent["login"] == ("u", "p") and m["Bcc"] is None and "\n" not in m["Subject"]
    for bad in (["b@x.org\r\nBcc: z@z"], ["nodomain"], ["a@b.c, d@e.f"]):
        with pytest.raises(ConfigError):
            ch.EmailChannel(EmailSettings(enabled=True, from_addr="a@x.org", to_addrs=bad))
    with pytest.raises(ConfigError):
        ch.EmailChannel(EmailSettings(enabled=True))


class Recorder:
    name = "rec"
    def __init__(self, fail=0): self.got, self.fail = [], fail
    def send(self, n):
        if self.fail:
            self.fail -= 1
            raise OSError("down")
        self.got.append(n)


def disp(rec, **kw):
    cfg = NotificationSettings(min_severity=kw.pop("min", "high"), dedupe_seconds=kw.pop("dedupe", 300))
    return Dispatcher([rec], cfg, sync=True, backoff=0, **kw), cfg


def test_severity_filter_dedupe_retry_and_isolation():
    rec = Recorder()
    d, _ = disp(rec)
    assert not d.notify(Notification("x", "y", "low")) and d.notify(Notification("x", "y", "critical"))
    assert d.notify(Notification("a", "b", "high"), dedupe_key="k") and not d.notify(Notification("a", "b", "high"), dedupe_key="k")
    flaky = Recorder(fail=2)
    d2, _ = disp(flaky)
    d2.notify(Notification("x", "y", "high"))
    assert len(flaky.got) == 1 and d2.sent == 1
    dead = Recorder(fail=99)
    d3, _ = disp(dead)
    d3.notify(Notification("x", "y", "high"))  # must not raise
    assert d3.failed == 1 and not Dispatcher([], NotificationSettings()).notify(Notification("x", "y", "critical"))


def test_dedupe_expires():
    t = [0.0]
    rec = Recorder()
    d, _ = disp(rec, clock=lambda: t[0], dedupe=10)
    assert d.notify(Notification("a", "b", "high"), dedupe_key="k")
    t[0] = 11
    assert d.notify(Notification("a", "b", "high"), dedupe_key="k")


def test_event_listener():
    rec = Recorder()
    d, _ = disp(rec, min="medium")
    lst = d.event_listener()
    lst(SecurityEvent(kind="x", source_ip="1.1.1.1", severity="low"), "none")
    lst(SecurityEvent(kind="jail_threshold", source_ip="1.1.1.1", severity="high", jail="sshd"), "banned")
    lst(SecurityEvent(kind="jail_threshold", source_ip="1.1.1.1", severity="high", jail="sshd"), "banned")
    assert len(rec.got) == 1 and "(banned)" in rec.got[0].title and rec.got[0].fields["jail"] == "sshd"


def test_build_channels_and_resource_alerts():
    cfg = NotificationSettings(telegram=TelegramSettings(enabled=True, bot_token=SecretStr("t"), chat_id="1"),
                               webhook=WebhookSettings(enabled=True, url="https://example.com/h"))
    assert [c.name for c in build_channels(cfg)] == ["telegram", "webhook"]
    rec = Recorder()
    d, c2 = disp(rec)
    t = [0.0]
    snap = {"cpu_percent": 95, "memory": {"percent": 10}, "disk": {"percent": 99}}
    m = ResourceMonitor(d, c2, snapshot=lambda: snap, clock=lambda: t[0])
    assert m.check() == ["cpu", "disk"] and m.check() == []
    t[0] = 5000
    assert m.check() == ["cpu", "disk"] and len(rec.got) == 4
