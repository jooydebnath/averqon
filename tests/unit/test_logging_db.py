import logging

from sqlalchemy import select

from app.audit.service import record_audit
from app.core.logging import RedactingFilter
from app.database.base import Base, make_engine, make_session_factory, session_scope
from app.database.models import AuditLogEntry


def test_redaction():
    rec = logging.LogRecord("x", logging.INFO, "", 0, "login password=hunter2 token: abc", None, None)
    RedactingFilter().filter(rec)
    assert "hunter2" not in rec.msg and "abc" not in rec.msg


def test_audit_roundtrip_and_rollback():
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)
    f = make_session_factory(engine)
    with session_scope(f) as s:
        record_audit(s, actor="admin", action="ban", target="1.2.3.4", details={"a": 1})
    try:
        with session_scope(f) as s:
            record_audit(s, actor="x", action="y")
            raise RuntimeError
    except RuntimeError:
        pass
    with session_scope(f) as s:
        rows = s.scalars(select(AuditLogEntry)).all()
    assert [r.actor for r in rows] == ["admin"] and rows[0].details == {"a": 1}


def test_json_formatter_and_configure(capsys):
    import json

    from app.core.logging import JsonFormatter, configure_logging

    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        rec = logging.LogRecord("n", logging.ERROR, "", 0, "msg %s", ("a",), sys.exc_info())
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "msg a" and out["level"] == "ERROR" and "boom" in out["exc"]
    configure_logging("DEBUG", json_output=True)
    configure_logging("INFO")  # idempotent: one handler only
    assert len(logging.getLogger().handlers) == 1
    logging.getLogger("t").info("password=hunter2")
    assert "hunter2" not in capsys.readouterr().err
