"""Unit tests for log_format.parse_logger_name."""
import pytest
from vigil.log_format import parse_logger_name


def test_format_1_asctime_ms_dash():
    line = "2026-04-21 12:00:00,123 INFO vigil.auth.login - user=hong@example.com"
    assert parse_logger_name(line) == "vigil.auth.login"


def test_format_1_asctime_no_ms_dash():
    line = "2026-04-21 12:00:00 INFO vigil.auth.login - message"
    # Format 1 requires comma+ms; this falls through to format 2
    result = parse_logger_name(line)
    assert result == "vigil.auth.login"


def test_format_2_asctime_colon():
    line = "2026-04-21 12:00:00 INFO vigil.payment.processor: card=4539148803436467"
    assert parse_logger_name(line) == "vigil.payment.processor"


def test_format_2_asctime_ms_colon():
    line = "2026-04-21 09:30:00,456 ERROR app.user: something went wrong"
    assert parse_logger_name(line) == "app.user"


def test_format_3_basic_config():
    line = "INFO:vigil.auth.login:user connected"
    assert parse_logger_name(line) == "vigil.auth.login"


def test_format_3_basic_config_error_level():
    line = "ERROR:myapp.db:connection failed"
    assert parse_logger_name(line) == "myapp.db"


def test_format_4_bracketed():
    line = "[2026-04-21 12:00:02] [WARNING] [app.user] 이름=홍길동"
    assert parse_logger_name(line) == "app.user"


def test_format_4_bracketed_debug():
    line = "[2026-01-01 00:00:00] [DEBUG] [my_service.handler] request received"
    assert parse_logger_name(line) == "my_service.handler"


def test_no_logger_name_returns_none():
    line = "박수진 담당자 연락처"
    assert parse_logger_name(line) is None


def test_plain_log_line_returns_none():
    line = "user=hong@example.com rrn=9001011234568"
    assert parse_logger_name(line) is None


def test_case_insensitive_level_format3():
    line = "debug:my.module:something"
    assert parse_logger_name(line) == "my.module"


def test_case_insensitive_level_format1():
    line = "2026-04-21 12:00:00,000 warning my.module - something"
    assert parse_logger_name(line) == "my.module"


def test_logger_name_with_dots_and_hyphens():
    line = "INFO:my-app.sub_module:message"
    assert parse_logger_name(line) == "my-app.sub_module"


def test_logger_name_with_underscore_start():
    line = "INFO:_internal.helper:debug info"
    assert parse_logger_name(line) == "_internal.helper"


def test_ignores_trailing_colons_in_message_format3():
    # Extra colons in the message should not affect name parsing
    line = "INFO:my.module:key=value:extra=colon"
    assert parse_logger_name(line) == "my.module"


def test_empty_line_returns_none():
    assert parse_logger_name("") is None


def test_partial_timestamp_returns_none():
    # Looks like a timestamp but malformed — should not match
    line = "2026-04-21 INFO vigil.module - message"
    assert parse_logger_name(line) is None


def test_format_5_wildfly_embedded():
    # WildFly/JBoss: outer server prefix + inner app log embedded in the line
    line = "[0m00:00:07,720 INFO  [stdout] (default task-1) 2026-04-14 00:00:07.720 [INFO ] [default task-1] c.o.p.a.soc.controller.KmcController - message"
    assert parse_logger_name(line) == "c.o.p.a.soc.controller.KmcController"


def test_format_5_wildfly_warn_level():
    line = "[0m00:00:18,763 INFO  [stdout] (scheduler) 2026-04-14 00:00:18.763 [WARN ] [scheduler] c.o.p.a.p.s.ClipPointServiceImpl - timeout"
    assert parse_logger_name(line) == "c.o.p.a.p.s.ClipPointServiceImpl"


def test_format_5_wildfly_error_level():
    line = "... 2026-04-14 09:00:00.000 [ERROR] [http-thread] com.example.MyService - something failed"
    assert parse_logger_name(line) == "com.example.MyService"
