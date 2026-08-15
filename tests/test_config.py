import pytest

from pestilentia.config import Settings, _load


def test_defaults_applied(monkeypatch):
    monkeypatch.delenv("PEST_DB_URL", raising=False)
    monkeypatch.delenv("PEST_LOG_LEVEL", raising=False)
    monkeypatch.delenv("PEST_API_BASE_URL", raising=False)
    monkeypatch.delenv("PEST_POLL_INTERVAL_HOURS", raising=False)
    monkeypatch.delenv("PEST_WEB_HOST", raising=False)
    monkeypatch.delenv("PEST_WEB_PORT", raising=False)
    monkeypatch.delenv("PEST_FUZZY_THRESHOLD", raising=False)
    s = _load()
    assert s.db_url == "sqlite:///elementaryctiDB.db"
    assert s.log_level == "INFO"
    assert s.poll_interval_hours == 4
    assert s.web_port == 8000
    assert s.fuzzy_threshold == 85


def test_load_from_env(monkeypatch):
    monkeypatch.setenv("PEST_DB_URL", "postgresql://localhost/test")
    monkeypatch.setenv("PEST_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("PEST_POLL_INTERVAL_HOURS", "6")
    monkeypatch.setenv("PEST_WEB_PORT", "9000")
    monkeypatch.setenv("PEST_FUZZY_THRESHOLD", "90")
    s = _load()
    assert s.db_url == "postgresql://localhost/test"
    assert s.log_level == "DEBUG"
    assert s.poll_interval_hours == 6
    assert s.web_port == 9000
    assert s.fuzzy_threshold == 90


def test_invalid_type_exits(monkeypatch, capsys):
    monkeypatch.setenv("PEST_WEB_PORT", "not-a-number")
    with pytest.raises(SystemExit):
        _load()
    captured = capsys.readouterr()
    assert "PEST_WEB_PORT" in captured.err


def test_settings_frozen():
    s = Settings()
    with pytest.raises(AttributeError):
        s.db_url = "new-value"


def test_partial_env_uses_defaults(monkeypatch):
    monkeypatch.setenv("PEST_LOG_LEVEL", "WARNING")
    monkeypatch.delenv("PEST_DB_URL", raising=False)
    monkeypatch.delenv("PEST_WEB_PORT", raising=False)
    s = _load()
    assert s.log_level == "WARNING"
    assert s.db_url == "sqlite:///elementaryctiDB.db"
    assert s.web_port == 8000


# --- Phase 5: the confidence gate's thresholds -------------------------------


def test_a_gate_threshold_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("PEST_AI_GATE_IOC_MIN", "0.6")

    assert _load().ai_gate_ioc_min == 0.6


@pytest.mark.parametrize("bad", ["85", "-0.1", "1.5"])
def test_a_threshold_outside_zero_to_one_aborts_at_start_up(monkeypatch, capsys, bad):
    """The failure being refused is a percentage typed where a fraction belongs.

    `PEST_AI_GATE_IOC_MIN=85` meant as 85% would otherwise be read as a float
    no finding can ever reach, and the gate would look like a scoring bug for
    as long as it took someone to find it. Coercing it to something permissive
    would be worse: the gate would open silently.
    """
    monkeypatch.setenv("PEST_AI_GATE_IOC_MIN", bad)

    with pytest.raises(SystemExit):
        _load()

    assert "PEST_AI_GATE_IOC_MIN" in capsys.readouterr().err


def test_the_local_lift_is_validated_like_the_thresholds(monkeypatch):
    monkeypatch.setenv("PEST_AI_GATE_LOCAL_LIFT", "2.0")

    with pytest.raises(SystemExit):
        _load()
