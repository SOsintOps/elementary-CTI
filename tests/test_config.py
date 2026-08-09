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
