"""Unit tests for configuration loading."""

import pytest

from check_msdefender.core.config import _find_config_file, load_config

_INI = """[auth]
client_id = abc
tenant_id = def
client_secret = ghi
"""


class TestLoadConfig:
    """Tests for load_config."""

    def test_load_from_absolute_path(self, tmp_path):
        """Load a config file given its absolute path."""
        ini = tmp_path / "check_msdefender.ini"
        ini.write_text(_INI)
        config = load_config(str(ini))
        assert config.has_section("auth")
        assert config["auth"]["client_id"] == "abc"

    def test_missing_file_raises(self, tmp_path):
        """A path that does not exist raises FileNotFoundError."""
        missing = tmp_path / "nope.ini"
        with pytest.raises(FileNotFoundError, match="Configuration file not found"):
            load_config(str(missing))


class TestFindConfigFile:
    """Tests for _find_config_file."""

    def test_absolute_path_returned_as_is(self, tmp_path):
        """An absolute path is returned unchanged."""
        absolute = str(tmp_path / "x.ini")
        assert _find_config_file(absolute) == absolute

    def test_found_in_current_directory(self, tmp_path, monkeypatch):
        """A relative path is resolved against the current directory."""
        ini = tmp_path / "check_msdefender.ini"
        ini.write_text(_INI)
        monkeypatch.chdir(tmp_path)
        assert _find_config_file("check_msdefender.ini") == str(ini)

    def test_falls_back_to_original_path(self, tmp_path, monkeypatch):
        """When nowhere to be found, the original relative path is returned."""
        monkeypatch.chdir(tmp_path)
        assert _find_config_file("absent.ini") == "absent.ini"
