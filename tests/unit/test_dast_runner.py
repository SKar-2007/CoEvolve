"""Tests for DAST runner helpers (no servers launched, no network)."""

from __future__ import annotations

import socket
import types

import packages.judge.dast.runner as runner
from packages.judge.dast.runner import (
    ClassResult,
    _check_runtime,
    _find_free_port,
    _start_js_app,
    _start_python_app,
    _wait_for_server,
    run_exploit_against_app,
)


class TestHelpers:
    def test_free_port_bindable(self):
        port = _find_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))  # would raise if unusable

    def test_check_runtime(self):
        assert _check_runtime("python3") is True
        assert _check_runtime("definitely-not-a-binary-xyz") is False

    def test_wait_for_server_closed_port(self):
        assert _wait_for_server("http://127.0.0.1:1/", timeout=0) is False


class TestClassResult:
    def test_passed_requires_all(self):
        r = ClassResult(vuln_class="SQLi")
        assert r.passed is False
        r.app_started = True
        assert r.passed is False
        r.exploit_result = types.SimpleNamespace(success=True)
        assert r.passed is True
        r.exploit_result = types.SimpleNamespace(success=False)
        assert r.passed is False


class TestLaunchers:
    def test_python_unknown_class(self):
        assert _start_python_app("NoSuchClass", 18080) is None

    def test_js_no_runtime(self, monkeypatch):
        monkeypatch.setattr(runner, "_check_runtime", lambda name: False)
        assert _start_js_app("SQLi", 18081) is None

    def test_js_missing_file(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runner, "_check_runtime", lambda name: True)
        monkeypatch.setattr(runner, "TARGETS_DIR", tmp_path)
        assert _start_js_app("SQLi", 18082) is None

    def test_java_no_build(self, monkeypatch):
        monkeypatch.setattr(runner, "_build_java_app", lambda: False)
        assert runner._start_java_app("SQLi", 18083) is None

    def test_java_build_missing_pom(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runner, "_java_built", False)
        monkeypatch.setattr(runner, "TARGETS_DIR", tmp_path)
        assert runner._build_java_app() is False

    def test_registries_consistent(self):
        assert set(runner.LAUNCHERS) == {"python", "javascript", "java"}
        assert set(runner.APP_REGISTRIES) == {"python", "javascript", "java"}


class TestExploitDispatch:
    def test_success_path(self, monkeypatch):
        calls = {}

        class FakeExecutor:
            def execute_http(self, **kwargs):
                calls.update(kwargs)
                return types.SimpleNamespace(success=True)

        monkeypatch.setattr(runner, "ExploitExecutor", FakeExecutor)
        result = run_exploit_against_app("SQLi", 1234, lang="python")
        assert result.exploit_result.success is True
        assert calls["base_url"] == "http://127.0.0.1:1234"
        assert calls["endpoint"] == "/search"

    def test_executor_error_captured(self, monkeypatch):
        class Broken:
            def execute_http(self, **kwargs):
                raise ConnectionError("refused")

        monkeypatch.setattr(runner, "ExploitExecutor", Broken)
        result = run_exploit_against_app("SQLi", 1234)
        assert result.exploit_result is None
        assert "refused" in result.error

    def test_unknown_class_default_endpoint(self, monkeypatch):
        class FakeExecutor:
            def execute_http(self, **kwargs):
                calls.update(kwargs)
                return types.SimpleNamespace(success=False)

        calls = {}
        monkeypatch.setattr(runner, "ExploitExecutor", FakeExecutor)
        run_exploit_against_app("NoSuchClass", 1234)
        assert calls["endpoint"] == "/"


class TestRunAll:
    def test_unknown_lang_returns_empty(self):
        result = runner.run_all(lang="cobol")
        assert result.total == 0
        assert result.results == []

    def test_missing_runtime_skips(self, monkeypatch):
        monkeypatch.setattr(runner, "_check_runtime", lambda name: False)
        result = runner.run_all(classes=["SQLi"], lang="python")
        assert result.total == 0
        assert result.results == []
