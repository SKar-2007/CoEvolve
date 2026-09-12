"""End-to-end DAST runner: starts vulnerable apps and runs exploits.

Supports Python (Flask), JavaScript (Node.js), and Java targets.

Usage:
    python -m packages.judge.dast.runner
    python -m packages.judge.dast.runner --classes SQLi PathTraversal
    python -m packages.judge.dast.runner --all
    python -m packages.judge.dast.runner --lang python
    python -m packages.judge.dast.runner --lang javascript
    python -m packages.judge.dast.runner --lang java
    python -m packages.judge.dast.runner --lang all
"""

from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .executor import DASTResult, ExploitExecutor
from .targets.vulnerable_app import APP_REGISTRY as PYTHON_APPS

TARGETS_DIR = Path(__file__).resolve().parent / "targets"

# JavaScript apps: {class_name: (endpoint, param)}
JS_APPS = {
    "SQLi": ("/search", "name"),
    "PathTraversal": ("/files", "name"),
    "CommandInjection": ("/ping", "host"),
    "XSS": ("/search", "q"),
    "SSRF": ("/fetch", "url"),
    "OpenRedirect": ("/redirect", "url"),
}

# Java apps: same endpoints as JS
JAVA_APPS = dict(JS_APPS)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: int = 15) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _check_runtime(name: str) -> bool:
    """Check if a runtime (node, java, javac) is available."""
    return shutil.which(name) is not None


@dataclass
class ClassResult:
    vuln_class: str
    lang: str = "python"
    exploit_result: DASTResult | None = None
    app_started: bool = False
    error: str = ""

    @property
    def passed(self) -> bool:
        return self.app_started and self.exploit_result is not None and self.exploit_result.success


@dataclass
class RunResult:
    results: list[ClassResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0


# ---------------------------------------------------------------------------
# Python app launcher
# ---------------------------------------------------------------------------
def _start_python_app(vuln_class: str, port: int) -> subprocess.Popen | None:
    factory = PYTHON_APPS.get(vuln_class)
    if not factory:
        return None

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"""
import sys
sys.path.insert(0, '.')
from packages.judge.dast.targets.vulnerable_app import {factory.__name__}
app = {factory.__name__}()
app.run(host='127.0.0.1', port={port}, debug=False)
""",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


# ---------------------------------------------------------------------------
# JavaScript app launcher
# ---------------------------------------------------------------------------
def _start_js_app(vuln_class: str, port: int) -> subprocess.Popen | None:
    if not _check_runtime("node"):
        return None

    js_file = TARGETS_DIR / "vulnerable_app_js.js"
    if not js_file.exists():
        return None

    proc = subprocess.Popen(
        ["node", str(js_file), "--class", vuln_class, "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


# ---------------------------------------------------------------------------
# Java app launcher
# ---------------------------------------------------------------------------
_java_built = False


def _build_java_app() -> bool:
    """Build the Spring Boot app with Maven if needed."""
    global _java_built
    if _java_built:
        return True

    java_dir = TARGETS_DIR / "vulnerable_app_java"
    if not (java_dir / "pom.xml").exists():
        return False

    # Find Maven: check PATH, JAVA_HOME, common locations
    mvn_cmd = shutil.which("mvn")
    if not mvn_cmd:
        import os

        java_home = os.environ.get("JAVA_HOME", "")
        if java_home:
            candidate = Path(java_home) / ".." / "apache-maven-3.9.6" / "bin" / "mvn"
            if candidate.exists():
                mvn_cmd = str(candidate)
    if not mvn_cmd:
        # Try common homebrew/sdkman paths
        for p in [
            Path.home() / ".sdkman" / "candidates" / "maven" / "current" / "bin" / "mvn",
            Path("/usr/local/bin/mvn"),
        ]:
            if p.exists():
                mvn_cmd = str(p)
                break
    if not mvn_cmd:
        return False

    result = subprocess.run(
        [mvn_cmd, "package", "-q", "-DskipTests"],
        capture_output=True,
        cwd=str(java_dir),
    )
    if result.returncode != 0:
        print(f"    Maven build failed: {result.stderr.decode()[:200]}")
        return False

    _java_built = True
    return True


def _start_java_app(vuln_class: str, port: int) -> subprocess.Popen | None:
    """Start a Spring Boot app for a specific vulnerability class."""
    java_dir = TARGETS_DIR / "vulnerable_app_java"

    # Build first if needed
    if not _build_java_app():
        return None

    jar_path = java_dir / "target" / "vulnapp-1.0.0.jar"
    if not jar_path.exists():
        return None

    proc = subprocess.Popen(
        ["java", "-jar", str(jar_path)],
        env={**__import__("os").environ, "PORT": str(port)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


# ---------------------------------------------------------------------------
# Exploit execution
# ---------------------------------------------------------------------------
def run_exploit_against_app(vuln_class: str, port: int, lang: str = "python") -> ClassResult:
    """Run the exploit for a given class against the running app."""
    result = ClassResult(vuln_class=vuln_class, lang=lang)
    base_url = f"http://127.0.0.1:{port}"

    executor = ExploitExecutor()

    # All languages share the same endpoint/param mapping
    endpoint_map = {
        "SQLi": ("/search", "name", False, None),
        "PathTraversal": ("/files", "name", False, None),
        "CommandInjection": ("/ping", "host", False, None),
        "XSS": ("/xss", "q", False, None),
        "SSTI": ("/greet", "name", False, None),
        "SSRF": ("/fetch", "url", False, f"http://127.0.0.1:{port}/internal/metadata"),
        "OpenRedirect": ("/redirect", "url", False, None),
    }

    endpoint, param, follow_redirects, payload_override = endpoint_map.get(
        vuln_class, ("/", "name", False, None)
    )

    try:
        result.exploit_result = executor.execute_http(
            class_id=vuln_class,
            base_url=base_url,
            endpoint=endpoint,
            param_name=param,
            follow_redirects=follow_redirects,
            payload_override=payload_override,
        )
    except Exception as e:
        result.error = str(e)

    return result


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------
LAUNCHERS = {
    "python": _start_python_app,
    "javascript": _start_js_app,
    "java": _start_java_app,
}

APP_REGISTRIES = {
    "python": PYTHON_APPS,
    "javascript": JS_APPS,
    "java": JAVA_APPS,
}


def run_all(
    classes: list[str] | None = None,
    lang: str = "all",
    port_override: int | None = None,
) -> RunResult:
    """Run DAST exploits against all (or selected) vulnerable apps."""
    run_result = RunResult()

    # Determine which languages to run
    languages = ["python", "javascript", "java"] if lang == "all" else [lang]

    for language in languages:
        launcher = LAUNCHERS.get(language)
        app_registry = APP_REGISTRIES.get(language, {})

        if not launcher:
            continue

        # Check runtime availability
        runtime_map = {"python": "python3", "javascript": "node", "java": "java"}
        runtime = runtime_map.get(language)
        if runtime and not _check_runtime(runtime):
            print(f"  [{language}] {runtime} not found, skipping")
            continue

        target_classes = classes or list(app_registry.keys())

        for vuln_class in target_classes:
            if vuln_class not in app_registry:
                # SSTI not supported in JS/Java
                continue

            port = port_override or _find_free_port()
            proc = launcher(vuln_class, port)

            if proc is None:
                run_result.results.append(
                    ClassResult(vuln_class=vuln_class, lang=language, error="Failed to start")
                )
                run_result.skipped += 1
                continue

            try:
                url = f"http://127.0.0.1:{port}/internal/metadata"
                # Java Spring Boot takes ~45s to start; Python/JS take ~2s
                wait_timeout = 60 if language == "java" else 15
                if not _wait_for_server(url, timeout=wait_timeout):
                    run_result.results.append(
                        ClassResult(
                            vuln_class=vuln_class, lang=language, error="Server did not start"
                        )
                    )
                    run_result.skipped += 1
                    continue

                class_result = run_exploit_against_app(vuln_class, port, lang=language)
                class_result.app_started = True
                run_result.results.append(class_result)

                if class_result.passed:
                    run_result.passed += 1
                else:
                    run_result.failed += 1
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                run_result.total += 1

    return run_result


def print_results(result: RunResult) -> None:
    """Print formatted DAST results."""
    print("=" * 70)
    print("CoEvolve DAST Exploit Verification (Multi-Language)")
    print("=" * 70)

    for r in result.results:
        status = "PASS" if r.passed else "FAIL" if r.app_started else "SKIP"
        icon = "+" if r.passed else "-" if r.app_started else "~"
        lang_tag = f" [{r.lang}]" if r.lang else ""
        print(f"\n[{icon}] {r.vuln_class}{lang_tag}: {status}")
        if r.exploit_result:
            print(f"    Payload: {r.exploit_result.payload[:60]}")
            print(f"    Success: {r.exploit_result.success}")
            if r.exploit_result.evidence:
                print(f"    Evidence: {r.exploit_result.evidence}")
            print(f"    Time: {r.exploit_result.execution_time_ms}ms")
        if r.error:
            print(f"    Error: {r.error}")

    print("\n" + "=" * 70)
    print(
        f"Results: {result.passed}/{result.total} passed, {result.failed} failed, {result.skipped} skipped"
    )
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="DAST exploit runner (multi-language)")
    parser.add_argument("--classes", nargs="*", help="Vulnerability classes to test")
    parser.add_argument("--port", type=int, help="Fixed port for all apps")
    parser.add_argument(
        "--lang",
        default="all",
        choices=["python", "javascript", "java", "all"],
        help="Language to test (default: all)",
    )
    parser.add_argument("--all", action="store_true", help="Run all classes")
    args = parser.parse_args()

    classes = args.classes if args.classes else (list(PYTHON_APPS.keys()) if args.all else None)
    result = run_all(classes=classes, lang=args.lang, port_override=args.port)
    print_results(result)

    if result.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
