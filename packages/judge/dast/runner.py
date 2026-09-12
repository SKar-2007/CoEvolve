"""End-to-end DAST runner: starts vulnerable apps and runs exploits.

Usage:
    python -m packages.judge.dast.runner
    python -m packages.judge.dast.runner --classes SQLi PathTraversal
    python -m packages.judge.dast.runner --all
"""

from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field

from .executor import DASTResult, ExploitExecutor
from .targets.vulnerable_app import APP_REGISTRY


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


@dataclass
class ClassResult:
    vuln_class: str
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


def run_exploit_against_app(vuln_class: str, port: int) -> ClassResult:
    """Run the exploit for a given class against the running app."""
    result = ClassResult(vuln_class=vuln_class)
    base_url = f"http://127.0.0.1:{port}"

    executor = ExploitExecutor()

    endpoint_map = {
        "SQLi": ("/search", "name", False, None),
        "PathTraversal": ("/files", "name", False, None),
        "CommandInjection": ("/ping", "host", False, None),
        "XSS": ("/search", "q", False, None),
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


def run_all(classes: list[str] | None = None, port_override: int | None = None) -> RunResult:
    """Run DAST exploits against all (or selected) vulnerable apps."""
    run_result = RunResult()
    target_classes = classes or list(APP_REGISTRY.keys())

    for vuln_class in target_classes:
        if vuln_class not in APP_REGISTRY:
            run_result.results.append(
                ClassResult(vuln_class=vuln_class, error=f"Unknown class: {vuln_class}")
            )
            run_result.skipped += 1
            continue

        port = port_override or _find_free_port()
        factory = APP_REGISTRY[vuln_class]

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

        try:
            url = f"http://127.0.0.1:{port}/"
            if not _wait_for_server(url):
                run_result.results.append(
                    ClassResult(vuln_class=vuln_class, error="Server did not start")
                )
                run_result.skipped += 1
                continue

            class_result = run_exploit_against_app(vuln_class, port)
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
    print("=" * 60)
    print("CoEvolve DAST Exploit Verification")
    print("=" * 60)

    for r in result.results:
        status = "PASS" if r.passed else "FAIL" if r.app_started else "SKIP"
        icon = "+" if r.passed else "-" if r.app_started else "~"
        print(f"\n[{icon}] {r.vuln_class}: {status}")
        if r.exploit_result:
            print(f"    Payload: {r.exploit_result.payload[:60]}")
            print(f"    Success: {r.exploit_result.success}")
            if r.exploit_result.evidence:
                print(f"    Evidence: {r.exploit_result.evidence}")
            print(f"    Time: {r.exploit_result.execution_time_ms}ms")
        if r.error:
            print(f"    Error: {r.error}")

    print("\n" + "=" * 60)
    print(
        f"Results: {result.passed}/{result.total} passed, {result.failed} failed, {result.skipped} skipped"
    )
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="DAST exploit runner")
    parser.add_argument("--classes", nargs="*", help="Vulnerability classes to test (default: all)")
    parser.add_argument("--port", type=int, help="Fixed port for all apps (default: random)")
    parser.add_argument("--all", action="store_true", help="Run all classes")
    args = parser.parse_args()

    classes = args.classes if args.classes else (list(APP_REGISTRY.keys()) if args.all else None)
    result = run_all(classes=classes, port_override=args.port)
    print_results(result)

    if result.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
