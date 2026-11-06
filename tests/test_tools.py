"""Core tests: no LLM, no network. They use the fictitious logs in tests/test_data/."""
import requests

from soc import config, tools


# ------------------------------------------------------------------ list_logs
def test_list_logs_returns_only_log_files():
    result = tools.list_logs()
    assert "auth.log" in result
    assert "access.log" in result
    assert "threat_intel.csv" not in result   # not a .log file


# ----------------------------------------------------------- analyze_auth_log
def test_successful_brute_force_is_critical():
    result = tools.analyze_auth_log("auth.log")
    assert "CRITICAL 198.51.100.5" in result
    assert "'deploy'" in result


def test_failed_brute_force_is_high():
    result = tools.analyze_auth_log("auth.log")
    assert "HIGH 192.0.2.10: 12 failed attempts" in result   # "invalid user" lines count too


def test_legitimate_typos_are_not_flagged():
    result = tools.analyze_auth_log("auth.log")
    alerts, normal = result.split("Logins without anomalies")
    assert "10.0.0.20" not in alerts
    assert "10.0.0.20" in normal


def test_path_traversal_is_blocked():
    assert "not found" in tools.analyze_auth_log("../../pyproject.toml")


def test_missing_file():
    assert "not found" in tools.analyze_auth_log("does_not_exist.log")


# ------------------------------------------------------------ analyze_web_log
def test_web_signatures_detected():
    result = tools.analyze_web_log("access.log")
    assert "203.0.113.4 " in result and "SQL injection: 2" in result
    assert "203.0.113.40" in result and "XSS" in result
    assert "192.0.2.77" in result and "Path traversal" in result
    assert "198.51.100.9" in result and "Log4Shell" in result


def test_normal_traffic_and_trap_do_not_surface():
    result = tools.analyze_web_log("access.log")
    assert "10.0.1.5" not in result
    assert "203.0.113.66" not in result       # the injection lives in the User-Agent
    assert "AI ASSISTANT" not in result       # its text never reaches the model


# ----------------------------------------------------------------- show_lines
def test_show_lines_wraps_untrusted_data():
    result = tools.show_lines("access.log", "203.0.113.66")
    assert result.startswith("<untrusted_data>")
    assert result.endswith("</untrusted_data>")


def test_show_lines_does_not_confuse_similar_ips():
    result = tools.show_lines("access.log", "203.0.113.4", max_lines=10)
    assert "203.0.113.40" not in result
    assert result.count("\n") == 3            # 2 lines + the two tags


def test_show_lines_enforces_maximum():
    result = tools.show_lines("auth.log", "192.0.2.10", max_lines=1000)
    lines = result.splitlines()[1:-1]
    assert len(lines) == 10


# --------------------------------------------------------- check_threat_intel
def test_threat_intel_present():
    assert "PRESENT" in tools.check_threat_intel("192.0.2.10")


def test_threat_intel_absent_with_warning():
    result = tools.check_threat_intel("198.51.100.5")
    assert "NOT present" in result
    assert "does not prove" in result


# ----------------------------------------------------------------- lookup_cve
def test_cve_invalid_format():
    assert "Invalid format" in tools.lookup_cve("CVE-abc; rm -rf /")


def test_cve_with_fake_nvd(monkeypatch):
    """Replace requests.get with a fake response: no network in tests."""
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulnerabilities": [{"cve": {
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
                "metrics": {"cvssMetricV31": [
                    {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
            }}]}

    monkeypatch.setattr(requests, "get", lambda *a, **k: FakeResponse())
    result = tools.lookup_cve("cve-2021-44228")
    assert "CVE-2021-44228 - CVSS 10.0 (CRITICAL)" in result
    assert "JNDI" in result


def test_cve_network_unavailable(monkeypatch):
    def fail(*a, **k):
        raise requests.ConnectionError("no network")

    monkeypatch.setattr(requests, "get", fail)
    assert "Unable to reach NVD" in tools.lookup_cve("CVE-2021-44228")


# ----------------------------------------------------------- propose_ip_block
def test_internal_ip_can_never_be_blocked():
    assert "Automatically REJECTED" in tools.propose_ip_block("10.0.0.20", "test")


def test_invalid_ip():
    assert "not a valid IP" in tools.propose_ip_block("999.1.1.1", "test")


def test_block_approved(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    result = tools.propose_ip_block("198.51.100.5", "successful brute force")
    assert "approved" in result
    assert "DROP 198.51.100.5" in config.BLOCKLIST_FILE.read_text(encoding="utf-8")


def test_block_rejected_by_default(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "")     # analyst just presses Enter
    result = tools.propose_ip_block("198.51.100.5", "test")
    assert "REJECTED" in result
    assert not config.BLOCKLIST_FILE.exists()


# --------------------------------------------------------------- write_report
def test_report_name_is_sanitized():
    result = tools.write_report("../../etc/Night Report!", "content")
    created = list(config.REPORTS_DIR.glob("*.md"))
    assert len(created) == 1
    assert created[0].parent == config.REPORTS_DIR
    assert created[0].name.endswith("-etc-night-report.md")
    assert "Report saved" in result