"""Tests for policy-guard CLI commands."""
from click.testing import CliRunner
from policy_guard.cli import main


class TestMainGroup:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "policy-guard" in result.output

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "demo" in result.output
        assert "rules" in result.output


class TestScanCommand:
    def test_scan_good_manifests(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests])
        assert result.exit_code == 0

    def test_scan_bad_manifests(self, bad_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_manifests])
        assert result.exit_code == 0

    def test_scan_verbose(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--verbose"])
        assert result.exit_code == 0

    def test_scan_export_json(self, good_manifests, tmp_path):
        output = str(tmp_path / "report.json")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--format", "json", "--output", output])
        assert result.exit_code == 0
        import json
        with open(output) as f:
            data = json.load(f)
        assert "violations" in data

    def test_scan_export_html(self, good_manifests, tmp_path):
        output = str(tmp_path / "report.html")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--format", "html", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "report.html").exists()

    def test_scan_export_sarif(self, good_manifests, tmp_path):
        output = str(tmp_path / "report.sarif")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--format", "sarif", "--output", output])
        assert result.exit_code == 0
        assert (tmp_path / "report.sarif").exists()

    def test_scan_nonexistent_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_fail_on(self, bad_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", bad_manifests, "--fail-on", "critical"])
        assert result.exit_code in (0, 1)

    def test_scan_level_baseline(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--level", "baseline"])
        assert result.exit_code == 0

    def test_scan_level_privileged(self, good_manifests):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", good_manifests, "--level", "privileged"])
        assert result.exit_code == 0


class TestDemoCommand:
    def test_demo_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["demo"])
        assert result.exit_code == 0


class TestRulesCommand:
    def test_rules_list(self):
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "PG-" in result.output
