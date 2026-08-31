"""
reporting/report_generator.py
AI Kavach CRS — Proof-of-Fix Report Generator.

Generates both a Markdown summary and a rich HTML report for each finding.
The HTML report is intended for judges / defence operators.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


class ReportGenerator:
    """Generates proof-of-fix (or failure) reports from FindingReport objects."""

    def __init__(self, output_dir: str = "output/reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, report) -> dict[str, str]:
        """
        Generate Markdown and HTML reports for a finding.

        Args:
            report: A FindingReport instance.

        Returns:
            Dict with keys 'markdown_path' and 'html_path'.
        """
        from models import PipelineStatus
        slug = f"{report.crash.target_name}_{report.crash.stack_fingerprint[:8]}"
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{timestamp}_{slug}"

        md_path = os.path.join(self.output_dir, f"{base_name}.md")
        html_path = os.path.join(self.output_dir, f"{base_name}.html")

        md_content = self._render_markdown(report)
        html_content = self._render_html(report, md_content)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        log.info("[reporter] Reports written:")
        log.info("[reporter]   Markdown: %s", md_path)
        log.info("[reporter]   HTML:     %s", html_path)

        return {"markdown_path": md_path, "html_path": html_path}

    # ------------------------------------------------------------------
    # Markdown render
    # ------------------------------------------------------------------

    def _render_markdown(self, report) -> str:
        from models import PipelineStatus

        c = report.crash
        rca = report.root_cause
        patch = report.patch
        val = report.validation

        status_badge = "✅ PROVEN FIX" if report.is_proven_fix() else "❌ COULD NOT PATCH"
        timestamp = datetime.datetime.now().isoformat()

        lines = [
            f"# AI Kavach — Security Finding Report",
            f"",
            f"**Status:** {status_badge}  ",
            f"**Generated:** {timestamp}  ",
            f"**Target:** `{c.target_name}`  ",
            f"**CWE:** {c.cwe} — {c.cwe_name}  ",
            f"**Severity:** {c.severity.value}  ",
            f"",
            "---",
            "",
            "## 1. Vulnerability Summary",
            "",
        ]

        if rca:
            lines += [
                f"**Root Cause:** {rca.explanation}",
                f"",
                f"**CWE Confirmed:** {rca.cwe_confirmed} — {rca.cwe_name}",
                f"**Exploitability Note:** {c.exploitability_note}",
                f"**LLM Confidence:** {rca.confidence}/10",
                "",
            ]
        else:
            lines += ["*Root cause analysis was not completed.*", ""]

        lines += [
            "---",
            "",
            "## 2. Crash Evidence",
            "",
            "### Crash Input (hex)",
            "```",
            c.crash_input_hex[:500] + ("..." if len(c.crash_input_hex) > 500 else ""),
            "```",
            "",
            "### ASan / UBSan Output (unpatched build)",
            "```",
            c.asan_output[:2000] + ("..." if len(c.asan_output) > 2000 else ""),
            "```",
            "",
            "### Code Slice at Crash Site",
            "```c",
            c.code_slice[:1500] if c.code_slice else "[Not available]",
            "```",
            "",
            "---",
            "",
            "## 3. Generated Patch",
            "",
        ]

        if patch:
            lines += [
                f"**Attempt:** {patch.attempt_number}  ",
                f"**Target File:** `{patch.target_file}`  ",
                f"**Patch Confidence:** {patch.confidence}/10  ",
                f"**Explanation:** {patch.explanation}",
                "",
                "```diff",
                patch.diff,
                "```",
                "",
            ]
        else:
            lines += ["*No patch was generated.*", ""]

        lines += [
            "---",
            "",
            "## 4. Validation Results",
            "",
        ]

        if val:
            def step_row(step):
                icon = "✅" if step.passed else "❌"
                return f"| {step.step_name} | {icon} {('PASS' if step.passed else 'FAIL')} | {step.notes} |"

            lines += [
                "| Validation Step | Result | Notes |",
                "|---|---|---|",
                step_row(val.pre_patch_crash),
                step_row(val.post_patch_crash),
                step_row(val.regression),
                "",
            ]

            if val.pre_patch_crash.stdout:
                lines += [
                    "### Pre-patch Sanitizer Output",
                    "```",
                    val.pre_patch_crash.stdout[:1000],
                    "```",
                    "",
                ]

            if val.post_patch_crash.stdout:
                lines += [
                    "### Post-patch Run Output",
                    "```",
                    val.post_patch_crash.stdout[:500],
                    "```",
                    "",
                ]

            if val.regression.stdout:
                lines += [
                    "### Regression Test Output",
                    "```",
                    val.regression.stdout[:1000],
                    "```",
                    "",
                ]
        else:
            lines += ["*Validation was not run.*", ""]

        lines += [
            "---",
            "",
            "## 5. Pipeline Metrics",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Pipeline Status | {report.status.value} |",
            f"| Wall-Clock Time | {report.wall_clock_seconds:.1f}s |",
            f"| Total LLM Calls | {report.total_llm_calls} |",
            f"| Patch Retry Count | {report.retry_count} |",
            f"| Peak Memory | {report.peak_memory_mb:.0f} MB |",
        ]

        for stage, secs in report.stage_timings.items():
            lines.append(f"| {stage} | {secs:.2f}s |")

        if report.error_message:
            lines += [
                "",
                "---",
                "",
                "## ⚠️ Error / Could Not Patch",
                "",
                f"```",
                report.error_message,
                "```",
            ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTML render
    # ------------------------------------------------------------------

    def _render_html(self, report, markdown_content: str) -> str:
        """Generate HTML from the template, embedding the markdown content."""
        template_path = os.path.join(TEMPLATE_DIR, "report.html.j2")

        if os.path.exists(template_path):
            try:
                from jinja2 import Environment, FileSystemLoader
                env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
                tmpl = env.get_template("report.html.j2")
                return tmpl.render(report=report, markdown=markdown_content)
            except ImportError:
                pass

        # Fallback: convert markdown to HTML inline (basic)
        return self._minimal_html(report, markdown_content)

    def _minimal_html(self, report, markdown_content: str) -> str:
        """Minimal HTML wrapper around the markdown content."""
        status_color = "#22c55e" if report.is_proven_fix() else "#ef4444"
        status_text = "PROVEN FIX" if report.is_proven_fix() else "COULD NOT PATCH"

        # Very basic markdown → HTML (enough for report readability)
        import re
        html_body = markdown_content
        html_body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)
        html_body = re.sub(r'`([^`]+)`', r'<code>\1</code>', html_body)
        html_body = re.sub(r'```diff\n(.*?)```', r'<pre class="diff">\1</pre>', html_body, flags=re.DOTALL)
        html_body = re.sub(r'```c\n(.*?)```', r'<pre class="c-code">\1</pre>', html_body, flags=re.DOTALL)
        html_body = re.sub(r'```\n?(.*?)```', r'<pre>\1</pre>', html_body, flags=re.DOTALL)
        html_body = re.sub(r'^---$', r'<hr>', html_body, flags=re.MULTILINE)
        html_body = re.sub(r'^\| (.+) \|$', r'<tr><td>\1</td></tr>', html_body, flags=re.MULTILINE)
        html_body = html_body.replace('\n\n', '</p><p>')

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Kavach — Finding Report: {report.crash.target_name}</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 24px; color: #1a1a2e; background: #f8fafc; }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #3b82f6; padding-bottom: 12px; }}
  h2 {{ color: #1e40af; margin-top: 2rem; }}
  h3 {{ color: #374151; }}
  .status-badge {{ display: inline-block; background: {status_color}; color: white; padding: 6px 18px; border-radius: 20px; font-weight: bold; font-size: 1.1rem; margin: 12px 0; }}
  pre {{ background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.875rem; line-height: 1.5; }}
  pre.diff {{ background: #0d1117; }}
  pre.diff .add {{ color: #22c55e; }}
  pre.diff .del {{ color: #ef4444; }}
  code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 0.875rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  td, th {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
  th {{ background: #1e40af; color: white; }}
  tr:nth-child(even) {{ background: #f1f5f9; }}
  hr {{ border: none; border-top: 2px solid #e2e8f0; margin: 2rem 0; }}
  .metric-box {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 8px 0; }}
  .header-banner {{ background: linear-gradient(135deg, #1e40af 0%, #0f172a 100%); color: white; padding: 24px; border-radius: 12px; margin-bottom: 2rem; }}
  .header-banner h1 {{ color: white; border-bottom: 2px solid rgba(255,255,255,0.3); }}
</style>
</head>
<body>
<div class="header-banner">
  <h1>🛡️ AI Kavach — Cyber-Reasoning System</h1>
  <div class="status-badge">{status_text}</div>
  <p>Target: <strong>{report.crash.target_name}</strong> &nbsp;|&nbsp;
     CWE: <strong>{report.crash.cwe}</strong> — {report.crash.cwe_name} &nbsp;|&nbsp;
     Severity: <strong>{report.crash.severity.value}</strong></p>
</div>
<p>{html_body}</p>
</body>
</html>"""
