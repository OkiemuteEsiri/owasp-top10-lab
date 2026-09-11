import json
import tempfile
import unittest
from pathlib import Path

from src.analyzer import classify, deterministic_id, load_assessment, portfolio_metrics, prioritize, score_finding
from src.models import Assessment, Finding
from src.report import render_markdown


BASE = {
    "finding_id": "T-1",
    "title": "Synthetic finding",
    "category": "A01:2021-Broken Access Control",
    "severity": "high",
    "affected_component": "GET /lab/resource",
    "evidence": "Synthetic evidence",
    "remediation": "Apply server-side authorization",
    "validation": "Verify denied access for unauthorized role"
}


class AssessmentTests(unittest.TestCase):
    def finding(self, **overrides):
        raw = dict(BASE)
        raw.update(overrides)
        return Finding.from_dict(raw)

    def test_high_severity_scores_high(self):
        self.assertGreaterEqual(score_finding(self.finding()), 55)

    def test_context_increases_risk(self):
        base = self.finding()
        exposed = self.finding(internet_exposed=True, authentication_required=False, sensitive_data=True)
        self.assertGreater(score_finding(exposed), score_finding(base))

    def test_score_is_bounded(self):
        finding = self.finding(severity="critical", internet_exposed=True, authentication_required=False, sensitive_data=True)
        self.assertEqual(score_finding(finding), 100)

    def test_remediated_reduces_score(self):
        open_finding = self.finding()
        fixed = self.finding(status="remediated")
        self.assertLess(score_finding(fixed), score_finding(open_finding))

    def test_classification_boundaries(self):
        self.assertEqual(classify(80), "critical")
        self.assertEqual(classify(60), "high")
        self.assertEqual(classify(35), "medium")
        self.assertEqual(classify(1), "low")
        self.assertEqual(classify(0), "informational")

    def test_deterministic_ids_are_stable(self):
        finding = self.finding()
        self.assertEqual(deterministic_id(finding), deterministic_id(finding))

    def test_duplicate_finding_ids_fail_closed(self):
        raw = {"application": "Lab", "environment": "lab", "authorized": True, "findings": [BASE, BASE]}
        with self.assertRaises(ValueError):
            Assessment.from_dict(raw)

    def test_unauthorized_assessment_fails_closed(self):
        raw = {"application": "Lab", "environment": "lab", "authorized": False, "findings": []}
        with self.assertRaises(ValueError):
            Assessment.from_dict(raw)

    def test_production_environment_is_rejected(self):
        raw = {"application": "Lab", "environment": "production", "authorized": True, "findings": []}
        with self.assertRaises(ValueError):
            Assessment.from_dict(raw)

    def test_unknown_owasp_category_is_rejected(self):
        with self.assertRaises(ValueError):
            self.finding(category="A99:2021-Unknown")

    def test_prioritize_orders_highest_first(self):
        lower = self.finding(finding_id="L", severity="low")
        higher = self.finding(finding_id="H", severity="critical")
        result = prioritize([lower, higher])
        self.assertEqual(result[0].finding.finding_id, "H")

    def test_metrics_and_report(self):
        assessment = Assessment("Lab", "lab", True, (self.finding(),))
        metrics = portfolio_metrics(assessment.findings)
        self.assertEqual(metrics["total_findings"], 1)
        report = render_markdown(assessment)
        self.assertIn("Web Security Assessment", report)
        self.assertIn("Synthetic finding", report)

    def test_loader_accepts_valid_json(self):
        raw = {"application": "Lab", "environment": "local", "authorized": True, "findings": [BASE]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "assessment.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            assessment = load_assessment(path)
        self.assertEqual(assessment.application, "Lab")


if __name__ == "__main__":
    unittest.main()
