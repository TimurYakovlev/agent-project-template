import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from check import REQUIRED, SKILLS, check, scan_text

TEMPLATE_PROFILE = {
    "schema_version": 1, "status": "template", "name": "", "purpose": "",
    "audience": "", "language": "ru", "areas": [], "sources": [], "checks": [],
    "review": {"independent_for": []}, "integrations": [],
}


class TemplateChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "fixture"
        # Fixtures stay independent of the user's configured project and private files.
        for name in REQUIRED:
            self.write(name, "# Fixture\n")
        self.write("project.json", json.dumps(TEMPLATE_PROFILE))
        self.write("work/tasks.json", "[]\n")
        self.write("CLAUDE.md", "@AGENTS.md\n")
        self.write(".gitignore", ".env\n.local/\n")
        self.write("docs/workflows/content.md", "# Content fixture\n")
        for skill, workflow in SKILLS.items():
            entry = (f'---\nname: {skill}\ndescription: "Fixture skill"\n---\n'
                     f'AGENTS.md [workflow](../../../{workflow})\n')
            for host in (".agents", ".claude"):
                self.write(f"{host}/skills/{skill}/SKILL.md", entry)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def profile(self, **updates):
        path = self.root / "project.json"
        profile = json.loads(path.read_text(encoding="utf-8"))
        profile.update(updates)
        self.write("project.json", json.dumps(profile))
        return profile

    def test_clean_template(self):
        self.assertEqual([], check(self.root))

    def test_configured_profile_and_real_route(self):
        self.profile(status="configured", name="Demo", purpose="Example",
                     audience="Team", areas=[{"id": "writing", "instruction": "AGENTS.md",
                     "workflow": "docs/workflows/content.md", "checks": ["Read final"]}],
                     review={"independent_for": ["writing"]})
        self.assertEqual([], check(self.root))

    def test_bad_route_and_unknown_review_are_rejected(self):
        self.profile(areas=[{"id": "work", "instruction": "../outside.md",
                     "workflow": "missing.md", "checks": []}],
                     review={"independent_for": ["unknown"]})
        findings = "\n".join(check(self.root))
        self.assertIn("invalid area instruction", findings)
        self.assertIn("invalid area workflow", findings)
        self.assertIn("unknown area", findings)

    def test_incomplete_configured_profile_fails(self):
        self.profile(status="configured")
        self.assertTrue(any("is required" in x for x in check(self.root)))
        self.assertTrue(any("at least one area" in x for x in check(self.root)))

    def test_broken_link_and_invalid_json(self):
        self.write("docs/extra.md", "[missing](gone.md)\n")
        self.write("work/tasks.json", "{")
        findings = "\n".join(check(self.root))
        self.assertIn("broken or outside-root", findings)
        self.assertIn("invalid JSON", findings)

    def test_bad_profile_types_do_not_crash(self):
        for field, value in [("areas", None), ("review", None), ("sources", None),
                             ("checks", 8), ("integrations", "wrong")]:
            self.write("project.json", json.dumps(TEMPLATE_PROFILE))
            self.profile(**{field: value})
            self.assertTrue(check(self.root), field)

    def test_duplicate_tasks_are_rejected(self):
        task = {"id": "one", "title": "Example", "status": "todo", "source": "request"}
        self.write("work/tasks.json", json.dumps([task, copy.copy(task)]))
        self.assertTrue(any("duplicate task" in x for x in check(self.root)))

    def test_source_url_requires_hostname(self):
        self.profile(sources=["https:"])
        self.assertTrue(any("source must be" in x for x in check(self.root)))

    def test_damaged_skill_and_import_return_findings(self):
        (self.root / ".agents/skills/project-setup/SKILL.md").write_bytes(bytes([255]))
        (self.root / "CLAUDE.md").write_bytes(bytes([255]))
        findings = "\n".join(check(self.root))
        self.assertIn("unreadable skill entry", findings)
        self.assertIn("unreadable shared rules import", findings)

    def test_host_divergence_is_rejected(self):
        path = self.root / ".claude/skills/project-setup/SKILL.md"
        self.write(str(path.relative_to(self.root)), path.read_text(encoding="utf-8") + "\nExtra\n")
        self.assertTrue(any("host entries differ" in x for x in check(self.root)))

    def test_common_secret_types_are_redacted(self):
        tokens = [
            "gh" + "p_" + "a" * 36,
            "sk" + "-proj-" + "a" * 40,
            "AK" + "IA" + "A" * 16,
            "-----BEGIN " + "PRIVATE KEY-----",
            "https://" + "name:secret" + "@example.com/",
            'api_key="' + "a" * 32 + '"',
            "123456789:" + "a" * 35,
        ]
        for token in tokens:
            with self.subTest(kind=token[:3]):
                findings = scan_text("example.txt", token)
                self.assertTrue(findings)
                self.assertNotIn(token, "\n".join(findings))

    def test_secret_filename_and_personal_path(self):
        self.write(".env", "harmless")
        self.write("notes.md", "C:" + "/Users/" + "example/file.md")
        findings = "\n".join(check(self.root))
        self.assertIn("private configuration", findings)
        self.assertIn("personal home path", findings)
        self.assertNotIn("harmless", findings)

    @unittest.skipUnless(shutil.which("git"), "Git required")
    def test_tracked_ignored_secret_is_not_skipped(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, capture_output=True)
        self.write(".env", "not-a-real-key")
        subprocess.run(["git", "-C", str(self.root), "add", "-f", ".env"], check=True, capture_output=True)
        self.assertTrue(any(".env: private" in x for x in check(self.root)))

    def test_outside_link_is_rejected_without_following(self):
        outside = Path(self.temp.name) / "outside.md"
        outside.write_text("Outside", encoding="utf-8")
        self.write("docs/extra.md", "[outside](../../outside.md)\n")
        self.assertTrue(any("outside-root" in x for x in check(self.root)))


if __name__ == "__main__":
    unittest.main()
