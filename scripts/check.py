"""Local structure and candidate-file checks; no network or command execution from config."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote, urlsplit

REQUIRED = (
    "AGENTS.md", "CLAUDE.md", "PROJECT.md", "NOW.md", "project.json",
    "README.md", "LICENSE", "SECURITY.md", ".gitignore", "work/tasks.json",
    "docs/onboarding.md", "docs/intake.md", "docs/workflows/task.md",
    "docs/roles/executor.md", "docs/roles/reviewer.md",
)
SKILLS = {"project-setup": "docs/onboarding.md", "project-task": "docs/workflows/task.md"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")
SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("provider-key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,}\b")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("bot-token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
    ("credential-url", re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")),
    ("secret-assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\b["']?\s*[:=]\s*["']([A-Za-z0-9_./+=-]{16,})["']"""
    )),
)
PLACEHOLDERS = {"replace_me", "change_me", "your_key_here", "example", "placeholder"}


def local_file(root, value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    candidate = root / value
    return not Path(value).is_absolute() and candidate.resolve().is_relative_to(root) and candidate.is_file()


def candidates(root):
    """Git includes tracked ignored files; errors in an existing checkout fail closed."""
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True, check=True,
        )
        return sorted(set(result.stdout.decode("utf-8").rstrip("\0").split("\0")) - {""})
    found = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        # Do not follow directory links into somebody else's files.
        links = [name for name in dirs if (Path(directory) / name).is_symlink()]
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and name not in links]
        found.extend((Path(directory) / name).relative_to(root).as_posix() for name in files + links)
    return sorted(found)


def scan_text(name, text):
    issues = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                if label == "secret-assignment" and any(p in match.group(1).lower() for p in PLACEHOLDERS):
                    continue
                issues.append(f"{name}:{line_number}: possible {label} (value hidden)")
        if re.search(r"(?:[A-Za-z]:[\\/]+Users[\\/]|/Users/|/home/)[A-Za-z0-9_.-]+", line):
            issues.append(f"{name}:{line_number}: personal home path")
    return issues


def check(root):
    root = Path(root).resolve()
    issues = [f"missing required file: {name}" for name in REQUIRED if not local_file(root, name)]
    try:
        names = candidates(root)
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        return issues + ["cannot enumerate Git candidates; scan incomplete"]

    for name in names:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            issues.append(f"{name}: linked or outside-root file")
            continue
        if not path.is_file():
            issues.append(f"{name}: candidate is not a regular file")
            continue
        if (path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")
                or name in {".mcp.json", ".codex/config.toml", ".claude/settings.local.json"}
                or any(part in {".local", ".aws", ".ssh"} for part in path.relative_to(root).parts)
                or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".session", ".db", ".sqlite", ".sqlite3"}):
            issues.append(f"{name}: private configuration or data file")
            continue
        if path.stat().st_size > 5_000_000:
            issues.append(f"{name}: too large to scan; review required")
            continue
        try:
            raw = path.read_bytes()
            if b"\0" in raw:
                continue  # Binary contents require manual review; filenames are still checked.
            text = raw.decode("utf-8-sig")
        except (OSError, UnicodeError):
            issues.append(f"{name}: cannot read as UTF-8; review required")
            continue
        issues.extend(scan_text(name, text))
        if path.suffix == ".md":
            for target in LINK.findall(text):
                if target.startswith("#") or urlsplit(target).scheme:
                    continue
                relative = unquote(target.split("#", 1)[0]).strip("<>")
                destination = path.parent / relative
                if not destination.resolve().is_relative_to(root) or not destination.exists():
                    issues.append(f"{name}: broken or outside-root link: {target}")
        if path.suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError:
                issues.append(f"{name}: invalid JSON")

    try:
        profile = json.loads((root / "project.json").read_text(encoding="utf-8-sig"))
        if not isinstance(profile, dict):
            raise ValueError
        if profile.get("schema_version") != 1 or profile.get("status") not in {"template", "configured"}:
            issues.append("project.json: invalid version or status")
        for field in ("name", "purpose", "audience", "language"):
            if not isinstance(profile.get(field), str):
                issues.append(f"project.json: {field} must be text")
            elif (profile.get("status") == "configured" or field == "language") and not profile[field].strip():
                issues.append(f"project.json: {field} is required")
        areas = profile.get("areas")
        if not isinstance(areas, list):
            raise ValueError
        ids = []
        for area in areas:
            if not isinstance(area, dict) or not re.fullmatch(r"[a-z][a-z0-9-]*", str(area.get("id", ""))):
                issues.append("project.json: area requires a simple unique id")
                continue
            ids.append(area["id"])
            for field in ("instruction", "workflow"):
                if not local_file(root, area.get(field)):
                    issues.append(f"project.json: invalid area {field}: {area['id']}")
            if not isinstance(area.get("checks"), list) or not all(isinstance(x, str) and x.strip() for x in area["checks"]):
                issues.append(f"project.json: invalid checks: {area['id']}")
        if len(ids) != len(set(ids)):
            issues.append("project.json: duplicate area id")
        if profile.get("status") == "configured" and not ids:
            issues.append("project.json: configured project requires at least one area")
        for field in ("sources", "checks", "integrations"):
            if not isinstance(profile.get(field), list):
                issues.append(f"project.json: {field} must be a list")
        for source in profile.get("sources", []):
            parsed = urlsplit(source) if isinstance(source, str) else None
            if not isinstance(source, str) or not ((parsed.scheme in {"https", "http"} and parsed.hostname) or local_file(root, source)):
                issues.append("project.json: source must be an existing local file or HTTP URL")
        if not all(isinstance(x, str) and x.strip() for x in profile.get("checks", [])):
            issues.append("project.json: checks must contain nonempty text")
        for integration in profile.get("integrations", []):
            if (not isinstance(integration, dict) or not all(isinstance(integration.get(f), str) and integration[f].strip() for f in ("service", "purpose"))
                    or integration.get("status") not in {"not-connected", "configured", "verified"}):
                issues.append("project.json: invalid integration description")
        review = profile.get("review", {}).get("independent_for")
        if not isinstance(review, list) or any(x not in ids for x in review):
            issues.append("project.json: review refers to unknown area")
    except (OSError, ValueError, TypeError, AttributeError):
        issues.append("project.json: unreadable or invalid profile")

    try:
        tasks = json.loads((root / "work/tasks.json").read_text(encoding="utf-8-sig"))
        if not isinstance(tasks, list):
            raise ValueError
        task_ids = []
        for task in tasks:
            if (not isinstance(task, dict) or not all(isinstance(task.get(f), str) and task[f].strip() for f in ("id", "title", "source"))
                    or task.get("status") not in {"todo", "doing", "blocked", "done"}):
                issues.append("work/tasks.json: invalid task")
            else:
                task_ids.append(task["id"])
        if len(task_ids) != len(set(task_ids)):
            issues.append("work/tasks.json: duplicate task id")
    except (OSError, ValueError, TypeError):
        issues.append("work/tasks.json: unreadable or invalid task list")

    for skill, workflow in SKILLS.items():
        copies = []
        for host in (".agents", ".claude"):
            name = f"{host}/skills/{skill}/SKILL.md"
            path = root / name
            if not local_file(root, name):
                issues.append(f"missing skill entry: {name}")
                continue
            try:
                text = path.read_text(encoding="utf-8-sig")
            except (OSError, UnicodeError):
                issues.append(f"{name}: unreadable skill entry")
                continue
            header = text.split("---", 2)
            if len(header) != 3 or header[0] or not re.search(rf"(?m)^name: {re.escape(skill)}$", header[1]) or not re.search(r'(?m)^description: "[^"\n]+"$', header[1]):
                issues.append(f"{name}: invalid skill frontmatter")
            if f"../../../{workflow}" not in text or "AGENTS.md" not in text:
                issues.append(f"{name}: wrong shared workflow")
            copies.append(text)
        if len(copies) == 2 and copies[0] != copies[1]:
            issues.append(f"{skill}: host entries differ")
    claude = root / "CLAUDE.md"
    if claude.is_file():
        try:
            if not re.search(r"(?m)^@AGENTS\.md\s*$", claude.read_text(encoding="utf-8-sig")):
                issues.append("CLAUDE.md: missing shared rules import")
        except (OSError, UnicodeError):
            issues.append("CLAUDE.md: unreadable shared rules import")
    return sorted(set(issues))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    findings = check(args.root)
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"{'FAIL' if findings else 'PASS'}: structure, local links, JSON, host entries and candidate-file scan")
    raise SystemExit(bool(findings))
