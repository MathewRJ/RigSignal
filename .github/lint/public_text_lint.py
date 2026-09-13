#!/usr/bin/env python3
"""Refuse public text that carries operator-environment detail.

Commit messages and annotated tag messages in this repository are permanent and
world-readable. This checks them against `public-text-rules.json`, which is the
single source of truth: this file applies rules, it does not define them.

Six behaviours here exist because an earlier implementation of the same idea got
them wrong, and every one of those bugs survived a green test suite that
exercised the rule function and nothing around it:

  * the trailer exemption blanks only the ADDRESS of a well-formed trailer in the
    FINAL paragraph, never a whole line, and never a key like `Author:`;
  * messages are read ONE COMMIT AT A TIME and the count is asserted, because a
    single separator byte inside a message silently truncates a batched parse;
  * annotated TAG messages are read separately, because `git log` on a tag peels
    to the commit and never sees the tag body;
  * documentation address ranges are carved out ONCE, centrally, so two rules
    cannot reach opposite verdicts on the same address;
  * EVERY match is reported, not the first, so one push does not become four
    red runs;
  * `--selftest` seeds a known leak and fails if the checker does not catch it,
    so removing the control is itself detectable.

Exit status: 0 clean, 1 findings, 2 usage or internal error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RULES_PATH = Path(__file__).with_name("public-text-rules.json")


@dataclass(frozen=True)
class Finding:
    source: str
    rule_id: str
    why: str
    line_no: int
    excerpt: str


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed with {result.returncode}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def load_rules(path: Path = RULES_PATH) -> dict:
    with path.open(encoding="utf-8") as handle:
        rules = json.load(handle)
    for rule in rules["rules"]:
        rule["compiled"] = re.compile(rule["pattern"])
    return rules


def strip_trailer_addresses(message: str, keys: list[str]) -> str:
    """Blank the ADDRESS of well-formed trailers in the final paragraph only.

    Everything else about the line is preserved, so a rule can still fire on the
    rest of it. Scoped to the final paragraph because that is where git itself
    looks for trailers -- a `Co-Authored-By:` written mid-message is prose, and
    prose does not get an exemption.
    """
    paragraphs = message.split("\n\n")
    if not paragraphs:
        return message
    key_alternation = "|".join(re.escape(key) for key in keys)
    trailer = re.compile(
        rf"^(\s*(?:{key_alternation})\s*:\s*[^<>\n]*<)[^<>\n]+(>\s*)$",
        re.IGNORECASE | re.MULTILINE,
    )
    paragraphs[-1] = trailer.sub(r"\1\2", paragraphs[-1])
    return "\n\n".join(paragraphs)


def mask_documentation_addresses(message: str, prefixes: list[str]) -> str:
    """Replace reserved documentation addresses with a neutral placeholder.

    Done ONCE here rather than inside each rule. When an earlier implementation
    carved these out of one rule and not another, the same address drew opposite
    verdicts from two rules in the repository the carve-out existed to protect.
    """
    for prefix in prefixes:
        message = message.replace(prefix, "reserved-example.")
    return message


def scan(message: str, source: str, rules: dict) -> list[Finding]:
    cleaned = strip_trailer_addresses(message, rules["trailer_exemption"]["keys"])
    cleaned = mask_documentation_addresses(
        cleaned, rules["documentation_addresses"]["prefixes"]
    )

    findings: list[Finding] = []
    for rule in rules["rules"]:
        # finditer, not search: report every occurrence. One message with four
        # private addresses should cost one fix, not four red runs.
        for match in rule["compiled"].finditer(cleaned):
            line_no = cleaned.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    source=source,
                    rule_id=rule["id"],
                    why=rule["why"],
                    line_no=line_no,
                    # The finding names the RULE, never the matched value: echoing
                    # it back into CI logs republishes exactly what was withheld.
                    excerpt=f"<{len(match.group(0))} characters matched>",
                )
            )
    return _apply_precedence(findings, rules)


def _apply_precedence(findings: list[Finding], rules: dict) -> list[Finding]:
    """One problem, one finding, per line.

    A session-trailer line also matches the URL and bare-id rules. Reporting all
    three trains a reader to skim, which is how the fourth, unrelated finding
    below them gets missed. Suppression is per LINE, so a genuinely separate
    occurrence elsewhere in the message still reports.
    """
    precedence = rules.get("finding_precedence", {}).get("suppressed_by", {})
    if not precedence:
        return findings
    dominant_lines: dict[str, set[int]] = {
        dominant: {f.line_no for f in findings if f.rule_id == dominant}
        for dominant in precedence
    }
    kept: list[Finding] = []
    for finding in findings:
        suppressed = any(
            finding.rule_id in subordinates
            and finding.line_no in dominant_lines.get(dominant, set())
            for dominant, subordinates in precedence.items()
        )
        if not suppressed:
            kept.append(finding)
    return kept


def commit_messages(base: str, head: str) -> list[tuple[str, str]]:
    """Read each commit message individually, and assert the count.

    A batched read with separator bytes is unsafe: a message containing the
    separator splits into a bogus record with an empty body, which lints clean.
    The only tell is a count that disagrees with reality, so the count is checked
    rather than trusted.
    """
    rev_range = f"{base}..{head}"
    expected = int(_git("rev-list", "--count", rev_range).strip() or "0")
    shas = [line for line in _git("rev-list", rev_range).splitlines() if line]
    if len(shas) != expected:
        raise RuntimeError(
            f"enumerated {len(shas)} commits but rev-list counted {expected} "
            f"for {rev_range}; refusing to lint a set I cannot enumerate"
        )
    return [(sha, _git("log", "-1", "--format=%B", sha)) for sha in shas]


def tag_messages() -> list[tuple[str, str]]:
    """Annotated tag bodies, which `git log` never reads.

    `git log <tag>` peels to the tagged commit, so a tag placed on an
    already-published commit yields an empty range and reports clean while its
    own message ships anything at all.
    """
    names = [
        line.strip()
        for line in _git(
            "for-each-ref", "--format=%(refname:short)", "refs/tags/*"
        ).splitlines()
        if line.strip()
    ]
    # ONE TAG AT A TIME, for the same reason commits are read one at a time.
    # The first version of this function batched them with a separator byte and
    # split on it -- reintroducing, in the tag path, the exact defect the commit
    # path was written to avoid. A repair inherits the defect one axis over.
    messages: list[tuple[str, str]] = []
    for name in names:
        body = _git("for-each-ref", "--format=%(contents)", f"refs/tags/{name}")
        messages.append((f"tag {name}", body))
    if len(messages) != len(names):
        raise RuntimeError(
            f"enumerated {len(names)} tags but read {len(messages)} messages"
        )
    return messages


SELFTEST_CASES = [
    ("Claude-Session: https://claude.ai/code/session_abc", "session-trailer"),
    ("see https://claude.ai/code/abcdef123456", "session-url"),
    ("ref session_0123456789abcdefghijklmn", "session-id"),
    ("host at 192.168.1.10 was unreachable", "private-ipv4"),
    ("moved /home/someone/project/file.rs", "absolute-home-path"),
    ("built in ~/coding/thing", "tilde-checkout-path"),
    ("removed worktrees/scratch-1", "worktree-path"),
    ("ssh user@10.0.0.5 to check", "user-at-ip-literal"),
    ("nic 0a:1b:2c:3d:4e:5f flapped", "mac-address"),
    ("addr fe80::1c2d:3e4f:5a6b:7c8d on the link", "private-ipv6"),
    ("addr fd12:3456:789a::1 assigned", "private-ipv6"),
    ("wrote /root/config.toml", "absolute-home-path"),
    ("built in $HOME/coding/thing", "tilde-checkout-path"),
    ("removed worktree/scratch", "worktree-path"),
    # The trap that made an earlier implementation exempt everything: a key that
    # LOOKS like a trailer but is not in the closed set, and is not a trailer at
    # all in the subject position.
    ("Author: someone@10.0.0.5", "private-ipv4"),
    ("cc: ran on 192.168.1.1", "private-ipv4"),
    # A well-formed trailer key, but NOT in the final paragraph, so not a trailer.
    ("Co-Authored-By: N <n@10.0.0.5>\n\nbody text", "private-ipv4"),
]

SELFTEST_CLEAN = [
    "fix(shipper): make the outermost error layer static\n\n"
    "Co-Authored-By: Someone <someone@example.com>\n",
    "docs: cite the reserved example address 192.0.2.254 in a doc comment\n",
    "test: cover the 2001:db8::1 documentation prefix\n",
]


def selftest(rules: dict) -> int:
    """Prove the control is ARMED, not merely that it returns a value.

    A suite that asserts the checker's output cannot see the control being
    removed: an earlier implementation stayed green when its hook's final exit
    was changed to 0. So this asserts both directions -- every seeded leak is
    caught, and every clean message passes -- and the workflow runs it as a
    separate step whose failure fails the job.
    """
    failures = 0
    for text, expected_rule in SELFTEST_CASES:
        found = {f.rule_id for f in scan(text, "selftest", rules)}
        if expected_rule not in found:
            print(
                f"SELFTEST FAIL: seeded leak for rule '{expected_rule}' was NOT "
                f"caught (rules that fired: {sorted(found) or 'none'})"
            )
            failures += 1
    for text in SELFTEST_CLEAN:
        found = [f.rule_id for f in scan(text, "selftest", rules)]
        if found:
            print(
                f"SELFTEST FAIL: a message that must pass was rejected by "
                f"{sorted(set(found))}"
            )
            failures += 1
    if failures:
        print(f"public_text_lint selftest: {failures} failure(s)")
        return 1
    print(
        f"public_text_lint selftest: {len(SELFTEST_CASES)} seeded leaks caught, "
        f"{len(SELFTEST_CLEAN)} clean messages passed"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="exclusive lower bound of the commit range")
    parser.add_argument("--head", default="HEAD", help="upper bound of the range")
    parser.add_argument(
        "--tags", action="store_true", help="also scan annotated tag messages"
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="verify the checker catches seeded leaks and passes clean messages",
    )
    args = parser.parse_args()

    try:
        rules = load_rules()
    except Exception as error:  # noqa: BLE001 - a broken rules file must be loud
        print(f"public_text_lint: cannot load rules: {error}")
        return 2

    if args.selftest:
        return selftest(rules)

    if not args.base and not args.tags:
        print(
            "public_text_lint: --base is required unless --selftest or --tags "
            "is given"
        )
        return 2

    try:
        subjects = commit_messages(args.base, args.head) if args.base else []
        if args.tags:
            subjects += tag_messages()
    except RuntimeError as error:
        print(f"public_text_lint: {error}")
        return 2

    findings: list[Finding] = []
    for source, message in subjects:
        findings.extend(scan(message, source, rules))

    print(f"public_text_lint: scanned {len(subjects)} message(s)")
    if not findings:
        print("public_text_lint: clean")
        return 0

    print(f"public_text_lint: {len(findings)} finding(s)\n")
    for finding in findings:
        print(f"  {finding.source}  line {finding.line_no}")
        print(f"    {finding.rule_id}: {finding.why}")
        print(f"    {finding.excerpt}\n")
    print(
        "Rewrite the message(s). This repository is public and its history is\n"
        "permanent. The matched text is deliberately not echoed above.\n"
        "\n"
        "NOT COVERED by this job, stated so a pass is not read as a guarantee:\n"
        "organisation-specific hostnames and internal identifier prefixes. Those\n"
        "cannot be checked here without publishing them in this repository, so\n"
        "they belong in private tooling."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
