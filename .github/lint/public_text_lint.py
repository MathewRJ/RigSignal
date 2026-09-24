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
import copy
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
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

    def required(obj: dict, key: str, kind: type, location: str):
        if not isinstance(obj, dict) or key not in obj or not isinstance(obj[key], kind):
            raise ValueError(f"invalid rules: {location}.{key} must be {kind.__name__}")
        return obj[key]

    if not isinstance(rules, dict):
        raise ValueError("invalid rules: root must be object")
    required(rules, "version", int, "root")
    prefixes = required(required(rules, "documentation_addresses", dict, "root"), "prefixes", list, "documentation_addresses")
    keys = required(required(rules, "trailer_exemption", dict, "root"), "keys", list, "trailer_exemption")
    entries = required(rules, "rules", list, "root")
    tokens = required(required(rules, "template_allowlist", dict, "root"), "tokens", list, "template_allowlist")
    precedence = required(required(rules, "finding_precedence", dict, "root"), "suppressed_by", dict, "finding_precedence")
    for location, items in (("documentation_addresses.prefixes", prefixes), ("trailer_exemption.keys", keys), ("template_allowlist.tokens", tokens)):
        if not all(isinstance(item, str) and item for item in items):
            raise ValueError(f"invalid rules: {location} must contain strings")
    for dominant, subordinates in precedence.items():
        if not isinstance(dominant, str) or not isinstance(subordinates, list) or not all(isinstance(item, str) for item in subordinates):
            raise ValueError("invalid rules: finding_precedence.suppressed_by must map strings to string lists")
    for index, rule in enumerate(entries):
        for key in ("id", "pattern", "why", "severity"):
            required(rule, key, str, f"rules[{index}]")
    for rule in rules["rules"]:
        rule["compiled"] = re.compile(rule["pattern"])
    rules["documentation_networks"] = documentation_networks(prefixes)
    return rules


def strip_trailer_addresses(message: str, keys: list[str]) -> str:
    """Blank the ADDRESS of well-formed trailers in the final paragraph only.

    Everything else about the line is preserved, so a rule can still fire on the
    rest of it. Scoped to the final paragraph because that is where git itself
    looks for trailers -- a `Co-Authored-By:` written mid-message is prose, and
    prose does not get an exemption.
    """
    paragraphs = message.split("\n\n")
    # Trailing blank paragraphs: git preserves a message ending "...\n\n", which
    # makes paragraphs[-1] the EMPTY string and leaves the real trailer one
    # element back, un-exempted. Found in review; it produced spurious findings
    # on a legitimate commit.
    last = len(paragraphs) - 1
    while last > 0 and not paragraphs[last].strip():
        last -= 1

    key_alternation = "|".join(re.escape(key) for key in keys)
    # The capture is an EMAIL GRAMMAR, not "anything between angle brackets".
    #
    # A review found the critical hole here: with `[^<>\n]+` the exemption blanked
    # whatever was placed inside the brackets, so
    #   Co-Authored-By: Name <a@b.com -- ssh admin@10.0.0.5 mac 0a:1b:2c:3d:4e:5f>
    # scanned completely clean. The accommodation the project's mandated trailer
    # requires had become a way to smuggle anything past every rule. Anything that
    # is not an address now falls through to normal scanning.
    trailer = re.compile(
        rf"^([ \t]*(?:{key_alternation})[ \t]*:[ \t]*[^<>\n]*<)"
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        r"(>[ \t]*)$",
        re.IGNORECASE | re.MULTILINE,
    )
    paragraphs[last] = trailer.sub(r"\1\2", paragraphs[last])
    return "\n\n".join(paragraphs)


def documentation_networks(prefixes: list[str]) -> list[ipaddress._BaseNetwork]:
    """Configured three-octet IPv4 and two-hextet IPv6 prefixes denote /24 and /32."""
    networks = []
    for prefix in prefixes:
        if re.fullmatch(r"(?:[0-9]{1,3}\.){3}", prefix):
            networks.append(ipaddress.ip_network(prefix + "0/24", strict=False))
        elif re.fullmatch(r"[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:", prefix):
            networks.append(ipaddress.ip_network(prefix + ":/32", strict=False))
        else:
            raise ValueError("invalid rules: documentation_addresses.prefixes contains an invalid prefix")
    return networks


ADDRESS_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_:.])[0-9A-Fa-f:.]+(?![A-Za-z0-9_])")


def mask_documentation_addresses(message: str, networks: list[ipaddress._BaseNetwork]) -> str:
    """Replace reserved documentation addresses with a neutral placeholder.

    Done ONCE here rather than inside each rule. When an earlier implementation
    carved these out of one rule and not another, the same address drew opposite
    verdicts from two rules in the repository the carve-out existed to protect.
    """
    # A candidate starts outside an address/word continuation. A trailing full
    # stop is prose punctuation; internal dots and colons remain in the token.
    # Parse the COMPLETE candidate, then replace it with same-width nonspace
    # text. Spaces could split a token and CREATE an allowlisted spelling.
    def mask(match: re.Match[str]) -> str:
        token = match.group().rstrip(".")
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            return match.group()
        if any(address in network for network in networks):
            return "x" * len(token) + match.group()[len(token):]
        return match.group()

    return ADDRESS_CANDIDATE.sub(mask, message)


def scan(message: str, source: str, rules: dict) -> list[Finding]:
    cleaned = strip_trailer_addresses(message, rules["trailer_exemption"]["keys"])
    cleaned = mask_documentation_addresses(
        cleaned, rules["documentation_networks"]
    )

    findings: list[Finding] = []
    for rule in rules["rules"]:
        # finditer, not search: report every occurrence. One message with four
        # private addresses should cost one fix, not four red runs.
        for match in rule["compiled"].finditer(cleaned):
            if rule["id"] == "private-ipv6":
                try:
                    address = ipaddress.IPv6Address(match.group())
                except ValueError:
                    continue
                if address not in ipaddress.ip_network("fc00::/7") and address not in ipaddress.ip_network("fe80::/10"):
                    continue
            if (
                rule["id"] == "tilde-checkout-path"
                and _whole_token(cleaned, match.start())
                in rules["template_allowlist"]["tokens"]
            ):
                # Exact whole-token equality exempts only this occurrence.
                # Unlisted punctuation, suffixes and quotes are not normalised.
                continue
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


def _whole_token(text: str, index: int) -> str:
    """Return the whitespace-delimited token verbatim, including punctuation."""
    start = index
    while start > 0 and not text[start - 1].isspace():
        start -= 1
    end = index
    while end < len(text) and not text[end].isspace():
        end += 1
    return text[start:end]


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


def tag_messages(ref: str | None = None) -> list[tuple[str, str]]:
    """Annotated tag bodies, which `git log` never reads.

    `git log <tag>` peels to the tagged commit, so a tag placed on an
    already-published commit yields an empty range and reports clean while its
    own message ships anything at all.
    """
    names = [
        line.strip()
        for line in _git(
            "for-each-ref", "--format=%(refname)", ref or "refs/tags/"
        ).splitlines()
        if line.strip()
    ]
    if ref and (not ref.startswith("refs/tags/") or names != [ref]):
        raise RuntimeError("pushed tag full ref is missing or invalid")
    # ONE TAG AT A TIME, for the same reason commits are read one at a time.
    # The first version of this function batched them with a separator byte and
    # split on it -- reintroducing, in the tag path, the exact defect the commit
    # path was written to avoid. A repair inherits the defect one axis over.
    messages: list[tuple[str, str]] = []
    lightweight = 0
    for name in names:
        kind = _git("cat-file", "-t", name).strip()
        if kind == "commit":
            print(f"public_text_lint: {name} is lightweight; it has no tag message")
            lightweight += 1
            continue
        if kind != "tag":
            raise RuntimeError(f"{name} is neither an annotated nor a lightweight tag")
        body = _git("for-each-ref", "--format=%(contents)", name)
        messages.append((f"tag {name}", body))
    if len(messages) + lightweight != len(names):
        raise RuntimeError(
            f"enumerated {len(names)} tags but could not account for every tag"
        )
    return messages


SELFTEST_CASES = [
    ("Claude-Session: https://claude.ai/code/session_abc", "session-trailer"),
    ("see https://claude.ai/code/abcdef123456", "session-url"),
    ("ref session_0123456789abcdefghijklmn", "session-id"),
    ("host at 192.168.1.10 was unreachable", "private-ipv4"),
    ("host 10.0.0.5.", "private-ipv4"),
    ("host 10.0.0.5,", "private-ipv4"),
    ("host 10.0.0.5;", "private-ipv4"),
    ("host (10.0.0.5)", "private-ipv4"),
    ("host 10.0.0.5", "private-ipv4"),
    ("moved /home/someone/project/file.rs", "absolute-home-path"),
    ("built in ~/coding/thing", "tilde-checkout-path"),
    ("removed worktrees/scratch-1", "worktree-path"),
    ("ssh user@10.0.0.5 to check", "user-at-ip-literal"),
    ("nic 0a:1b:2c:3d:4e:5f flapped", "mac-address"),
    ("nic 0a:1b:2c:3d:4e:5f.", "mac-address"),
    ("nic 0a:1b:2c:3d:4e:5f,", "mac-address"),
    ("nic 0a:1b:2c:3d:4e:5f;", "mac-address"),
    ("nic (0a:1b:2c:3d:4e:5f)", "mac-address"),
    ("nic 0a:1b:2c:3d:4e:5f", "mac-address"),
    ("addr fe80::1c2d:3e4f:5a6b:7c8d on the link", "private-ipv6"),
    ("addr fd12:3456:789a::1 assigned", "private-ipv6"),
    ("host fd12::", "private-ipv6"),
    ("host fe80::", "private-ipv6"),
    ("host fd12:2001:db8::1", "private-ipv6"),
    ("docs 2001:db8::1 and host fd12::", "private-ipv6"),
    ("probe ~/elastic/elastic-agent-*/),2001:db8::1", "tilde-checkout-path"),
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
    # THE CRITICAL CASE a review found: the trailer exemption blanked whatever sat
    # inside the brackets, so a well-formed key was a way to smuggle anything past
    # every rule. The capture is an email grammar now, and this must fire.
    (
        "subject\n\nCo-Authored-By: N <a@b.com -- ssh admin@10.0.0.5>",
        "private-ipv4",
    ),
    ("subject\n\nCo-Authored-By: N <a@b.com mac 0a:1b:2c:3d:4e:5f>", "mac-address"),
    # Notations the first rule set missed. The dash form is the Windows getmac
    # default, so it is the likely accidental paste rather than an attack.
    ("nic 0a-1b-2c-3d-4e-5f flapped", "mac-address"),
    ("nic 0a1b.2c3d.4e5f flapped", "mac-address"),
    ("built in ${HOME}/coding/thing", "tilde-checkout-path"),
    ("moved /home//someone/project/file.rs", "absolute-home-path"),
    # Absolute-home-path findings remain unaffected by template membership.
    ("moved /home/realuser/project* to storage", "absolute-home-path"),
    ("cleaned up /home/someone/.cache/thing-* before rebuilding", "absolute-home-path"),
    # The suppression found in review, paired with its no-glob control.
    ("cleaned ~/someone/backups/old-project-*", "tilde-checkout-path"),
    ("cleaned ~/someone/backups/old-project", "tilde-checkout-path"),
    # Synthetic and not allowlisted; the heuristic that exempted it is gone.
    ("fix: probe ~/vendor/product-*/bin for the tool", "tilde-checkout-path"),
    # Different tokens: no suffix, wildcard, punctuation or quote normalisation.
    ("probe ~/elastic/elastic-agent-*/someone", "tilde-checkout-path"),
    ("probe ~/elastic/elastic-agent-*/", "tilde-checkout-path"),
    ("probe ~/elastic/elastic-agent-*/),host", "tilde-checkout-path"),
    ("probe ~/elastic/elastic-agent-**/", "tilde-checkout-path"),
    ("probe ~/elastic/elastic-agent-*/).", "tilde-checkout-path"),
    ("probe ~/elastic/elastic-agent-*/)", "tilde-checkout-path"),
    ('probe "~/elastic/elastic-agent-*/),"', "tilde-checkout-path"),
    ("probe '~/elastic/elastic-agent-*/'", "tilde-checkout-path"),
    ("probe prefix~/elastic/elastic-agent-*/", "tilde-checkout-path"),
]

SELFTEST_CLEAN = [
    "fix(shipper): make the outermost error layer static\n\n"
    "Co-Authored-By: Someone <someone@example.com>\n",
    "docs: cite the reserved example address 192.0.2.254 in a doc comment\n",
    "test: cover the 2001:db8::1 documentation prefix\n",
    # Historical token at 1d5ac56, including punctuation; the clean entry does
    # not cover this distinct spelling under exact whole-token equality.
    "(env -> PATH -> /opt/Elastic/Agent -> ~/elastic/elastic-agent-*/), registry",
    # A message ending in a blank line leaves paragraphs[-1] empty; the real
    # trailer is one element back and must still be exempted.
    "fix: something\n\nCo-Authored-By: Someone <someone@example.com>\n\n",
    "docs: use user@[2001:DB8::1] as the reserved example",
    "docs: 192.0.2.254, 2001:0DB8::1; 233.252.0.1",
    "host 10.0.0.5.6 is an invalid longer token",
    "nic 0a:1b:2c:3d:4e:5f:60 is seven octets",
    "nic 0a-1b-2c-3d-4e-5f-60 is seven octets",
    "host fd12::: is an invalid longer token",
    "host fd12::gg is an invalid longer token",
    "docs 2001:db8::1suffix is not a complete address",
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
    if rules["template_allowlist"]["tokens"] != ["~/elastic/elastic-agent-*/),"]:
        print("SELFTEST FAIL: allowlist must contain only the cited historical token")
        failures += 1
    fixture_texts = {text for text, _ in SELFTEST_CASES}
    placeholder = "someone"
    for text in (f"cleaned ~/{placeholder}/backups/old-project-*",
                 f"cleaned ~/{placeholder}/backups/old-project",
                 f"probe ~/elastic/elastic-agent-*/{placeholder}"):
        if text not in fixture_texts:
            print("SELFTEST FAIL: path fixture lost its generic placeholder")
            failures += 1
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
    # Mandatory structure is rejected at load time, independent of the text.
    raw = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    paths = (("version",), ("documentation_addresses",), ("documentation_addresses", "prefixes"),
             ("trailer_exemption",), ("trailer_exemption", "keys"),
             ("template_allowlist",), ("template_allowlist", "tokens"),
             ("finding_precedence",), ("finding_precedence", "suppressed_by"),
             ("rules",), ("rules", 0, "id"), ("rules", 0, "pattern"),
             ("rules", 0, "why"), ("rules", 0, "severity"))
    for path in paths:
        for mutation in ("missing", "wrong type"):
            broken = copy.deepcopy(raw)
            parent = broken
            for part in path[:-1]:
                parent = parent[part]
            if mutation == "missing":
                del parent[path[-1]]
            else:
                parent[path[-1]] = [] if path == ("version",) else 7
            with tempfile.TemporaryDirectory() as directory:
                file = Path(directory) / "rules.json"
                file.write_text(json.dumps(broken), encoding="utf-8")
                try:
                    load_rules(file)
                except (ValueError, KeyError, TypeError, re.error):
                    pass
                else:
                    print(f"SELFTEST FAIL: invalid mandatory path {path} ({mutation}) loaded")
                    failures += 1
    # Adding the permitted token to a message must preserve ALL
    # findings from the separate tokens, including every other rule. Comparing
    # lists also catches a spurious finding on the allowed token itself.
    for template in ("~/elastic/elastic-agent-*/),",):
        for text, _ in SELFTEST_CASES:
            expected = scan(text, "selftest", rules)
            found = scan(f"{text}\t{template}", "selftest", rules)
            if found != expected:
                print("SELFTEST FAIL: a listed token changed separate findings")
                failures += 1
        # This synthetic rule deliberately matches the allowed token itself:
        # exemption membership must never suppress a different rule's match.
        other_rules = dict(rules)
        other_rules["rules"] = [
            {"id": "other-rule-control", "why": "selftest control",
             "compiled": re.compile(re.escape(template))}
        ]
        if [f.rule_id for f in scan(template, "selftest", other_rules)] != [
            "other-rule-control"
        ]:
            print("SELFTEST FAIL: template exemption reached another rule")
            failures += 1
    if failures:
        print(f"public_text_lint selftest: {failures} failure(s)")
        return 1
    print(
        f"public_text_lint selftest: {len(SELFTEST_CASES)} seeded leaks caught, "
        f"{len(SELFTEST_CLEAN)} clean messages passed; "
        f"{len(SELFTEST_CASES)} mixed-message and 1 other-rule control passed"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="exclusive lower bound of the commit range")
    parser.add_argument("--head", default="HEAD", help="upper bound of the range")
    parser.add_argument(
        "--tags", action="store_true", help="also scan annotated tag messages"
    )
    parser.add_argument("--tag-ref", help="scan one pushed tag by full refs/tags/ name")
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

    if not args.base and not args.tags and not args.tag_ref:
        print(
            "public_text_lint: --base is required unless --selftest or --tags "
            "is given"
        )
        return 2

    try:
        subjects = commit_messages(args.base, args.head) if args.base else []
        if args.tags or args.tag_ref:
            subjects += tag_messages(args.tag_ref)
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
    # The declared known gaps are deliberately NOT printed here. This output
    # reaches every author who trips the gate, and listing the blind spots on
    # every failure republishes them far wider than the people evaluating the
    # gate. They live in the rules file and in the workflow header, which is
    # where a reviewer or an owner reads them.
    return 1


if __name__ == "__main__":
    sys.exit(main())
