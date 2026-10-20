#!/usr/bin/env python3
"""Audit a public vote for coordinated or fake accounts, and export it anonymised.

Input CSV columns: created_at (ISO 8601), user_id, email, category, nominee

  python fraud_report.py votes.csv --out report/           # report.md, report.json, chart.svg
  python fraud_report.py votes.csv --anonymise votes-anon.csv

Signals, each cheap and explainable to a jury:
  alias_mailbox   several accounts that resolve to one inbox (Gmail ignores dots and +tags,
                  googlemail.com == gmail.com): only the first vote per inbox and category counts
  account_series  5+ accounts on one stem whose numeric suffixes cluster
                  (ion1, ion2, ion3...): all their votes are flagged
  disposable      throwaway e-mail domains
  burst           a nominee receiving many votes inside a short window, far above its usual pace

The output is a per-nominee table of raw vs. adjusted votes and the share of suspicious votes,
so organisers can decide; nothing is deleted.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import secrets
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com",
              "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc"}
TRAILING_DIGITS = re.compile(r"\d+$")


def split_email(email: str) -> tuple[str, str]:
    local, _, domain = email.strip().lower().partition("@")
    return local, domain


def normalise_mailbox(email: str) -> str:
    """The inbox a message actually lands in. Gmail: dots ignored, +tag dropped, googlemail aliased."""
    local, domain = split_email(email)
    local = local.split("+", 1)[0]
    if domain in GMAIL_DOMAINS:
        local, domain = local.replace(".", ""), "gmail.com"
    return f"{local}@{domain}"


def stem(email: str) -> str:
    """Local part without trailing digits, on the normalised mailbox: ion12@ and i.on7@gmail share a stem."""
    local, domain = split_email(normalise_mailbox(email))
    return f"{TRAILING_DIGITS.sub('', local)}@{domain}"


@dataclass
class Vote:
    at: datetime
    user_id: str
    email: str
    category: str
    nominee: str
    flags: set[str] = field(default_factory=set)


def load(path: Path) -> list[Vote]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [Vote(datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")), r["user_id"], r["email"] or "", r["category"], r["nominee"])
                for r in csv.DictReader(f)]


def has_cluster(numbers: set[int], size: int = 3, span: int = 10) -> bool:
    """True if at least `size` numbers fall within any range of `span`."""
    xs = sorted(numbers)
    return any(xs[i + size - 1] - xs[i] <= span for i in range(len(xs) - size + 1))


def flag_votes(votes: list[Vote], series_min: int = 5) -> None:
    # alias mailboxes: keep the earliest vote per (inbox, category), flag the rest
    seen: set[tuple[str, str]] = set()
    for v in sorted(votes, key=lambda v: v.at):
        if not v.email:
            continue
        key = (normalise_mailbox(v.email), v.category)
        if key in seen:
            v.flags.add("alias_mailbox")
        seen.add(key)

    # account series: many accounts on one stem whose numeric suffixes cluster (ion1, ion2, ion3...).
    # Common names alone (ana.maria12, ana.maria451) are not a series: the suffixes must be close together.
    accounts_by_stem: dict[str, set[str]] = defaultdict(set)
    suffixes: dict[str, set[int]] = defaultdict(set)
    for v in votes:
        if v.email:
            s = stem(v.email)
            accounts_by_stem[s].add(v.user_id)
            m = TRAILING_DIGITS.search(split_email(normalise_mailbox(v.email))[0])
            if m:
                suffixes[s].add(int(m.group()))
    series = {s for s, users in accounts_by_stem.items() if len(users) >= series_min and has_cluster(suffixes[s])}
    for v in votes:
        if v.email and stem(v.email) in series:
            v.flags.add("account_series")
        if split_email(v.email)[1] in DISPOSABLE:
            v.flags.add("disposable")


def bursts(votes: list[Vote], window: timedelta = timedelta(minutes=10), min_votes: int = 15, factor: float = 8.0) -> dict[str, dict]:
    """Per nominee: the busiest window, flagged when it holds >= min_votes and >= factor x the nominee's average window."""
    out = {}
    by_nominee: dict[str, list[Vote]] = defaultdict(list)
    for v in votes:
        by_nominee[v.nominee].append(v)
    for nominee, vs in by_nominee.items():
        vs.sort(key=lambda v: v.at)
        span = max((vs[-1].at - vs[0].at) / window, 1.0)
        avg = len(vs) / span
        threshold = max(min_votes, factor * avg)
        best, best_start, j = 0, 0, 0
        hot: set[int] = set()
        for i in range(len(vs)):
            while vs[i].at - vs[j].at > window:
                j += 1
            n = i - j + 1
            if n > best:
                best, best_start = n, j
            if n >= threshold:  # every window over the threshold, so a 25-minute attack is covered end to end
                hot.update(range(j, i + 1))
        for k in hot:
            vs[k].flags.add("burst")
        out[nominee] = {"peak_votes": best, "peak_start": vs[best_start].at.isoformat(), "avg_per_window": round(avg, 2),
                        "burst": bool(hot), "burst_votes": len(hot)}
    return out


def nominee_table(votes: list[Vote]) -> list[dict]:
    rows: dict[tuple[str, str], dict] = {}
    for v in votes:
        r = rows.setdefault((v.category, v.nominee), {"category": v.category, "nominee": v.nominee, "raw": 0, "suspicious": 0, "adjusted": 0, "by_flag": Counter()})
        r["raw"] += 1
        hard = v.flags & {"alias_mailbox", "account_series", "disposable"}
        if v.flags:
            r["suspicious"] += 1
            r["by_flag"].update(v.flags)
        if not hard:
            r["adjusted"] += 1
    table = []
    for r in rows.values():
        r["suspicious_share"] = round(r["suspicious"] / r["raw"], 3)
        r["by_flag"] = dict(r["by_flag"])
        table.append(r)
    return sorted(table, key=lambda r: (r["category"], -r["raw"]))


def anonymise(votes: list[Vote], out: Path) -> None:
    """Same rows, no personal data. A fresh random salt per export: hashes can't be joined across exports or reversed."""
    salt = secrets.token_bytes(32)
    h = lambda s: hashlib.blake2b(s.encode(), key=salt, digest_size=12).hexdigest() if s else ""
    with out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["created_at", "user_hash", "email_hash", "mailbox_hash", "stem_hash", "domain", "category", "nominee", "flags"])
        for v in votes:
            w.writerow([v.at.isoformat(), h(v.user_id), h(v.email.lower()), h(normalise_mailbox(v.email) if v.email else ""),
                        h(stem(v.email) if v.email else ""), split_email(v.email)[1], v.category, v.nominee, "|".join(sorted(v.flags))])


def chart_svg(table: list[dict], top: int = 10) -> str:
    rows = sorted(table, key=lambda r: -r["raw"])[:top]
    if not rows:
        return "<svg xmlns='http://www.w3.org/2000/svg'/>"
    w, bar_h, gap, left = 760, 22, 14, 210
    h = 70 + len(rows) * (bar_h + gap)
    scale = (w - left - 70) / max(r["raw"] for r in rows)
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;")
    out = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' font-family='Segoe UI,Arial,sans-serif'>",
           f"<rect width='100%' height='100%' fill='#0f1115'/>",
           "<text x='20' y='34' fill='#f5f5f5' font-size='18' font-weight='700'>Raw vs. adjusted votes</text>",
           "<rect x='470' y='22' width='14' height='14' fill='#3a4150'/><text x='490' y='34' fill='#9aa0a6' font-size='13'>removed (alias / series / disposable)</text>",
           "<rect x='470' y='44' width='14' height='14' fill='#6D4AFF'/><text x='490' y='56' fill='#9aa0a6' font-size='13'>counted</text>"]
    for i, r in enumerate(rows):
        y = 70 + i * (bar_h + gap)
        out.append(f"<text x='{left - 10}' y='{y + 16}' fill='#e6e6e6' font-size='13' text-anchor='end'>{esc(r['nominee'][:28])}</text>")
        out.append(f"<rect x='{left}' y='{y}' width='{r['raw'] * scale:.1f}' height='{bar_h}' rx='3' fill='#3a4150'/>")
        out.append(f"<rect x='{left}' y='{y}' width='{r['adjusted'] * scale:.1f}' height='{bar_h}' rx='3' fill='#6D4AFF'/>")
        out.append(f"<text x='{left + r['raw'] * scale + 8:.1f}' y='{y + 16}' fill='#9aa0a6' font-size='12'>{r['adjusted']}/{r['raw']}</text>")
    out.append("</svg>")
    return "\n".join(out)


def report(votes: list[Vote], out_dir: Path) -> dict:
    flag_votes(votes)
    burst_info = bursts(votes)
    table = nominee_table(votes)
    summary = {
        "votes": len(votes),
        "accounts": len({v.user_id for v in votes}),
        "mailboxes": len({normalise_mailbox(v.email) for v in votes if v.email}),
        "flagged_votes": sum(1 for v in votes if v.flags),
        "by_flag": dict(Counter(f for v in votes for f in v.flags)),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps({"summary": summary, "nominees": table, "bursts": burst_info}, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "chart.svg").write_text(chart_svg(table), encoding="utf-8")
    lines = ["# Vote audit", "", f"{summary['votes']} votes from {summary['accounts']} accounts and {summary['mailboxes']} distinct inboxes; "
             f"{summary['flagged_votes']} votes flagged ({', '.join(f'{k}: {v}' for k, v in sorted(summary['by_flag'].items()))}).", "",
             "| category | nominee | raw | adjusted | suspicious | peak 10 min |", "|---|---|---:|---:|---:|---:|"]
    for r in table:
        b = burst_info[r["nominee"]]
        lines.append(f"| {r['category']} | {r['nominee']} | {r['raw']} | {r['adjusted']} | {r['suspicious_share']:.0%} | {b['peak_votes']}{' ⚠' if b['burst'] else ''} |")
    (out_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("votes", type=Path)
    ap.add_argument("--out", type=Path, default=Path("report"))
    ap.add_argument("--anonymise", type=Path, help="also write an anonymised CSV here")
    args = ap.parse_args()
    votes = load(args.votes)
    print(json.dumps(report(votes, args.out), indent=2))
    if args.anonymise:
        anonymise(votes, args.anonymise)
        print(f"anonymised -> {args.anonymise}")


if __name__ == "__main__":
    main()
