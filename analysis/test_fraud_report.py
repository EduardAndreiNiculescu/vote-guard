import csv
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fraud_report import Vote, anonymise, bursts, flag_votes, nominee_table, normalise_mailbox, report, stem  # noqa: E402
from synthetic import generate  # noqa: E402

T = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)


def v(email, nominee="A", category="C", minutes=0, user=None):
    return Vote(T + timedelta(minutes=minutes), user or email, email, category, nominee)


def test_gmail_normalisation():
    assert normalise_mailbox("J.O.H.N+gala@GoogleMail.com") == "john@gmail.com"
    assert normalise_mailbox("j.ohn+x@yahoo.com") == "j.ohn@yahoo.com"  # dots matter outside Gmail
    assert stem("i.on.popa17@gmail.com") == "ionpopa@gmail.com"


def test_alias_inbox_counts_once_per_category():
    votes = [v("john@gmail.com", minutes=0), v("j.o.h.n+2@gmail.com", minutes=5), v("john+3@gmail.com", category="Other", minutes=6)]
    flag_votes(votes)
    assert [x.flags for x in votes] == [set(), {"alias_mailbox"}, set()]


def test_account_series_needs_digit_variation():
    series = [v(f"ion{i}@gmail.com", user=f"u{i}") for i in range(1, 7)]
    spread = [v(f"maria.stan{n}@gmail.com", user=f"s{n}") for n in (12, 80, 451, 777, 905)]
    namesakes = [v("maria@outlook.com", user="m1"), v("maria@outlook.com", user="m2", category="Other")]
    flag_votes(series + namesakes + spread)
    assert all("account_series" in x.flags for x in series)
    assert not any("account_series" in x.flags for x in namesakes + spread), "common names with scattered numbers are not a series"


def test_burst_detection():
    calm = [v(f"a{i}@x.example", minutes=i * 60) for i in range(40)]
    spike = [v(f"b{i}@y.example", nominee="B", minutes=i * 60) for i in range(20)] + [v(f"c{i}@z.example", nominee="B", minutes=900 + i * 0.3) for i in range(20)]
    info = bursts(calm + spike)
    assert info["A"]["burst"] is False
    assert info["B"]["burst"] is True and info["B"]["peak_votes"] >= 20


def test_synthetic_fraud_is_found_and_removed(tmp_path):
    rows = generate()
    votes = [Vote(datetime.fromisoformat(r["created_at"]), r["user_id"], r["email"], r["category"], r["nominee"]) for r in rows]
    summary = report(votes, tmp_path)
    table = {r["nominee"]: r for r in nominee_table(votes)}
    assert table["Olive Lab"]["by_flag"]["account_series"] >= 70
    assert table["Olive Lab"]["by_flag"]["burst"] >= 60
    assert table["Olive Lab"]["adjusted"] < table["Olive Lab"]["raw"] - 60
    assert table["Medlink"]["by_flag"]["alias_mailbox"] == 24      # 25 accounts, one inbox: first vote counts
    assert table["Medlink"]["by_flag"]["disposable"] == 12
    for organic in ("Bistro Nord", "Casa Veche", "Greenroute", "Pixel Farm"):
        assert table[organic]["suspicious_share"] < 0.03, organic   # organic nominees stay clean
    assert (tmp_path / "report.md").exists() and (tmp_path / "chart.svg").exists()
    assert summary["flagged_votes"] >= 70 + 24 + 12


def test_anonymised_export_has_no_personal_data(tmp_path):
    votes = [v("john.smith+gala@gmail.com", user="11111111-aaaa")]
    flag_votes(votes)
    out = tmp_path / "anon.csv"
    anonymise(votes, out)
    text = out.read_text(encoding="utf-8")
    assert "john" not in text and "11111111" not in text
    row = next(csv.DictReader(out.open(encoding="utf-8")))
    assert row["domain"] == "gmail.com" and len(row["mailbox_hash"]) == 24
