#!/usr/bin/env python3
"""Generate a fictional vote with known fraud injected, to demo and test the audit.

  python synthetic.py demo-votes.csv
"""
from __future__ import annotations

import csv
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

DOMAINS = ["gmail.com"] * 6 + ["yahoo.com", "outlook.com", "icloud.com", "company.example"]
SURNAMES = ["popescu", "ionescu", "stan", "dumitru", "matei", "tudor", "marin", "barbu", "nistor", "florea", "ene", "toma", "rusu", "moldovan", "dobre", "lungu", "voicu", "preda", "oprea", "neagu"]
NAMES = ["ana", "mihai", "elena", "radu", "ioana", "andrei", "maria", "vlad", "bianca", "george", "irina", "sorin", "oana", "florin"]
CATEGORIES = {"Restaurant of the year": ["Bistro Nord", "Casa Veche", "Olive Lab"],
              "Startup of the year": ["Pixel Farm", "Greenroute", "Medlink"]}


def generate(seed: int = 11) -> list[dict]:
    rnd = random.Random(seed)
    start = datetime(2026, 9, 10, 8, tzinfo=timezone.utc)
    rows = []

    def vote(at, email, category, nominee, user=None):
        rows.append({"created_at": at.isoformat(), "user_id": user or str(uuid.UUID(int=rnd.getrandbits(128))), "email": email,
                     "category": category, "nominee": nominee})

    # organic voters spread over 10 days, voting in one or two categories; every inbox is unique
    used: set[str] = set()
    for i in range(900):
        while True:
            email = f"{rnd.choice(NAMES)}.{rnd.choice(SURNAMES)}{rnd.randint(1, 999) if rnd.random() < 0.3 else ''}@{rnd.choice(DOMAINS)}"
            if email.replace(".", "") not in used:
                used.add(email.replace(".", ""))
                break
        user = str(uuid.UUID(int=rnd.getrandbits(128)))
        for category in rnd.sample(list(CATEGORIES), k=rnd.choice([1, 1, 2])):
            weights = [5, 3, 2] if category.startswith("Restaurant") else [3, 4, 3]
            vote(start + timedelta(minutes=rnd.randint(0, 14400)), email, category, rnd.choices(CATEGORIES[category], weights)[0], user)

    # fraud 1: an account series ion1..ion70 on gmail, all for one nominee, within 25 minutes
    t0 = start + timedelta(days=6, hours=21)
    for i in range(1, 71):
        vote(t0 + timedelta(seconds=rnd.randint(0, 1500)), f"ion.popa{i}@gmail.com", "Restaurant of the year", "Olive Lab")

    # fraud 2: one inbox, many accounts via dots and +tags (Gmail delivers them all to the same place)
    for i in range(25):
        local = "".join(c + ("." if rnd.random() < 0.4 else "") for c in "andreeastan").rstrip(".")
        vote(start + timedelta(days=rnd.randint(1, 9), minutes=rnd.randint(0, 600)), f"{local}+v{i}@gmail.com", "Startup of the year", "Medlink")

    # fraud 3: throwaway domains
    for i in range(12):
        vote(start + timedelta(days=8, minutes=rnd.randint(0, 90)), f"user{rnd.randint(1000, 9999)}@yopmail.com", "Startup of the year", "Medlink")

    rows.sort(key=lambda r: r["created_at"])
    return rows


if __name__ == "__main__":
    rows = generate()
    with open(sys.argv[1] if len(sys.argv) > 1 else "demo-votes.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} votes")
