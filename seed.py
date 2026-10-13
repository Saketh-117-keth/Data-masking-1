"""Create a demo financial database (synthetic data only)."""
import os
import random
import sqlite3
import sys

FIRST = ["Asha", "Ravi", "Meera", "Karthik", "Sneha", "Arjun", "Divya", "Imran", "Priya", "Vikram",
         "Anita", "Rohan", "Nisha", "Suresh", "Lakshmi", "Aman", "Pooja", "Harsha", "Tara", "Dev"]
LAST = ["Verma", "Reddy", "Nair", "Sharma", "Iyer", "Khan", "Patel", "Rao", "Das", "Mehta"]
CITIES = ["Pune", "Hyderabad", "Chennai", "Vizianagaram", "Mumbai", "Bengaluru"]
STREETS = ["MG Road", "Lake View Rd", "Park Street", "Temple Lane", "Station Road", "Hill Avenue"]
MERCHANTS = ["Amazon", "Swiggy", "Uber", "Flipkart", "Reliance Fresh", "IRCTC", "Netflix"]


def luhn_check_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def make_card(rng: random.Random) -> str:
    body = "4" + "".join(str(rng.randint(0, 9)) for _ in range(14))
    n = body + luhn_check_digit(body)
    return "-".join(n[i:i + 4] for i in range(0, 16, 4))


def seed(path: str, n_customers: int = 40, seed_value: int = 7) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    rng = random.Random(seed_value)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE customers (
            customer_id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT,
            ssn TEXT, dob TEXT, address TEXT, city TEXT,
            contact TEXT   -- misleading name on purpose: holds emails (found by content scan)
        );
        CREATE TABLE accounts (
            account_id INTEGER PRIMARY KEY, customer_id INTEGER, account_number TEXT,
            card_number TEXT, balance REAL, account_type TEXT
        );
        CREATE TABLE transactions (
            txn_id INTEGER PRIMARY KEY, account_id INTEGER, amount REAL, merchant TEXT, txn_date TEXT
        );
    """)
    txn = 1
    for cid in range(1, n_customers + 1):
        if cid == 1:  # fixed row so the demo output is predictable
            name, ssn, card = "Asha Verma", "123-45-6789", "4111-1111-1111-1111"
        else:
            name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
            ssn = f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
            card = make_card(rng)
        email = name.lower().replace(" ", ".") + f"{cid}@example.com"
        phone = f"+91 {rng.randint(70000, 99999)} {rng.randint(10000, 99999)}"
        dob = f"{rng.randint(1960, 2003)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
        city = rng.choice(CITIES)
        address = f"{rng.randint(1, 250)} {rng.choice(STREETS)}, {city}"
        conn.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?)",
                     (cid, name, email, phone, ssn, dob, address, city, f"alt.{email}"))
        balance = round(rng.choice([rng.uniform(200, 9000), rng.uniform(10_000, 90_000), rng.uniform(100_000, 900_000)]), 2)
        conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?)",
                     (cid, cid, f"ACCT-{rng.randint(10**9, 10**10 - 1)}", card, balance,
                      rng.choice(["SAVINGS", "CURRENT", "CREDIT"])))
        for _ in range(rng.randint(1, 4)):
            conn.execute("INSERT INTO transactions VALUES (?,?,?,?,?)",
                         (txn, cid, round(rng.uniform(50, 5000), 2), rng.choice(MERCHANTS),
                          f"2026-{rng.randint(1, 9):02d}-{rng.randint(1, 28):02d}"))
            txn += 1
    conn.commit()
    conn.close()


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/bank.db"
    seed(target)
    print(f"Seeded {target}")
