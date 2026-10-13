"""Streamlit dashboard.   pip install streamlit pandas   then:   streamlit run streamlit_app.py"""
import os
from dataclasses import asdict

import pandas as pd
import streamlit as st

from masking import MaskingEngine, QueryRejected, SQLiteBackend
from masking.maskers import POLICIES
from seed import seed

DB = os.environ.get("BANK_DB", "data/bank.db")
COLORS = {"partial": "#fff3cd", "hash": "#dbe7ff", "redact": "#f8d7da"}
EXAMPLES = {
    "Customers": "SELECT customer_id, full_name, email, phone, ssn, dob FROM customers LIMIT 10",
    "Join (cards + balance)": "SELECT c.full_name, a.account_number, a.card_number, a.balance "
                              "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 10",
    "Alias + math (bypass attempt)": "SELECT ssn AS tax_ref, balance*1.1 AS projected "
                                     "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id LIMIT 10",
    "Aggregate": "SELECT city, COUNT(*) AS customers, SUM(balance) AS total "
                 "FROM customers c JOIN accounts a ON a.customer_id=c.customer_id GROUP BY city",
}

st.set_page_config(page_title="Smart Data Masking", layout="wide")


@st.cache_resource
def get_engine():
    if not os.path.exists(DB):
        seed(DB)
    eng = MaskingEngine(SQLiteBackend(DB))
    if not eng.tags:
        eng.scan()
    return eng


def show(result):
    df = pd.DataFrame(result.rows, columns=result.columns)
    action = {r["column"]: r["action"] for r in result.column_report}

    def paint(col):
        color = COLORS.get(action.get(col.name))
        return [f"background-color: {color}; color: #111" if color else ""] * len(col)

    if df.columns.is_unique:
        st.dataframe(df.style.apply(paint, axis=0), hide_index=True)
    else:
        st.dataframe(df, hide_index=True)
    protected = [r for r in result.column_report if r["action"] != "none"]
    if protected:
        st.caption("Protected: " + ", ".join(f'{r["column"]} ({r["tag"]} → {r["action"]})' for r in protected))


engine = get_engine()

st.title("Smart Data Masking System")
st.caption("Same query, same database, different view per role. Stored data is never modified.")

role = st.sidebar.radio("Active role", list(POLICIES), index=1)
st.sidebar.markdown("**Policy**")
st.sidebar.table(pd.DataFrame(POLICIES).T.fillna("none"))

tab_q, tab_cmp, tab_raw, tab_scan, tab_audit = st.tabs(
    ["Query", "Compare all roles", "Raw stored data", "PII scan report", "Audit log"]
)

if "sql" not in st.session_state:
    st.session_state.sql = EXAMPLES["Customers"]


def load_example():
    st.session_state.sql = EXAMPLES[st.session_state.example]


with tab_q:
    st.selectbox("Example queries", list(EXAMPLES), key="example", on_change=load_example)
    sql = st.text_area("SQL (read-only SELECT)", key="sql", height=110)
    if st.button("Run as " + role, type="primary"):
        try:
            show(engine.query(role, sql))
        except QueryRejected as exc:
            st.error(f"Rejected: {exc}")
        except Exception as exc:
            st.error(f"Query failed: {exc}")

with tab_cmp:
    if st.button("Run as every role"):
        cols = st.columns(len(POLICIES))
        for col, r in zip(cols, POLICIES):
            with col:
                st.subheader(r)
                try:
                    show(engine.query(r, st.session_state.sql))
                except Exception as exc:
                    st.error(str(exc))

with tab_raw:
    st.caption("Demo only: reads the stored tables directly to prove they are untouched.")
    table = st.selectbox("Table", engine.backend.list_tables())
    cols, rows, _ = engine.backend.execute_readonly(f"SELECT * FROM {engine.backend.quote(table)} LIMIT 20")
    st.dataframe(pd.DataFrame(rows, columns=cols), hide_index=True)

with tab_scan:
    if st.button("Re-scan database"):
        engine.scan()
    st.dataframe(
        pd.DataFrame([asdict(t) | {"reasons": "; ".join(t.reasons)} for t in engine.tags]),
        hide_index=True,
    )

with tab_audit:
    st.dataframe(pd.DataFrame(engine.recent_audit(50)), hide_index=True)
