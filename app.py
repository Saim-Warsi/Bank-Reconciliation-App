import streamlit as st
import pandas as pd
import sqlite3, hashlib, secrets, json, shutil, io, zipfile, os, tempfile, threading
from pathlib import Path
from datetime import datetime, date
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

DB_PATH = Path("reconciliation.db")
st.set_page_config(page_title="Bank Reconciliation Pro", page_icon="🏦", layout="wide")


SYNC_STATE = {"enabled": False, "last_error": None}

@st.cache_resource(show_spinner=False)
def _sync_lock():
    return threading.Lock()

@st.cache_resource(show_spinner=False)
def _mongo_db():
    uri = None
    try:
        uri = st.secrets.get("MONGODB_URI")
    except Exception:
        pass
    uri = uri or os.environ.get("MONGODB_URI")
    if not uri:
        return None
    from pymongo import MongoClient
    client = MongoClient(uri, serverSelectionTimeoutMS=8000)
    client.admin.command("ping")
    name = None
    try:
        name = st.secrets.get("MONGODB_DB")
    except Exception:
        pass
    return client[name or os.environ.get("MONGODB_DB") or "bank_reconciliation"]

def _fs():
    db = _mongo_db()
    if db is None:
        return None
    import gridfs
    return gridfs.GridFS(db)

def restore_from_mongo():
    """Return disabled | local | restored | empty | error. Restores only if the local file is missing."""
    try:
        fs = _fs()
        if fs is None:
            return "disabled"
        SYNC_STATE["enabled"] = True
        if DB_PATH.exists():
            return "local"
        f = fs.find_one({"filename": "reconciliation.db"}, sort=[("uploadDate", -1)])
        if f is None:
            return "empty"
        DB_PATH.write_bytes(f.read())
        return "restored"
    except Exception as e:
        SYNC_STATE["last_error"] = str(e)
        return "error"

def push_to_mongo():
    """Copy a consistent snapshot of the local database to MongoDB; keeps the latest 5 versions."""
    if not SYNC_STATE["enabled"] or not DB_PATH.exists():
        return
    with _sync_lock():
        tmp = None
        try:
            fs = _fs()
            t = tempfile.NamedTemporaryFile(delete=False, suffix=".db"); t.close(); tmp = t.name
            src = sqlite3.connect(DB_PATH); dst = sqlite3.connect(tmp)
            src.backup(dst); dst.close(); src.close()
            fs.put(Path(tmp).read_bytes(), filename="reconciliation.db")
            versions = list(fs.find({"filename": "reconciliation.db"}, sort=[("uploadDate", -1)]))
            for old in versions[5:]:
                fs.delete(old._id)
            SYNC_STATE["last_error"] = None
        except Exception as e:
            SYNC_STATE["last_error"] = str(e)
        finally:
            if tmp and os.path.exists(tmp):
                try: os.unlink(tmp)
                except Exception: pass

class SyncConn(sqlite3.Connection):
    """Pushes the database to MongoDB after any block that committed changes."""
    def __exit__(self, exc_type, exc, tb):
        result = super().__exit__(exc_type, exc, tb)
        if exc_type is None and self.total_changes > 0:
            push_to_mongo()
        return result

def connect():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, factory=SyncConn)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def pw_hash(p, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 180000).hex()
    return salt + "$" + digest

def pw_ok(p, stored):
    try:
        salt, digest = stored.split("$", 1)
        return secrets.compare_digest(pw_hash(p, salt).split("$",1)[1], digest)
    except Exception:
        return False

def audit(user, action, detail):
    with connect() as c:
        c.execute("INSERT INTO audit_log(username,action,detail,created_at) VALUES(?,?,?,?)",
                  (user, action, detail[:1000], datetime.now().isoformat(timespec="seconds")))

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'Accountant', active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS companies(
          id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, currency TEXT NOT NULL DEFAULT 'PKR',
          created_at TEXT NOT NULL, deleted_at TEXT DEFAULT NULL);
        CREATE TABLE IF NOT EXISTS accounts(
          id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, bank_name TEXT NOT NULL,
          account_title TEXT NOT NULL, account_number TEXT NOT NULL, gl_code TEXT DEFAULT '',
          opening_bank REAL DEFAULT 0, opening_book REAL DEFAULT 0, active INTEGER DEFAULT 1,
          deleted_at TEXT DEFAULT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id));
        CREATE TABLE IF NOT EXISTS transactions(
          id INTEGER PRIMARY KEY, company_id INTEGER NOT NULL, account_id INTEGER NOT NULL,
          source TEXT NOT NULL CHECK(source IN ('Bank','Books','Adjustment')),
          txn_date TEXT NOT NULL, description TEXT DEFAULT '', reference TEXT DEFAULT '',
          debit REAL DEFAULT 0, credit REAL DEFAULT 0, amount REAL NOT NULL,
          fingerprint TEXT, match_group TEXT, status TEXT DEFAULT 'Unmatched',
          source_file TEXT DEFAULT '', imported_at TEXT NOT NULL, deleted_at TEXT DEFAULT NULL,
          FOREIGN KEY(company_id) REFERENCES companies(id),
          FOREIGN KEY(account_id) REFERENCES accounts(id));
        CREATE UNIQUE INDEX IF NOT EXISTS ux_txn_fingerprint ON transactions(fingerprint) WHERE fingerprint IS NOT NULL;
        CREATE TABLE IF NOT EXISTS reconciliation_runs(
          id INTEGER PRIMARY KEY, company_id INTEGER, account_id INTEGER, period_start TEXT,
          period_end TEXT, bank_closing REAL, book_closing REAL, brs_adjusted REAL,
          status TEXT DEFAULT 'Draft', created_by TEXT, created_at TEXT, deleted_at TEXT DEFAULT NULL,
          updated_at TEXT DEFAULT NULL, updated_by TEXT DEFAULT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY, username TEXT, action TEXT, detail TEXT, created_at TEXT);
                """)

        # Backward-compatible migrations for existing databases.
        migrations = {
            "companies": {"deleted_at": "TEXT DEFAULT NULL"},
            "accounts": {"deleted_at": "TEXT DEFAULT NULL"},
            "transactions": {"deleted_at": "TEXT DEFAULT NULL"},
            "reconciliation_runs": {
                "deleted_at": "TEXT DEFAULT NULL",
                "updated_at": "TEXT DEFAULT NULL",
                "updated_by": "TEXT DEFAULT NULL",
            },
        }
        for table, wanted in migrations.items():
            existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
            for column, definition in wanted.items():
                if column not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

        # Automatically upgrade older databases
        columns = [
            row["name"]
            for row in c.execute(
                "PRAGMA table_info(companies)"
            ).fetchall()
        ]

        if "currency" not in columns:
            c.execute("""
                ALTER TABLE companies
                ADD COLUMN currency TEXT DEFAULT 'PKR'
            """)
        if not c.execute("SELECT id FROM users LIMIT 1").fetchone():
            c.execute("INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                      ("admin", pw_hash("ChangeMe123!"), "Admin", 1, datetime.now().isoformat(timespec="seconds")))
        if not c.execute("SELECT id FROM companies LIMIT 1").fetchone():
            c.execute("INSERT INTO companies(name,currency,created_at) VALUES(?,?,?)",
                      ("Demo Company", "PKR", datetime.now().isoformat(timespec="seconds")))
            cid = c.execute("SELECT id FROM companies WHERE name='Demo Company'").fetchone()[0]
            c.execute("""INSERT INTO accounts(company_id,bank_name,account_title,account_number,gl_code)
                         VALUES(?,?,?,?,?)""", (cid, "Bank account", "Main Current Account", "DEMO-001", "1010"))

def qdf(sql, params=()):
    with connect() as c:
        return pd.read_sql_query(sql, c, params=params)

def company_options():
    d = qdf(
        "SELECT id, name, currency FROM companies WHERE deleted_at IS NULL ORDER BY name"
    )
    return d

def account_options(company_id):
    return qdf("SELECT * FROM accounts WHERE company_id=? AND active=1 AND deleted_at IS NULL ORDER BY bank_name,account_title", (int(company_id),))

def money(v, currency="PKR"):
    return f"{currency} {float(v or 0):,.2f}"

def norm_cols(df):
    df = df.copy()
    df.columns = [str(x).strip().lower().replace(" ","_") for x in df.columns]
    aliases = {
      "txn_date":["date","transaction_date","txn_date","value_date","posting_date"],
      "description":["narration","details","particulars","transaction_description"],
      "reference":["ref","cheque_no","check_no","instrument_no","transaction_id"],
      "debit":["withdrawal","withdrawals","dr","paid_out"],
      "credit":["deposit","deposits","cr","paid_in"],
      "amount":["transaction_amount","value"]
    }
    rename = {}
    for target, names in aliases.items():
        if target not in df.columns:
            for n in names:
                if n in df.columns:
                    rename[n] = target
                    break
    return df.rename(columns=rename)

def parse_file(upload):
    raw = pd.read_excel(upload) if upload.name.lower().endswith((".xlsx",".xls")) else pd.read_csv(upload)
    d = norm_cols(raw)
    if "txn_date" not in d: raise ValueError("Date column is required.")
    for col in ("description","reference"):
        if col not in d: d[col] = ""
    for col in ("debit","credit","amount"):
        if col in d:
            d[col] = pd.to_numeric(d[col].astype(str).str.replace(",","").str.replace("PKR","",regex=False).str.strip(), errors="coerce").fillna(0)
    if "amount" not in d:
        if "debit" not in d and "credit" not in d: raise ValueError("Provide Amount, or Debit and Credit columns.")
        d["amount"] = (d["credit"] if "credit" in d else 0) - (d["debit"] if "debit" in d else 0)
    elif "debit" in d or "credit" in d:
        dr = d["debit"] if "debit" in d else 0
        cr = d["credit"] if "credit" in d else 0
        d["amount"] = (cr-dr).where((dr!=0)|(cr!=0), d["amount"])
    dates = pd.to_datetime(d["txn_date"], errors="coerce", dayfirst=True)
    if dates.isna().any(): raise ValueError("One or more dates are invalid. Use DD-MM-YYYY or YYYY-MM-DD.")
    d["txn_date"] = dates.dt.strftime("%Y-%m-%d")
    d["description"] = d["description"].fillna("").astype(str).str.strip()
    d["reference"] = d["reference"].fillna("").astype(str).str.strip()
    d["debit"] = d["amount"].apply(lambda x: abs(float(x)) if x<0 else 0)
    d["credit"] = d["amount"].apply(lambda x: float(x) if x>0 else 0)
    return d[["txn_date","description","reference","debit","credit","amount"]]

def fingerprint(company, account, source, row):
    raw = "|".join(map(str,[company,account,source,row.txn_date,row.description.lower(),row.reference.lower(),f"{row.amount:.2f}"]))
    return hashlib.sha256(raw.encode()).hexdigest()

def import_transactions(d, company_id, account_id, source, filename, username):
    count=0
    with connect() as c:
        for r in d.itertuples(index=False):
            fp=fingerprint(company_id,account_id,source,r)
            try:
                c.execute("""INSERT INTO transactions(company_id,account_id,source,txn_date,description,reference,debit,credit,amount,
                          fingerprint,source_file,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                          (company_id,account_id,source,r.txn_date,r.description,r.reference,float(r.debit),float(r.credit),
                           float(r.amount),fp,filename,datetime.now().isoformat(timespec="seconds")))
                count+=1
            except sqlite3.IntegrityError: pass
    audit(username,"IMPORT",f"{count} {source} transactions imported from {filename}; company={company_id}; account={account_id}")
    return count

def transactions(company_id, account_id):
    return qdf("SELECT * FROM transactions WHERE company_id=? AND account_id=? AND deleted_at IS NULL ORDER BY txn_date,id",(company_id,account_id))


def update_transaction(txn_id, txn_date, description, reference, debit, credit, username):
    debit, credit = float(debit), float(credit)
    if debit < 0 or credit < 0 or (debit > 0 and credit > 0):
        raise ValueError("Enter either a non-negative debit or a non-negative credit, not both.")
    amount = credit - debit
    with connect() as c:
        row = c.execute(
            "SELECT * FROM transactions WHERE id=? AND deleted_at IS NULL", (int(txn_id),)
        ).fetchone()
        if not row:
            raise ValueError("Transaction not found.")
        if row["status"] == "Matched":
            raise ValueError("Undo its match group before editing this transaction.")
        c.execute("""UPDATE transactions
                     SET txn_date=?, description=?, reference=?, debit=?, credit=?, amount=?,
                         fingerprint=NULL
                     WHERE id=?""",
                  (txn_date.isoformat() if hasattr(txn_date, "isoformat") else str(txn_date),
                   description.strip(), reference.strip(), debit, credit, amount, int(txn_id)))
    audit(username, "UPDATE TRANSACTION",
          f"Transaction #{txn_id}; date={txn_date}; description={description}; reference={reference}; debit={debit}; credit={credit}")

def soft_delete_transaction(txn_id, username):
    with connect() as c:
        row = c.execute(
            "SELECT id, status, match_group FROM transactions WHERE id=? AND deleted_at IS NULL",
            (int(txn_id),)
        ).fetchone()
        if not row:
            raise ValueError("Transaction not found.")
        if row["status"] == "Matched":
            raise ValueError("Undo the match group before deleting this transaction.")
        c.execute("UPDATE transactions SET deleted_at=? WHERE id=?",
                  (datetime.now().isoformat(timespec="seconds"), int(txn_id)))
    audit(username, "TRASH TRANSACTION", f"Transaction #{txn_id} moved to Recycle Bin.")

def restore_transaction(txn_id, username):
    with connect() as c:
        row = c.execute("SELECT id FROM transactions WHERE id=? AND deleted_at IS NOT NULL",
                        (int(txn_id),)).fetchone()
        if not row:
            raise ValueError("Deleted transaction not found.")
        c.execute("UPDATE transactions SET deleted_at=NULL WHERE id=?", (int(txn_id),))
    audit(username, "RESTORE TRANSACTION", f"Transaction #{txn_id} restored.")

def update_brs(run_id, period_start, period_end, bank_closing, book_closing, username):
    if period_start > period_end:
        raise ValueError("Period start must not be after period end.")
    with connect() as c:
        row = c.execute("SELECT status FROM reconciliation_runs WHERE id=? AND deleted_at IS NULL",
                        (int(run_id),)).fetchone()
        if not row:
            raise ValueError("Reconciliation run not found.")
        if row["status"] != "Draft":
            raise ValueError("Only Draft reconciliation runs can be edited.")
        run_account = c.execute(
            "SELECT company_id, account_id FROM reconciliation_runs WHERE id=?", (int(run_id),)
        ).fetchone()
        txns = c.execute("""SELECT source, amount FROM transactions
                            WHERE company_id=? AND account_id=? AND deleted_at IS NULL
                              AND status='Unmatched' AND txn_date BETWEEN ? AND ?""",
                         (run_account["company_id"], run_account["account_id"],
                          period_start.isoformat(), period_end.isoformat())).fetchall()
        bank_credits = sum(r["amount"] for r in txns if r["source"] == "Bank" and r["amount"] > 0)
        bank_debits = sum(r["amount"] for r in txns if r["source"] == "Bank" and r["amount"] < 0)
        adjusted_book = float(book_closing + bank_credits + bank_debits)
        c.execute("""UPDATE reconciliation_runs
                     SET period_start=?, period_end=?, bank_closing=?, book_closing=?, brs_adjusted=?,
                         updated_at=?, updated_by=?
                     WHERE id=?""",
                  (period_start.isoformat(), period_end.isoformat(), float(bank_closing),
                   float(book_closing), adjusted_book, datetime.now().isoformat(timespec="seconds"),
                   username, int(run_id)))
    audit(username, "UPDATE BRS DRAFT", f"Reconciliation run #{run_id} updated.")

def soft_delete_brs(run_id, username):
    with connect() as c:
        row = c.execute("SELECT status FROM reconciliation_runs WHERE id=? AND deleted_at IS NULL",
                        (int(run_id),)).fetchone()
        if not row:
            raise ValueError("Reconciliation run not found.")
        if row["status"] != "Draft":
            raise ValueError("Only Draft reconciliation runs can be moved to the Recycle Bin.")
        c.execute("UPDATE reconciliation_runs SET deleted_at=? WHERE id=?",
                  (datetime.now().isoformat(timespec="seconds"), int(run_id)))
    audit(username, "TRASH BRS DRAFT", f"Reconciliation run #{run_id} moved to Recycle Bin.")

def match_group(ids, username, label="Manual match", balancing=None):
    """Match bank and book entries that offset to zero.

    balancing: optional dict(date, description, reference). When the selected entries
    do not net to zero, an Adjustment entry for the exact residual is created and matched
    in the same database transaction, so the group always balances and stays auditable.
    """
    ids=[int(x) for x in ids]
    if len(ids)<2: raise ValueError("Select at least two entries.")
    with connect() as c:
        marks=",".join("?"*len(ids))
        rows=c.execute(f"SELECT id,company_id,account_id,source,amount,status FROM transactions WHERE id IN ({marks})",ids).fetchall()
        if len(rows)!=len(ids): raise ValueError("One or more selected transactions do not exist.")
        if any(r["status"]=="Matched" for r in rows): raise ValueError("A selected transaction is already matched.")
        sources={r["source"] for r in rows}
        if "Bank" not in sources or not ({"Books","Adjustment"} & sources):
            raise ValueError("A match must include at least one Bank entry and at least one Books/Adjustment entry.")
        total=round(sum(r["amount"] for r in rows),2)
        gid="R-"+secrets.token_hex(5).upper()
        adj_id=None
        if abs(total)>0.01:
            if not balancing or not str(balancing.get("description","")).strip():
                raise ValueError(f"Selected entries do not balance. Net difference: {total:,.2f}. "
                                 "Post a balancing entry with a description, or correct the entries.")
            amt=-total   # the adjustment offsets the residual exactly
            cur=c.execute("""INSERT INTO transactions(company_id,account_id,source,txn_date,description,reference,
                              debit,credit,amount,status,match_group,imported_at)
                             VALUES(?,?,'Adjustment',?,?,?,?,?,?,'Matched',?,?)""",
                          (rows[0]["company_id"],rows[0]["account_id"],balancing["date"],
                           balancing["description"].strip(),str(balancing.get("reference","")).strip(),
                           max(-amt,0),max(amt,0),amt,gid,datetime.now().isoformat(timespec="seconds")))
            adj_id=cur.lastrowid
        c.execute(f"UPDATE transactions SET match_group=?,status='Matched' WHERE id IN ({marks})",[gid]+ids)
    detail=f"Group {gid}; transaction IDs={ids}"
    if adj_id: detail+=f"; balancing adjustment #{adj_id} amount={-total:,.2f}"
    audit(username,label,detail)
    return gid

def automatic_match(df, date_days, amount_tolerance, username):
    bank=df[(df.source=="Bank")&(df.status=="Unmatched")].copy()
    other=df[(df.source.isin(["Books","Adjustment"]))&(df.status=="Unmatched")].copy()
    done=0
    used=set()
    # First pass: exact one-to-one; then bounded subset-sum groups (up to 4 entries).
    for b in bank.itertuples():
        cand=other[~other.id.isin(used)].copy()
        if cand.empty: continue
        cand["date_diff"]=(pd.to_datetime(cand.txn_date)-pd.to_datetime(b.txn_date)).abs().dt.days
        cand["diff"]=(cand.amount+b.amount).abs()
        cand=cand[(cand.date_diff<=date_days)&(cand["diff"]<=amount_tolerance)]
        if len(cand):
            cand=cand.sort_values(["diff","date_diff"])
            chosen=cand.iloc[0]
            try:
                match_group([b.id,int(chosen.id)],username,"Automatic match")
                used.add(int(chosen.id)); done+=1
            except Exception: pass
    # Grouped match: find up to 4 same-side entries that sum to the opposite bank amount.
    import itertools
    fresh=transactions(int(df.iloc[0].company_id),int(df.iloc[0].account_id)) if len(df) else df
    for b in fresh[(fresh.source=="Bank")&(fresh.status=="Unmatched")].itertuples():
        cand=fresh[(fresh.source.isin(["Books","Adjustment"]))&(fresh.status=="Unmatched")].copy()
        cand=cand[(pd.to_datetime(cand.txn_date)-pd.Timestamp(b.txn_date)).abs().dt.days<=date_days]
        cand=cand[~cand.id.isin(used)].head(25)
        vals=list(cand.itertuples())
        found=None
        for size in range(2,min(4,len(vals))+1):
            for subset in itertools.combinations(vals,size):
                if abs(sum(x.amount for x in subset)+b.amount)<=amount_tolerance:
                    found=[b.id]+[x.id for x in subset]; break
            if found: break
        if found:
            try:
                match_group(found,username,"Automatic grouped match")
                used.update(found[1:]); done+=1
                fresh=transactions(int(df.iloc[0].company_id),int(df.iloc[0].account_id))
            except Exception: pass
    return done

def make_excel(df, brs_df, audit_df=None):
    bio=io.BytesIO()
    with pd.ExcelWriter(bio,engine="openpyxl") as w:
        df.to_excel(w,index=False,sheet_name="Transactions")
        brs_df.to_excel(w,index=False,sheet_name="BRS")
        if audit_df is not None: audit_df.to_excel(w,index=False,sheet_name="Audit Log")
    bio.seek(0); return bio.getvalue()

def make_pdf(title, lines, table_data):
    bio=io.BytesIO()
    doc=SimpleDocTemplate(bio,pagesize=landscape(A4),rightMargin=24,leftMargin=24,topMargin=24,bottomMargin=24)
    styles=getSampleStyleSheet()
    story=[Paragraph(title,styles["Title"]),Spacer(1,10)]
    for line in lines: story.append(Paragraph(line,styles["Normal"]))
    story.append(Spacer(1,12))
    t=Table(table_data,repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#203864")),("TEXTCOLOR",(0,0),(-1,0),colors.white),
      ("GRID",(0,0),(-1,-1),0.35,colors.grey),("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
      ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#EEF2F7")])]))
    story.append(t); doc.build(story); bio.seek(0); return bio.getvalue()

_sync_status = restore_from_mongo()
if _sync_status == "error":
    st.error("Could not reach MongoDB, so the app has stopped to protect your data. "
             f"Check MONGODB_URI and the Atlas network access list. Details: {SYNC_STATE['last_error']}")
    st.stop()
init_db()
if SYNC_STATE["enabled"] and not st.session_state.get("_mongo_synced"):
    push_to_mongo(); st.session_state["_mongo_synced"]=True

# Login gate
if "user" not in st.session_state:
    st.title("🏦 Bank Reconciliation Pro")
    st.subheader("Sign in")
    with st.form("login"):
        u=st.text_input("Username")
        p=st.text_input("Password",type="password")
        go=st.form_submit_button("Sign in",type="primary")
    if go:
        row=None
        with connect() as c: row=c.execute("SELECT * FROM users WHERE username=? AND active=1",(u.strip(),)).fetchone()
        if row and pw_ok(p,row["password_hash"]):
            st.session_state.user={"username":row["username"],"role":row["role"]}
            audit(u.strip(),"LOGIN","Successful login")
            st.rerun()
        st.error("Invalid username or password.")
    st.info("Initial administrator login: admin / ChangeMe123! — change this password immediately after first login.")
    st.stop()

USER=st.session_state.user
role=USER["role"]
st.sidebar.title("🏦 Reconciliation Pro")
st.sidebar.write(f"**{USER['username']}** · {role}")
if SYNC_STATE["enabled"]:
    if SYNC_STATE["last_error"]: st.sidebar.warning("MongoDB sync failed: "+SYNC_STATE["last_error"][:150])
    else: st.sidebar.caption("☁️ MongoDB sync: ON")
else: st.sidebar.caption("⚠️ MongoDB not configured: data is temporary")
co=company_options()
if co.empty: st.error("Create a company first."); st.stop()
company_name=st.sidebar.selectbox("Company",co.name.tolist())
company_id=int(co.loc[co.name==company_name,"id"].iloc[0])
ac=account_options(company_id)
if ac.empty: st.sidebar.warning("No active bank accounts for this company.")
else:
    labels=ac.apply(lambda r:f"{r.bank_name} — {r.account_title} ({r.account_number})",axis=1).tolist()
    sel=st.sidebar.selectbox("Bank account",labels)
    account_id=int(ac.iloc[labels.index(sel)].id)
st.sidebar.button("Log out",on_click=lambda: st.session_state.pop("user",None))
st.title("Bank Reconciliation Pro")
st.caption("Multi-company • Multi-bank • Split/combined matching • Formal BRS • Audit trail")
if ac.empty: st.stop()
tabs=st.tabs(["Dashboard","Companies & Accounts","Import","Reconciliation","Manual Match & Adjustments","BRS & Reports","Data Management","Users & Audit","Backup & Restore"])

with tabs[0]:
    df=transactions(company_id,account_id)
    bank=df[df.source=="Bank"]; books=df[df.source.isin(["Books","Adjustment"])]
    matched=df[df.status=="Matched"]
    unmatched=df[df.status=="Unmatched"]
    a,b,c,d=st.columns(4)
    a.metric("Bank entries",len(bank)); b.metric("Book/adjustment entries",len(books))
    a2=matched[matched.source=="Bank"].shape[0]
    c.metric("Matched bank entries",a2); d.metric("Unmatched entries",len(unmatched))
    st.subheader("Account movement summary")
    x,y=st.columns(2)
    x.metric("Bank net movement",money(bank.amount.sum(),co.loc[co.id==company_id,"currency"].iloc[0]))
    y.metric("Books net movement",money(books.amount.sum(),co.loc[co.id==company_id,"currency"].iloc[0]))
    st.subheader("Recent activity")
    st.dataframe(df.tail(15),use_container_width=True,hide_index=True)
    st.caption("Movement totals are period movements, not closing balances. Use BRS & Reports to enter statement and ledger closing balances.")

with tabs[1]:
    st.subheader("Company management")
    if role=="Admin":
        with st.form("new_company"):
            name=st.text_input("Company name")
            curr=st.selectbox("Base currency",["PKR","USD","AED","GBP","EUR"])
            add=st.form_submit_button("Add company")
        if add and name.strip():
            try:
                with connect() as c: c.execute("INSERT INTO companies(name,currency,created_at) VALUES(?,?,?)",(name.strip(),curr,datetime.now().isoformat(timespec="seconds")))
                audit(USER["username"],"CREATE COMPANY",name.strip()); st.success("Company added. Refresh the page.")
            except sqlite3.IntegrityError: st.error("Company name already exists.")
    else: st.info("Only administrators can create companies or bank accounts.")
    st.subheader("Bank account register")
    st.dataframe(qdf("""SELECT c.name Company,a.bank_name Bank,a.account_title Account,a.account_number Account_No,a.gl_code GL_Code,
                      a.opening_bank Opening_Bank,a.opening_book Opening_Books,a.active Active
                      FROM accounts a JOIN companies c ON c.id=a.company_id ORDER BY c.name,a.bank_name"""),use_container_width=True)
    if role=="Admin":
        companies=company_options()
        with st.form("new_account"):
            co_name=st.selectbox("Company",companies.name.tolist(),key="acct_company")
            bank_name=st.text_input("Bank name")
            title=st.text_input("Account title")
            number=st.text_input("Account number (mask sensitive digits if preferred)")
            gl=st.text_input("General ledger code")
            ob=st.number_input("Opening bank balance",value=0.0)
            ol=st.number_input("Opening book balance",value=0.0)
            add_acc=st.form_submit_button("Add bank account")
        if add_acc and bank_name and title and number:
            cid=int(companies.loc[companies.name==co_name,"id"].iloc[0])
            with connect() as c: c.execute("""INSERT INTO accounts(company_id,bank_name,account_title,account_number,gl_code,opening_bank,opening_book)
             VALUES(?,?,?,?,?,?,?)""",(cid,bank_name,title,number,gl,ob,ol))
            audit(USER["username"],"CREATE BANK ACCOUNT",f"{co_name}: {bank_name} {title}")
            st.success("Account added. Refresh the page.")


    if role == "Admin":
        st.divider()
        st.subheader("Edit company")
        companies_edit = company_options()
        if not companies_edit.empty:
            edit_company_name = st.selectbox("Company to edit", companies_edit.name.tolist(), key="edit_company_select")
            edit_company = companies_edit[companies_edit.name == edit_company_name].iloc[0]
            with st.form("edit_company_form"):
                revised_company_name = st.text_input("Company name", value=str(edit_company.name))
                revised_currency = st.selectbox("Currency", ["PKR","USD","AED","GBP","EUR"],
                                                 index=["PKR","USD","AED","GBP","EUR"].index(edit_company.currency))
                save_company = st.form_submit_button("Update company")
            if save_company:
                try:
                    with connect() as c:
                        c.execute("UPDATE companies SET name=?,currency=? WHERE id=?",
                                  (revised_company_name.strip(), revised_currency, int(edit_company.id)))
                    audit(USER["username"], "UPDATE COMPANY", f"Company #{int(edit_company.id)} updated.")
                    st.success("Company updated.")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("That company name is already in use.")

        st.subheader("Edit bank account")
        all_accounts = qdf("SELECT * FROM accounts WHERE company_id=? AND deleted_at IS NULL ORDER BY id",
                           (company_id,))
        if not all_accounts.empty:
            account_choice = st.selectbox("Account to edit",
                all_accounts.apply(lambda r: f"#{r.id} · {r.bank_name} — {r.account_title}", axis=1).tolist(),
                key="edit_account_choice")
            account_row = all_accounts.iloc[all_accounts.apply(
                lambda r: f"#{r.id} · {r.bank_name} — {r.account_title}", axis=1).tolist().index(account_choice)]
            with st.form("edit_account_form"):
                revised_bank = st.text_input("Bank name", value=str(account_row.bank_name))
                revised_title = st.text_input("Account title", value=str(account_row.account_title))
                revised_number = st.text_input("Account number", value=str(account_row.account_number))
                revised_gl = st.text_input("GL code", value=str(account_row.gl_code or ""))
                revised_open_bank = st.number_input("Opening bank balance", value=float(account_row.opening_bank or 0))
                revised_open_book = st.number_input("Opening book balance", value=float(account_row.opening_book or 0))
                revised_active = st.checkbox("Account active", value=bool(account_row.active))
                save_account = st.form_submit_button("Update bank account")
            if save_account:
                with connect() as c:
                    c.execute("""UPDATE accounts SET bank_name=?,account_title=?,account_number=?,gl_code=?,
                                 opening_bank=?,opening_book=?,active=? WHERE id=?""",
                              (revised_bank.strip(), revised_title.strip(), revised_number.strip(), revised_gl.strip(),
                               revised_open_bank, revised_open_book, int(revised_active), int(account_row.id)))
                audit(USER["username"], "UPDATE BANK ACCOUNT", f"Account #{int(account_row.id)} updated.")
                st.success("Bank account updated.")
                st.rerun()

with tabs[2]:
    st.subheader("Import statements")
    f1,f2=st.columns(2)
    for col,src,key in [(f1,"Bank","bankup"),(f2,"Books","bookup")]:
        with col:
            st.markdown(f"**{src} {'statement' if src=='Bank' else 'cashbook / general ledger'}**")
            up=st.file_uploader("Select CSV or Excel",type=["csv","xlsx","xls"],key=key)
            if up and st.button(f"Import {src}",key=f"imp_{src}",type="primary",disabled=(role=="Viewer")):
                try:
                    data=parse_file(up)
                    n=import_transactions(data,company_id,account_id,src,up.name,USER["username"])
                    st.success(f"{n} new records imported; duplicates skipped.")
                except Exception as e: st.error(str(e))
    with st.expander("Expected input columns"):
        st.write("Date is mandatory. Description/Narration and Reference/Cheque No. are recommended. Supply either signed Amount (credits positive, debits negative) or Debit and Credit columns. Dates are interpreted day-first.")

with tabs[3]:
    st.subheader("Automatic reconciliation")
    df=transactions(company_id,account_id)
    days=st.number_input("Date tolerance (days)",0,30,2)
    tol=st.number_input("Amount tolerance",0.0,1000000.0,0.0,step=1.0)
    if st.button("Run automatic matching",type="primary",disabled=(role=="Viewer")):
        n=automatic_match(df,int(days),float(tol),USER["username"])
        st.success(f"{n} match groups created. Review all results before finalizing.")
        st.rerun()
    st.markdown("**Unmatched bank entries**")
    st.dataframe(df[(df.source=="Bank")&(df.status=="Unmatched")][["id","txn_date","description","reference","debit","credit","amount"]],use_container_width=True,hide_index=True)
    st.markdown("**Unmatched company entries**")
    st.dataframe(df[(df.source.isin(["Books","Adjustment"]))&(df.status=="Unmatched")][["id","source","txn_date","description","reference","debit","credit","amount"]],use_container_width=True,hide_index=True)
    st.caption("The engine first seeks one-to-one matches, then attempts grouped matches of up to four book entries against one bank entry. Amount and date tolerances apply. It does not replace accountant review.")

with tabs[4]:
    st.subheader("Manual matching")
    df=transactions(company_id,account_id)
    open_df=df[df.status=="Unmatched"]
    if not open_df.empty:
        options=open_df.apply(lambda r:f"#{r.id} | {r.source} | {r.txn_date} | {r.description[:40]} | {r.amount:,.2f}",axis=1).tolist()
        selected=st.multiselect("Select entries that offset to zero (one bank entry may match multiple book entries)",options)
        ids=[int(x.split("|")[0].replace("#","").strip()) for x in selected]
        sel=open_df[open_df.id.isin(ids)]
        bank_total=float(sel[sel.source=="Bank"].amount.sum())
        book_total=float(sel[sel.source!="Bank"].amount.sum())
        net=round(bank_total+book_total,2)
        balancing=None
        if ids:
            m1,m2,m3=st.columns(3)
            m1.metric("Bank entries total",f"{bank_total:,.2f}")
            m2.metric("Book entries total",f"{book_total:,.2f}")
            m3.metric("Net difference",f"{net:,.2f}")
            if abs(net)<=0.01:
                st.success("Bank and book entries balance.")
            else:
                st.warning(f"Selected entries do not balance. Net difference: {net:,.2f}")
                # Detect a probable inverted sign: flipping one entry would nearly close the gap.
                scale=max(abs(bank_total),abs(book_total),1.0)
                for r in sel.itertuples():
                    flipped=round(net-2*float(r.amount),2)
                    if abs(flipped)<abs(net)/2 and abs(flipped)<=0.01*scale:
                        st.info(f"Entry #{r.id} ({r.amount:,.2f}) may have an inverted sign. With its sign reversed the "
                                f"difference would be only {flipped:,.2f}. If so, correct it in Data Management; "
                                "otherwise post a balancing entry below for the true residual.")
                if role in ("Admin","Accountant"):
                    if st.checkbox(f"Post a manual balancing entry of {-net:,.2f} to close the difference",key="bal_on"):
                        bdate=st.date_input("Balancing entry date",value=date.today(),key="bal_date")
                        bdesc=st.text_input("Reason / description (required)",key="bal_desc",
                                            placeholder="e.g. Bank charges, rounding, timing difference")
                        bref=st.text_input("Reference",key="bal_ref")
                        balancing={"date":bdate.isoformat(),"description":bdesc,"reference":bref}
                else:
                    st.info("Your role cannot post balancing entries.")
        if st.button("Confirm manual match",disabled=(role=="Viewer")):
            try:
                gid=match_group(ids,USER["username"],balancing=balancing)
                st.success(f"Matched group {gid} created."); st.rerun()
            except Exception as e: st.error(str(e))
    else: st.info("No unmatched entries.")
    st.divider()
    st.subheader("Adjustment entry")
    if role in ("Admin","Accountant"):
        with st.form("adjustment"):
            adate=st.date_input("Adjustment date",value=date.today())
            desc=st.text_input("Description")
            ref=st.text_input("Reference")
            side=st.radio("Adjustment type",["Debit (outflow)","Credit (inflow)"],horizontal=True)
            amt=st.number_input("Amount",min_value=0.01,value=1.0)
            add_adj=st.form_submit_button("Save adjustment")
        if add_adj and desc:
            signed=-float(amt) if side.startswith("Debit") else float(amt)
            with connect() as c:
                c.execute("""INSERT INTO transactions(company_id,account_id,source,txn_date,description,reference,debit,credit,amount,status,imported_at)
                 VALUES(?,?,?,?,?,?,?,?,?,'Unmatched',?)""",(company_id,account_id,"Adjustment",adate.isoformat(),desc,ref,
                 max(-signed,0),max(signed,0),signed,datetime.now().isoformat(timespec="seconds")))
            audit(USER["username"],"CREATE ADJUSTMENT",f"{desc}; amount={signed}")
            st.success("Adjustment saved. It remains unmatched until reconciled.")
    else: st.info("Your role cannot create adjustments.")
    st.subheader("Matched groups")
    groups=df[df.status=="Matched"].groupby("match_group")
    for gid,g in groups:
        with st.expander(f"{gid} · {len(g)} entries · net {g.amount.sum():,.2f}"):
            st.dataframe(g[["id","source","txn_date","description","reference","amount"]],use_container_width=True,hide_index=True)
            if role=="Admin" and st.button("Undo this match",key=f"undo_{gid}"):
                with connect() as c: c.execute("UPDATE transactions SET status='Unmatched',match_group=NULL WHERE match_group=?",(gid,))
                audit(USER["username"],"UNMATCH MATCH GROUP",gid); st.rerun()

with tabs[5]:
    st.subheader("Formal Bank Reconciliation Statement")
    df=transactions(company_id,account_id)
    acc=ac[ac.id==account_id].iloc[0]
    with st.form("brs"):
        pstart=st.date_input("Period start",value=date(date.today().year,date.today().month,1))
        pend=st.date_input("Period end",value=date.today())
        bank_close=st.number_input("Bank statement closing balance",value=float(acc.opening_bank))
        book_close=st.number_input("Company ledger closing balance",value=float(acc.opening_book))
        create=st.form_submit_button("Generate BRS",type="primary")
    if create:
        if pstart>pend: st.error("Period start must not be after period end.")
        else:
            period=df[(df.txn_date>=pstart.isoformat())&(df.txn_date<=pend.isoformat())]
            bank_un=period[(period.source=="Bank")&(period.status=="Unmatched")]
            books_un=period[(period.source.isin(["Books","Adjustment"]))&(period.status=="Unmatched")]
            # Starting from book balance: add deposits in transit (books positive), subtract outstanding payments (books negative),
            # add bank credits not in books, subtract bank debits not in books.
            deposits=books_un[books_un.amount>0].amount.sum()
            payments=books_un[books_un.amount<0].amount.sum()
            bank_credits=bank_un[bank_un.amount>0].amount.sum()
            bank_debits=bank_un[bank_un.amount<0].amount.sum()
            # Adjust the book balance for bank-originated items not yet in the ledger.
            adjusted_book=float(book_close + bank_credits + bank_debits)
            # Adjust the bank balance for deposits in transit and outstanding payments.
            adjusted_bank=float(bank_close + deposits + payments)
            summary={"bank_closing":bank_close,"book_closing":book_close,"deposits_in_transit":deposits,
                     "outstanding_payments":payments,"bank_unrecorded_credits":bank_credits,
                     "bank_unrecorded_debits":bank_debits,"adjusted_book":adjusted_book,"adjusted_bank":adjusted_bank,
                     "difference":adjusted_book-adjusted_bank}
            with connect() as c:
                c.execute("""INSERT INTO reconciliation_runs(company_id,account_id,period_start,period_end,bank_closing,book_closing,brs_adjusted,status,created_by,created_at)
                VALUES(?,?,?,?,?,?,?,'Draft',?,?)""",(company_id,account_id,pstart.isoformat(),pend.isoformat(),bank_close,book_close,adjusted_book,USER["username"],datetime.now().isoformat(timespec="seconds")))
            audit(USER["username"],"GENERATE BRS",json.dumps(summary))
            st.session_state["brs_summary"]=summary
            st.session_state["brs_period"]=(pstart.isoformat(),pend.isoformat())
            st.session_state["brs_rows"]=pd.concat([bank_un.assign(side="Bank unmatched"),books_un.assign(side="Books unmatched")])
    if "brs_summary" in st.session_state:
        s=st.session_state["brs_summary"]
        st.markdown("#### Reconciliation calculation")
        rows=[
          ["Particulars","Amount"],
          ["Bank statement closing balance",money(s["bank_closing"])],
          ["Company ledger closing balance",money(s["book_closing"])],
          ["Add: Deposits in transit (books only)",money(s["deposits_in_transit"])],
          ["Add/(Less): Outstanding payments (signed)",money(s["outstanding_payments"])],
          ["Add: Bank credits not recorded in books",money(s["bank_unrecorded_credits"])],
          ["Less: Bank debits not recorded in books",money(s["bank_unrecorded_debits"])],
          ["Adjusted book-side balance",money(s["adjusted_book"])],
          ["Adjusted bank-side balance",money(s["adjusted_bank"])],
          ["Difference (requires investigation if non-zero)",money(s["difference"])]]
        st.table(pd.DataFrame(rows[1:],columns=rows[0]))
        if abs(s["difference"])<0.01: st.success("Adjusted balances agree.")
        else: st.warning("Adjusted balances do not agree. Review classifications and source balances before approval.")
        report_rows=[["Particulars","Amount"]]+[[r[0],r[1]] for r in rows[1:]]
        pdf=make_pdf("Bank Reconciliation Statement",[
          f"Company: {company_name} | Bank account: {sel}",
          f"Period: {st.session_state['brs_period'][0]} to {st.session_state['brs_period'][1]}",
          f"Prepared by: {USER['username']} | Status: Draft"
        ],report_rows)
        st.download_button("Download BRS PDF",pdf,"bank_reconciliation_statement.pdf","application/pdf")
        detail=st.session_state.get("brs_rows",pd.DataFrame())
        excel=make_excel(df,detail)
        st.download_button("Download Excel reconciliation workbook",excel,"bank_reconciliation_workbook.xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    st.subheader("Previous BRS runs")
    st.dataframe(qdf("SELECT id,period_start,period_end,bank_closing,book_closing,brs_adjusted,status,created_by,created_at FROM reconciliation_runs WHERE company_id=? AND account_id=? AND deleted_at IS NULL ORDER BY id DESC",(company_id,account_id)),use_container_width=True)


with tabs[6]:
    st.subheader("Transaction management")
    st.caption("Edit or move incorrect unmatched entries to the Recycle Bin. Matched entries must first be unmatched.")
    manage_df = transactions(company_id, account_id)
    if manage_df.empty:
        st.info("There are no active transactions for this account.")
    else:
        source_filter = st.selectbox("Filter source", ["All", "Bank", "Books", "Adjustment"], key="crud_source")
        status_filter = st.selectbox("Filter status", ["All", "Unmatched", "Matched"], key="crud_status")
        search_text = st.text_input("Search description or reference", key="crud_search")
        view_df = manage_df.copy()
        if source_filter != "All":
            view_df = view_df[view_df.source == source_filter]
        if status_filter != "All":
            view_df = view_df[view_df.status == status_filter]
        if search_text.strip():
            mask = (view_df.description.fillna("").str.contains(search_text, case=False, na=False) |
                    view_df.reference.fillna("").str.contains(search_text, case=False, na=False))
            view_df = view_df[mask]
        st.dataframe(view_df[["id","source","txn_date","description","reference","debit","credit","amount","status","match_group"]],
                     use_container_width=True, hide_index=True)
        if not view_df.empty:
            selected_id = st.selectbox("Select transaction to edit or delete",
                                       view_df.id.astype(int).tolist(), key="crud_txn_id")
            selected_row = manage_df[manage_df.id == selected_id].iloc[0]
            st.markdown(f"**Selected:** #{selected_id} · {selected_row.source} · {selected_row.status}")
            if selected_row.status == "Matched":
                st.warning("This transaction belongs to a match group. Undo that group in Manual Match & Adjustments before editing or deleting.")
            with st.form("edit_transaction_form"):
                edit_date = st.date_input("Transaction date", value=pd.to_datetime(selected_row.txn_date).date())
                edit_desc = st.text_input("Description", value=str(selected_row.description or ""))
                edit_ref = st.text_input("Reference", value=str(selected_row.reference or ""))
                edit_debit = st.number_input("Debit", min_value=0.0, value=float(selected_row.debit or 0), format="%.2f")
                edit_credit = st.number_input("Credit", min_value=0.0, value=float(selected_row.credit or 0), format="%.2f")
                save_txn = st.form_submit_button("Save transaction changes",
                                                 disabled=(role == "Viewer" or selected_row.status == "Matched"))
            if save_txn:
                try:
                    update_transaction(selected_id, edit_date, edit_desc, edit_ref,
                                       edit_debit, edit_credit, USER["username"])
                    st.success("Transaction updated.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
            with st.form("trash_transaction_form"):
                confirm_trash = st.checkbox(f"Move transaction #{selected_id} to Recycle Bin")
                trash_txn = st.form_submit_button("Move to Recycle Bin",
                                                  disabled=(role == "Viewer" or selected_row.status == "Matched"))
            if trash_txn and confirm_trash:
                try:
                    soft_delete_transaction(selected_id, USER["username"])
                    st.success("Transaction moved to Recycle Bin.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

    st.divider()
    st.subheader("Recycle Bin")
    st.caption("Deleted transactions are retained in the database and can be restored by an Admin.")
    if role == "Admin":
        trash_df = qdf("""SELECT id,source,txn_date,description,reference,debit,credit,amount,deleted_at
                          FROM transactions WHERE company_id=? AND account_id=? AND deleted_at IS NOT NULL
                          ORDER BY deleted_at DESC""", (company_id, account_id))
        if trash_df.empty:
            st.info("Recycle Bin is empty for this account.")
        else:
            st.dataframe(trash_df, use_container_width=True, hide_index=True)
            restore_id = st.selectbox("Select deleted transaction to restore",
                                      trash_df.id.astype(int).tolist(), key="restore_txn_id")
            if st.button("Restore selected transaction", type="primary"):
                try:
                    restore_transaction(restore_id, USER["username"])
                    st.success("Transaction restored.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
    else:
        st.info("Only Admin users can restore deleted transactions.")

    st.divider()
    st.subheader("Reconciliation draft management")
    runs = qdf("""SELECT id,period_start,period_end,bank_closing,book_closing,status,created_by,created_at
                  FROM reconciliation_runs WHERE company_id=? AND account_id=? AND deleted_at IS NULL
                  ORDER BY id DESC""", (company_id, account_id))
    st.dataframe(runs, use_container_width=True, hide_index=True)
    drafts = runs[runs.status == "Draft"] if not runs.empty else runs
    if not drafts.empty and role != "Viewer":
        run_id = st.selectbox("Select Draft BRS to modify", drafts.id.astype(int).tolist(), key="edit_brs_id")
        run = drafts[drafts.id == run_id].iloc[0]
        with st.form("edit_brs_form"):
            new_start = st.date_input("Period start", value=pd.to_datetime(run.period_start).date(), key="edit_brs_start")
            new_end = st.date_input("Period end", value=pd.to_datetime(run.period_end).date(), key="edit_brs_end")
            new_bank = st.number_input("Bank closing balance", value=float(run.bank_closing or 0), key="edit_brs_bank")
            new_books = st.number_input("Book closing balance", value=float(run.book_closing or 0), key="edit_brs_books")
            save_brs = st.form_submit_button("Update Draft BRS")
        if save_brs:
            try:
                update_brs(run_id, new_start, new_end, new_bank, new_books, USER["username"])
                st.success("Draft BRS updated. Generate a fresh report from BRS & Reports to recalculate.")
                st.rerun()
            except Exception as e:
                st.error(str(e))
        with st.form("trash_brs_form"):
            confirm_brs = st.checkbox(f"Move Draft BRS #{run_id} to Recycle Bin")
            delete_brs = st.form_submit_button("Move Draft BRS to Recycle Bin")
        if delete_brs and confirm_brs:
            try:
                soft_delete_brs(run_id, USER["username"])
                st.success("Draft BRS moved to Recycle Bin.")
                st.rerun()
            except Exception as e:
                st.error(str(e))
    elif role == "Viewer":
        st.info("View-only access.")

with tabs[7]:
    st.subheader("User accounts and permissions")
    if role=="Admin":
        with st.form("new_user"):
            nu=st.text_input("New username")
            np=st.text_input("Temporary password",type="password")
            nr=st.selectbox("Role",["Accountant","Viewer","Admin"])
            create_user=st.form_submit_button("Create user")
        if create_user and nu.strip() and len(np)>=10:
            try:
                with connect() as c: c.execute("INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,?,?)",
                    (nu.strip(),pw_hash(np),nr,1,datetime.now().isoformat(timespec="seconds")))
                audit(USER["username"],"CREATE USER",f"{nu.strip()} role={nr}"); st.success("User created.")
            except sqlite3.IntegrityError: st.error("Username already exists.")
        elif create_user: st.error("Enter a username and a password of at least 10 characters.")
        users=qdf("SELECT id,username,role,active,created_at FROM users ORDER BY username")
        st.dataframe(users,use_container_width=True,hide_index=True)
        st.markdown("**Change user role / deactivate**")
        if not users.empty:
            target=st.selectbox("User",users.username.tolist())
            target_row=users[users.username==target].iloc[0]
            new_role=st.selectbox("New role",["Admin","Accountant","Viewer"],index=["Admin","Accountant","Viewer"].index(target_row.role))
            active=st.checkbox("Account active (uncheck to deactivate)",value=bool(target_row.active))
            if st.button("Update user"):
                if target==USER["username"] and (not active or new_role!="Admin"): st.error("You cannot deactivate or demote your own active administrator session.")
                else:
                    with connect() as c: c.execute("UPDATE users SET role=?,active=? WHERE username=?",(new_role,int(active),target))
                    audit(USER["username"],"UPDATE USER",f"{target}; role={new_role}; active={active}"); st.success("User updated.")
        st.markdown("**Reset your password**")
        with st.form("change_pw"):
            old=st.text_input("Current password",type="password")
            new=st.text_input("New password (minimum 10 characters)",type="password")
            cp=st.form_submit_button("Change password")
        if cp:
            with connect() as c: row=c.execute("SELECT password_hash FROM users WHERE username=?",(USER["username"],)).fetchone()
            if row and pw_ok(old,row["password_hash"]) and len(new)>=10:
                with connect() as c: c.execute("UPDATE users SET password_hash=? WHERE username=?",(pw_hash(new),USER["username"]))
                audit(USER["username"],"CHANGE PASSWORD","Password changed"); st.success("Password changed.")
            else: st.error("Current password incorrect or new password too short.")
    else: st.info("Only administrators can manage user accounts.")
    st.subheader("Audit log")
    logs=qdf("SELECT created_at,username,action,detail FROM audit_log ORDER BY id DESC LIMIT 500")
    st.dataframe(logs,use_container_width=True,hide_index=True)
    st.download_button("Export audit log CSV",logs.to_csv(index=False).encode("utf-8-sig"),"audit_log.csv","text/csv")

with tabs[8]:
    st.subheader("Database backup and restore")
    st.write("Backup includes companies, accounts, transactions, user accounts, reconciliation runs and audit history.")
    if role=="Admin":
        if st.button("Prepare database backup",type="primary"):
            backup=io.BytesIO()
            with zipfile.ZipFile(backup,"w",zipfile.ZIP_DEFLATED) as z:
                if DB_PATH.exists(): z.write(DB_PATH,arcname="reconciliation.db")
                z.writestr("backup_manifest.json",json.dumps({"created_at":datetime.now().isoformat(),"application":"Bank Reconciliation Pro"},indent=2))
            st.download_button("Download full backup ZIP",backup.getvalue(),f"bank_reconciliation_backup_{date.today().isoformat()}.zip","application/zip")
        restore=st.file_uploader("Restore from backup ZIP (replaces current database)",type=["zip"])
        confirm=st.checkbox("I understand restore replaces all current application data.")
        if restore and confirm and st.button("Restore database",type="secondary"):
            try:
                with zipfile.ZipFile(restore) as z:
                    if "reconciliation.db" not in z.namelist(): raise ValueError("Backup ZIP does not contain reconciliation.db.")
                    payload=z.read("reconciliation.db")
                # Validate database before replacing live file.
                tmp=Path("restore_validation.db"); tmp.write_bytes(payload)
                test=sqlite3.connect(tmp); test.execute("PRAGMA integrity_check"); test.close()
                shutil.copy2(DB_PATH,DB_PATH.with_suffix(".pre_restore.bak")) if DB_PATH.exists() else None
                DB_PATH.write_bytes(payload); tmp.unlink(missing_ok=True)
                push_to_mongo()
                st.success("Database restored. Sign in again."); st.session_state.clear(); st.rerun()
            except Exception as e: st.error(f"Restore failed: {e}")
    else: st.info("Only administrators can back up or restore the database.")
    st.warning("Backups contain financial records and user password hashes. Store them securely and restrict access.")
