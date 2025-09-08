from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
import re

app = FastAPI(
    title="ABAP DB Operation Remediator for S/4HANA Obsolete FI/CO Tables (Note 2431747) — scanner style"
)

# Table mapping & config
TABLE_MAPPING = {
    "BSIS": {"source": "ACDOCA", "view": True},
    "BSAS": {"source": "ACDOCA", "view": True},
    "BSIK": {"source": "ACDOCA", "view": True},
    "BSAK": {"source": "ACDOCA", "view": True},
    "BSID": {"source": "ACDOCA", "view": True},
    "BSAD": {"source": "ACDOCA", "view": True},
    "GLT0": {"source": "ACDOCA", "view": True},
    "COEP": {"source": "ACDOCA", "view": True},
    "COSP": {"source": "ACDOCA", "view": True},
    "COSS": {"source": "ACDOCA", "view": True},
    "MLIT": {"source": "ACDOCA", "view": True},
    "ANEP": {"source": "ACDOCA", "view": True},
    "ANLP": {"source": "ACDOCA", "view": True},
}
NO_VIEW_TABLES = {"FAGLFLEXA", "FAGLFLEXT"}

# Models for input/output (payload and response)
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""

# ABAP statement regex
SELECT_RE = re.compile(
    r"""(?P<full>
            SELECT\s+(?:SINGLE\s+)?        
            (?P<fields>[\w\s,*]+)          
            \s+FROM\s+(?P<table>\w+)       
            (?P<middle>.*?)                
            (?:
                (?:INTO\s+TABLE\s+(?P<into_tab>[\w@()\->]+))
              | (?:INTO\s+(?P<into_wa>[\w@()\->]+))
            )
            (?P<tail>.*?)
        )\.""",
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
UPDATE_RE = re.compile(r"(UPDATE\s+\w+[\s\S]*?\.)", re.IGNORECASE)
DELETE_RE = re.compile(r"(DELETE\s+FROM\s+\w+[\s\S]*?\.)", re.IGNORECASE)
INSERT_RE = re.compile(r"(INSERT\s+\w+[\s\S]*?\.)", re.IGNORECASE)
MODIFY_RE = re.compile(r"(MODIFY\s+\w+[\s\S]*?\.)", re.IGNORECASE)

# Utility functions
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def get_replacement_table(table: str) -> str:
    t_up = (table or "").upper()
    if t_up in NO_VIEW_TABLES:
        return "ACDOCA"
    elif t_up in TABLE_MAPPING:
        return TABLE_MAPPING[t_up]["source"].split("/")[0]
    return table

def remediation_comment(table: str, stmt_type: str) -> str:
    t_up = (table or "").upper()
    if stmt_type in ("UPDATE", "INSERT", "MODIFY", "DELETE"):
        return "/* NOTE: Compatibility view cannot be used for write operations in S/4HANA. Use ACDOCA or source table directly. */"
    if t_up in NO_VIEW_TABLES:
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Use ACDOCA directly and map fields accordingly. */"
    elif t_up in TABLE_MAPPING:
        src = TABLE_MAPPING[t_up]["source"]
        return f"/* NOTE: {t_up} is obsolete in S/4HANA. Adapt to ACDOCA or compatibility view (source: {src}). */"
    return ""

def remediate_select(sel_text: str, table: str) -> str:
    rep_table = get_replacement_table(table)
    comment = remediation_comment(table, "SELECT")
    return re.sub(rf"\bFROM\s+{re.escape(table)}\b",
                  f"FROM {rep_table} {comment}", sel_text, flags=re.IGNORECASE).strip()

def remediate_other(stmt: str, stmt_type: str, table: str) -> str:
    rep_table = get_replacement_table(table)
    comment = remediation_comment(table, stmt_type)
    if stmt_type in ("DELETE", "SELECT"):
        return re.sub(rf"({stmt_type}\s+FROM\s+{re.escape(table)})",
                      rf"{stmt_type} FROM {rep_table} {comment}", stmt, flags=re.IGNORECASE).strip()
    else:
        return re.sub(rf"({stmt_type}\s+){re.escape(table)}\b",
                      rf"\1{rep_table} {comment}", stmt, flags=re.IGNORECASE).strip()

# Package finding record
def pack_issue(unit: Unit, issue_type: str, message: str, severity: str,
               start: int, end: int, suggestion: str, meta: dict = None):
    src = unit.code or ""
    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "class_implementation": unit.class_implementation,
        "start_line": unit.start_line,
        "end_line": unit.end_line,
        "issue_type": issue_type,
        "severity": severity,
        "line": line_of_offset(src, start),
        "message": message,
        "suggestion": suggestion,
        "snippet": snippet_at(src, start, end),
        "meta": meta or {}
    }

# Main scan logic (single unit)
def scan_unit(unit: Unit) -> dict:
    findings: List[Dict] = []
    src = unit.code or ""

    # SELECT
    for m in SELECT_RE.finditer(src):
        table = m.group("table")
        t_up = (table or "").upper()
        if t_up in TABLE_MAPPING or t_up in NO_VIEW_TABLES:
            suggestion = remediate_select(m.group("full"), table)
            msg = f"SELECT on obsolete table/view {t_up}."
            sev = "warning"
            comm = remediation_comment(table, "SELECT")
            meta = {
                "orig_table": table,
                "replacement_table": get_replacement_table(table),
                "comment_hint": comm
            }
            findings.append(pack_issue(unit, "ObsoleteTableSelect", msg, sev,
                                      m.start(), m.end(), suggestion, meta))

    # UPDATE, DELETE, INSERT, MODIFY
    for stmt_type, pattern in [
        ("UPDATE", UPDATE_RE),
        ("DELETE", DELETE_RE),
        ("INSERT", INSERT_RE),
        ("MODIFY", MODIFY_RE)
    ]:
        for m in pattern.finditer(src):
            stmt_text = m.group(1).strip()
            table_match = re.search(rf"{stmt_type}\s+(?:FROM\s+)?(\w+)", stmt_text, re.IGNORECASE)
            if table_match:
                table = table_match.group(1)
                t_up = (table or "").upper()
                if t_up in TABLE_MAPPING or t_up in NO_VIEW_TABLES:
                    suggestion = remediate_other(stmt_text, stmt_type, table)
                    msg = f"{stmt_type} on obsolete table/view {t_up}."
                    # For UPDATE, INSERT, etc., escalate warning to error
                    sev = "error" if stmt_type in ("UPDATE", "INSERT", "MODIFY", "DELETE") else "warning"
                    comm = remediation_comment(table, stmt_type)
                    meta = {
                        "orig_table": table,
                        "replacement_table": get_replacement_table(table),
                        "comment_hint": comm
                    }
                    findings.append(pack_issue(unit, f"ObsoleteTable{stmt_type.title()}", msg, sev,
                                              m.start(1), m.end(1), suggestion, meta))

    # Add findings field to the result for this unit (in same style as system code)
    res = unit.model_dump()
    res["findings"] = findings
    return res

# Orchestrator for all units
def analyze_units(units: List[Unit]) -> List[Dict]:
    out = []
    for u in units:
        out.append(scan_unit(u))
    return out

# FastAPI endpoint
@app.post("/remediate-array")
async def remediate_array(units: List[Unit]):
    return analyze_units(units)

@app.get("/health")
def health():
    return {"ok": True}