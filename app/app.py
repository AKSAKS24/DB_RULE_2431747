from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import re
import json

app = FastAPI(
    title="ABAP DB Operation Remediator for S/4HANA Obsolete FI/CO Tables (Note 2431747)"
)

TABLE_MAPPING = {
    "BSIS": {"source": "BSEG", "view": True},
    "BSAS": {"source": "BSEG", "view": True},
    "BSIK": {"source": "BSEG", "view": True},
    "BSAK": {"source": "BSEG", "view": True},
    "BSID": {"source": "BSEG", "view": True},
    "BSAD": {"source": "BSEG", "view": True},
    "GLT0": {"source": "ACDOCA/BSEG", "view": True},
    "COEP": {"source": "ACDOCA", "view": True},
    "COSP": {"source": "ACDOCA", "view": True},
    "COSS": {"source": "ACDOCA", "view": True},
    "MLIT": {"source": "ACDOCA", "view": True},
    "ANEP": {"source": "ACDOCA", "view": True},
    "ANLP": {"source": "ACDOCA", "view": True},
}
NO_VIEW_TABLES = {"FAGLFLEXA", "FAGLFLEXT"}

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

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""


def get_replacement_table(table: str) -> str:
    t_up = table.upper()
    if t_up in NO_VIEW_TABLES:
        return "ACDOCA"
    elif t_up in TABLE_MAPPING:
        return TABLE_MAPPING[t_up]["source"].split("/")[0]
    return table


def remediation_comment(table: str, stmt_type: str) -> str:
    t_up = table.upper()
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
    return re.sub(rf"\bFROM\s+{table}\b",
                  f"FROM {rep_table} {comment}", sel_text, flags=re.IGNORECASE).strip()


def remediate_other(stmt: str, stmt_type: str, table: str) -> str:
    rep_table = get_replacement_table(table)
    comment = remediation_comment(table, stmt_type)
    if stmt_type in ("DELETE", "SELECT"):
        return re.sub(rf"({stmt_type}\s+FROM\s+{table})",
                      rf"{stmt_type} FROM {rep_table} {comment}", stmt, flags=re.IGNORECASE).strip()
    else:
        return re.sub(rf"({stmt_type}\s+){table}\b",
                      rf"\1{rep_table} {comment}", stmt, flags=re.IGNORECASE).strip()


@app.post("/remediate-array")
def remediate_array(units: List[Unit]):
    results = []
    for u in units:
        src = u.code or ""
        selects_metadata = []

        # SELECT
        for m in SELECT_RE.finditer(src):
            table = m.group("table")
            if table.upper() in TABLE_MAPPING or table.upper() in NO_VIEW_TABLES:
                sel_info = {
                    "table": table,
                    "target_type": "itab" if m.group("into_tab") else "wa",
                    "target_name": (m.group("into_tab") or m.group("into_wa")),
                    "start_char_in_unit": m.span(0)[0],
                    "end_char_in_unit": m.span(0)[1],
                    "used_fields": [],
                    "ambiguous": False,
                    "suggested_fields": None,
                    "suggested_statement": remediate_select(m.group("full"), table)
                }
                selects_metadata.append(sel_info)

        # Others
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
                    if table.upper() in TABLE_MAPPING or table.upper() in NO_VIEW_TABLES:
                        sel_info = {
                            "table": table,
                            "target_type": None,
                            "target_name": None,
                            "start_char_in_unit": m.span(1)[0],
                            "end_char_in_unit": m.span(1)[1],
                            "used_fields": [],
                            "ambiguous": False,
                            "suggested_fields": None,
                            "suggested_statement": remediate_other(stmt_text, stmt_type, table)
                        }
                        selects_metadata.append(sel_info)

        obj = json.loads(u.model_dump_json())
        obj["selects"] = selects_metadata
        results.append(obj)

    return results