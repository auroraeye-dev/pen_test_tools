"""
Tiny SQL DDL reader for MockDBX: turns CREATE DATABASE / USE / CREATE TABLE
statements into {database: {table: [column definitions]}}. Structure only.
Anything else (INSERT, CREATE INDEX, views, procedures...) is skipped, so a
real-world schema dump can be dropped in without editing.
"""

import re
from pathlib import Path

_IDENT = r"[`\"\[]?([\w$]+)[`\"\]]?"
_CREATE_DB = re.compile(rf"^CREATE\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+NOT\s+EXISTS\s+)?{_IDENT}", re.I)
_USE = re.compile(rf"^USE\s+{_IDENT}", re.I)
_CREATE_TABLE = re.compile(
    rf"^CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    rf"(?:{_IDENT}\.)?{_IDENT}\s*\((.*)\)[^)]*$",
    re.I | re.S,
)
DEFAULT_DB = "main"


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"(--|#)[^\n]*", " ", sql)


def _split_top_level(body: str, sep: str):
    parts, depth, quote, cur = [], 0, None, []
    for ch in body:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur))
    return [" ".join(p.split()) for p in parts if p.strip()]


def parse_sql(sql: str, schema: dict, current_db: str = DEFAULT_DB) -> str:
    for stmt in _split_top_level(_strip_comments(sql), ";"):
        if m := _CREATE_DB.match(stmt):
            schema.setdefault(m.group(1), {})
        elif m := _USE.match(stmt):
            current_db = m.group(1)
            schema.setdefault(current_db, {})
        elif m := _CREATE_TABLE.match(stmt):
            db = m.group(1) or current_db
            schema.setdefault(db, {})[m.group(2)] = _split_top_level(m.group(3), ",")
    return current_db


def load_schema(folder) -> dict:
    schema: dict = {}
    for path in sorted(Path(folder).glob("*.sql")):
        parse_sql(path.read_text(encoding="utf-8", errors="replace"), schema)
    return {db: tables for db, tables in schema.items() if tables} or {DEFAULT_DB: {}}
