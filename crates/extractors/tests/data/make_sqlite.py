#!/usr/bin/env python3
"""Generate the SQLite test databases next to this script.

    python3 crates/extractors/tests/data/make_sqlite.py

All values are INVENTED and match no vendor token format. The databases use
512-byte pages so a few hundred rows already need interior B-tree pages and a
1 KiB value spills into overflow pages. The expectations live in
crates/extractors/tests/sqlite.rs.
"""
import json
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))


def fresh(name, encoding="UTF-8"):
    path = os.path.join(HERE, name)
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("PRAGMA page_size = 512")
    db.execute(f"PRAGMA encoding = '{encoding}'")
    db.execute("PRAGMA journal_mode = DELETE")
    return db


def kv(db, table):
    db.execute(f"CREATE TABLE {table} (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")


# --------------------------------------------------------- state.vscdb (UTF-8)
db = fresh("state-utf8.vscdb")
kv(db, "ItemTable")
kv(db, "cursorDiskKV")
db.execute("CREATE TABLE Other (key TEXT, value TEXT)")
rows = [(f"workbench.view.{i}", json.dumps({"visible": i % 2 == 0, "size": i})) for i in range(300)]
db.executemany("INSERT INTO ItemTable VALUES (?, ?)", rows)
# A plain (non-JSON) value under a credential-like key.
db.execute("INSERT INTO ItemTable VALUES (?, ?)", ("cursorAuth/refreshToken", "rfr-0paque-Vk83mQx2Lp"))
# A transcript-like JSON value with a command.
db.execute("INSERT INTO ItemTable VALUES (?, ?)", (
    "composerData:7f3a",
    json.dumps({"conversation": [{"type": "tool", "command": "sshpass -p Sq1t3Ssh9x ssh ops@203.0.113.9"}]}),
))
# A value that spills into overflow pages, secret at the end.
big = json.dumps({"text": "filler " * 300, "command": "mysql -uroot -pOv3rfl0wPw db"})
db.execute("INSERT INTO ItemTable VALUES (?, ?)", ("aichat.big", big.encode()))
# UTF-16LE JSON blob in cursorDiskKV.
blob = json.dumps({"command": "redis-cli -a U16R3disKy7 ping"}).encode("utf-16-le")
db.execute("INSERT INTO cursorDiskKV VALUES (?, ?)", ("bubbleId:1:2", blob))
# A table the catalogue does not list: never read.
db.execute("INSERT INTO Other VALUES (?, ?)", ("x", "sshpass -p N0tL1st3d9 ssh h"))
db.commit()
db.close()

# ------------------------------------------------- state.vscdb (UTF-16 database)
db = fresh("state-utf16.vscdb", "UTF-16le")
db.execute("CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value TEXT)")
db.execute("INSERT INTO ItemTable VALUES (?, ?)", (
    "chat.session",
    json.dumps({"requests": [{"message": {"text": "run it"}, "command": "sshpass -p Ut16Db5sh ssh h"}]}),
))
db.commit()
db.close()
print("wrote state-utf8.vscdb, state-utf16.vscdb")
