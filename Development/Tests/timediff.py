import datetime

def days_between(d):
    d1 = datetime.datetime.strptime(d, "%Y-%m-%d %H:%M:%S")
    d2 = datetime.datetime.now()
    return abs((d2 - d1).seconds)

print(days_between('2015-02-06 23:18:48'))



import sqlite3
from datetime import datetime as dt
conn = sqlite3.connect(':memory:')
cur = conn.cursor()

print(cur.execute("select DATETIME('now','localtime')").fetchone())
