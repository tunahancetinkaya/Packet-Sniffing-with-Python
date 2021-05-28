import sqlite3

def sil():
    db = sqlite3.connect("veritabani.db")
    cursor = db.cursor()
    command = ''' DROP table veri '''
    results = cursor.execute(command)
    cursor.execute("""CREATE TABLE IF NOT EXISTS veri
    (no, ip_src, ip_dst, protocol, length, info)""")

sil()