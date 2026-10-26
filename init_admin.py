"""Run once locally to create first administrator; never commit credentials."""
import getpass,sqlite3
from auth import conn,create_user
with conn() as db:
    existing=db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
if existing:
    raise SystemExit('Database sudah berisi pengguna. Buat akun lain melalui panel admin.')
username=input('Username administrator: ').strip()
name=input('Nama administrator: ').strip()
password=getpass.getpass('Password kuat (minimal 12 karakter): ')
repeat=getpass.getpass('Ulangi password: ')
if password!=repeat: raise SystemExit('Password tidak cocok.')
try:
    create_user(username,name,password,'admin')
except (ValueError,sqlite3.Error) as e:
    raise SystemExit(str(e))
print('Administrator berhasil dibuat. Jalankan Streamlit untuk login.')
