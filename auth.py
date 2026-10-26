"""Local account management for TaniCerdas. Store DB on a persistent volume in production."""
import os, sqlite3, hashlib, hmac, secrets, time, re
from pathlib import Path
from datetime import datetime, timezone
import pandas as pd
import streamlit as st

DB_PATH = Path(os.environ.get("TANICERDAS_DB_PATH", "data/tanicerdas_users.sqlite3"))
ITERATIONS = 500_000

def conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH), timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=15000")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time_utc TEXT NOT NULL, username TEXT, event TEXT NOT NULL, ip TEXT, details TEXT)")
    db.execute("CREATE INDEX IF NOT EXISTS audit_time ON audit(time_utc)")
    db.commit()
    return db

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def hash_password(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,ITERATIONS)
    return 'pbkdf2_sha256$%d$%s$%s'%(ITERATIONS,salt.hex(),digest.hex())

def verify_password(password, stored):
    try:
        method, rounds, salt, value=stored.split('$')
        if method!='pbkdf2_sha256': return False
        derived=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(rounds))
        return hmac.compare_digest(derived,bytes.fromhex(value))
    except (ValueError,TypeError): return False

def log_event(username,event,details=''):
    try:
        # Forwarded IP headers are unverified unless a trusted reverse proxy sanitizes them.
        ip = st.context.headers.get('X-Forwarded-For','') if hasattr(st,'context') else ''
    except Exception: ip = ''
    with conn() as db:
        db.execute('INSERT INTO audit(time_utc,username,event,ip,details) VALUES(?,?,?,?,?)',(now(),username,event,ip[:100],details[:300]))

def create_user(username,name,password,role='user'):
    username=username.strip().lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,40}',username): raise ValueError('Username 3–40 karakter: huruf kecil, angka, titik, garis bawah atau tanda minus.')
    if len(password)<12: raise ValueError('Password minimal 12 karakter.')
    if role not in ('admin','user'): raise ValueError('Role tidak valid.')
    if not name.strip(): raise ValueError('Nama tampilan tidak boleh kosong.')
    with conn() as db:
        db.execute('INSERT INTO users(username,display_name,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)',(username,name.strip(),hash_password(password),role,now()))
    return username

def check_login(username,password):
    username=username.strip().lower()
    with conn() as db:
        threshold=datetime.fromtimestamp(time.time()-900,timezone.utc).isoformat(timespec='seconds')
        fails=db.execute("SELECT count(*) FROM audit WHERE username=? AND event='login_failed' AND time_utc>=?",(username,threshold)).fetchone()[0]
        if fails>=5:
            log_event(username,'login_blocked')
            return None,'Terlalu banyak percobaan. Coba kembali setelah 15 menit.'
        record=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        # Match timing roughly even for non-existent users (fixed dummy hash computed during call).
        valid=verify_password(password,record['password_hash']) if record else verify_password(password,_dummy_hash())
        if not record or not valid or not record['active']:
            log_event(username,'login_failed')
            return None,'Username atau password tidak valid.'
        log_event(username,'login_success')
        return dict(record),None

@st.cache_resource
def _dummy_hash():
    return hash_password('a-password-no-one-uses')

def bootstrap_admin_from_secrets():
    """Initialize first administrator from deployment secrets only when DB is empty."""
    with conn() as db:
        existing = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if existing:
        return
    try:
        admin = st.secrets.get('bootstrap_admin', {})
        username = admin.get('username', '').strip()
        name = admin.get('display_name', '').strip()
        password = admin.get('password', '')
    except (FileNotFoundError, KeyError, AttributeError, TypeError):
        return
    if not (username and name and password):
        return
    try:
        create_user(username, name, password, 'admin')
    except sqlite3.IntegrityError:
        pass  # Another session completed initialization first.
    except ValueError:
        st.error('Konfigurasi bootstrap_admin tidak valid. Username minimal 3 karakter dan password minimal 12 karakter.')
        st.stop()

def gate():
    bootstrap_admin_from_secrets()
    with conn() as db:
        total=db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if total==0:
        st.error('Belum ada akun administrator. Jalankan: python init_admin.py')
        st.stop()
    username=st.session_state.get('auth_username')
    if username:
        with conn() as db:
            u=db.execute('SELECT username,display_name,role,active FROM users WHERE username=?',(username,)).fetchone()
        if u and u['active']:
            return dict(u)
        st.session_state.pop('auth_username',None)
    st.markdown('<div style="max-width:470px;margin:40px auto 12px;padding:32px;border:1px solid #28473E;border-radius:22px;background:#102A23"><div style="color:#34D399;font-size:12px;font-weight:700;letter-spacing:2px">TANICERDAS / SECURE ACCESS</div><h1 style="font-size:32px;color:#F1F7F3;margin:12px 0">Masuk ke Workspace</h1><p style="color:#9CB8AB">Akses platform hanya tersedia untuk pengguna terdaftar.</p></div>',unsafe_allow_html=True)
    left, center, right=st.columns([1,1.25,1])
    with center:
        with st.form('secure_login',clear_on_submit=False):
            entered=st.text_input('Username',autocomplete='username')
            password=st.text_input('Password',type='password',autocomplete='current-password')
            submit=st.form_submit_button('Masuk',type='primary',use_container_width=True)
        if submit:
            user,error=check_login(entered,password)
            if user:
                st.session_state['auth_username']=user['username']
                st.rerun()
            st.error(error)
        st.caption('Tidak memiliki akun? Hubungi administrator TaniCerdas.')
    st.stop()

def panel(user):
    st.markdown('---')
    st.caption('AKUN AKTIF')
    st.write(f"**{user['display_name']}**")
    st.caption(f"{user['username']} · {user['role'].upper()}")
    if st.button('Keluar akun',use_container_width=True):
        log_event(user['username'],'logout')
        st.session_state.pop('auth_username',None)
        st.rerun()
    if user['role'] != 'admin': return
    with st.expander('Administrasi pengguna',expanded=False):
        tabusers, tabaudit=st.tabs(['Pengguna','Riwayat akses'])
        with tabusers:
            with st.form('new_account',clear_on_submit=True):
                username=st.text_input('Username baru')
                display=st.text_input('Nama lengkap')
                pwd=st.text_input('Password sementara (min. 12 karakter)',type='password')
                role=st.selectbox('Hak akses',['user','admin'])
                add=st.form_submit_button('Tambah pengguna',use_container_width=True)
            if add:
                try:
                    created=create_user(username,display,pwd,role)
                    log_event(user['username'],'user_created',created)
                    st.success('Pengguna ditambahkan.')
                except sqlite3.IntegrityError: st.error('Username sudah dipakai.')
                except ValueError as e: st.error(str(e))
            with conn() as db:
                users=pd.read_sql_query('SELECT username,display_name,role,active,created_at FROM users ORDER BY created_at DESC',db)
            st.dataframe(users,hide_index=True,use_container_width=True)
            choices=[x for x in users['username'].tolist() if x!=user['username']]
            if choices:
                target=st.selectbox('Kelola akun',choices)
                with conn() as db:
                    active=db.execute('SELECT active FROM users WHERE username=?',(target,)).fetchone()['active']
                if st.button('Nonaktifkan akun' if active else 'Aktifkan akun',use_container_width=True):
                    with conn() as db:
                        db.execute('UPDATE users SET active=? WHERE username=?',(0 if active else 1,target))
                    log_event(user['username'],'account_status_changed',target)
                    st.rerun()
                with st.form('reset_user_password'):
                    new_pwd=st.text_input('Atur ulang password akun terpilih',type='password')
                    do_reset=st.form_submit_button('Simpan password baru')
                if do_reset:
                    if len(new_pwd)<12: st.error('Password minimal 12 karakter.')
                    else:
                        with conn() as db:
                            db.execute('UPDATE users SET password_hash=? WHERE username=?',(hash_password(new_pwd),target))
                        log_event(user['username'],'password_reset',target)
                        st.success('Password diperbarui.')
        with tabaudit:
            with conn() as db:
                logs=pd.read_sql_query('SELECT time_utc,username,event,ip,details FROM audit ORDER BY id DESC LIMIT 500',db)
            st.dataframe(logs,hide_index=True,use_container_width=True)
            st.download_button('Unduh log CSV',logs.to_csv(index=False).encode('utf-8-sig'),'riwayat_akses.csv','text/csv',use_container_width=True)
            st.caption('Waktu dalam UTC. IP hanya tersedia jika disediakan proxy; alamat IP tidak selalu mewakili satu orang.')
