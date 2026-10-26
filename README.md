# TaniCerdas Enterprise v6 — Login dan Audit Akses

## Persiapan

```bash
pip install -r requirements.txt
python init_admin.py
streamlit run app.py
```

Buat administrator menggunakan terminal interaktif. **Tidak ada password default.** Saat aplikasi berjalan, semua halaman membutuhkan username dan password. Admin bisa menambahkan pengguna, menonaktifkan akun, mengubah password pengguna dan meninjau atau mengunduh 500 log akses terakhir melalui sidebar > Administrasi pengguna.

## Apa yang tercatat?
- Login berhasil, gagal, terkunci sementara, logout, perubahan status akun dan pembuatan pengguna.
- Username, waktu UTC, serta informasi IP bila tersedia dari proxy. IP yang berasal dari header tidak terverifikasi secara mandiri.
- Catatan akses hanya untuk peristiwa autentikasi dan administrasi, **bukan pelacakan setiap klik atau kunjungan anonim**.
- Username pengguna yang masuk dapat diketahui karena tiap orang memakai akun tersendiri; jangan bagikan satu akun ke banyak orang.

## Hosting dan keamanan
- Database SQLite disimpan di `data/tanicerdas_users.sqlite3`; ubah lokasi melalui `TANICERDAS_DB_PATH` untuk memakai **volume persisten**. Pada hosting dengan filesystem sementara, data akan hilang saat restart/redeploy. Untuk produksi multi-server, ganti ke PostgreSQL atau layanan identitas terkelola (Auth0/Clerk/Supabase Auth).
- Gunakan HTTPS, atur akses file database serta backup secara aman; jangan unggah database, password, atau `.streamlit/secrets.toml` ke GitHub.
- Login ini memakai PBKDF2-SHA256 (500.000 iterasi dan salt unik); sesi login berlaku selama sesi browser Streamlit masih aktif, dan tidak menyediakan MFA/email verification. Gunakan identitas terkelola bila membutuhkan standar keamanan tingkat organisasi.
- Pembatasan 5 percobaan login gagal per username per 15 menit diterapkan pada database bersama; dapat dipakai untuk mengunci sementara username dengan mencoba password salah. Untuk layanan publik gunakan juga rate-limit di reverse proxy/WAF.
- Informasikan kebijakan privasi dan periode retensi log kepada pengguna; hindari memakai alamat IP untuk mengidentifikasi seseorang secara pasti.

## Integrasi sebelumnya
Masukkan `GEMINI_API_KEY`, `COPERNICUS_CLIENT_ID`, dan `COPERNICUS_CLIENT_SECRET` melalui environment atau Streamlit secrets. Integrasi analisis satelit bisa memiliki nilai simulasi ketika API tidak menyediakan data.
