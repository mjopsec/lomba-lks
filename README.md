## 📚 **REKAP MATERI & KONFIGURASI LKS CYBER SECURITY 2024**

## 🔐 PGP EMAIL - SERVER & CLIENT

PGP bukan client-server, tapi **user-to-user** berbasis **asymmetric key**.

---

### ✅ **1. GENERATE PGP KEY**

#### Di Komputer Siswa A
```bash
gpg --full-generate-key
```
Pilih:
- RSA and RSA
- 4096-bit
- No expiry
- Masukkan nama dan email

---

### ✅ **2. KIRIM PUBLIC KEY KE TEMAN**

```bash
gpg --armor --export siswaA@email.com > siswaA_pub.asc
```
Lalu kirim file `.asc` ke siswa B (via email atau flashdisk)

---

### ✅ **3. IMPORT PUBLIC KEY TEMAN**

Di Komputer Siswa B:
```bash
gpg --import siswaA_pub.asc
```

---

### ✅ **4. ENKRIPSI PESAN & KIRIM**

Misal siswa B ingin kirim ke A:
```bash
echo "Hallo MJ!" | gpg --encrypt --armor -r siswaA@email.com > pesan.asc
```

Lalu kirim `pesan.asc` ke siswa A

---

### ✅ **5. DEKRIPSI PESAN**

Siswa A terima `pesan.asc`, lalu:
```bash
gpg --decrypt pesan.asc
```

---

### ✅ **6. DIGITAL SIGNATURE (Tambahan)**

#### Tanda Tangan Pesan:
```bash
echo "Ini ditandatangani" | gpg --clearsign > signed.txt
```

#### Verifikasi:
```bash
gpg --verify signed.txt
```

### **7. Capture The Flag (CTF)**
📌 *Goal:* Mendeteksi dan mengeksploitasi kerentanan umum

#### Teknik & Tools:
| Jenis Exploit | Tools | Catatan |
|---------------|-------|---------|
| SQL Injection | `sqlmap` | `--dump`, `--dbs`, `--tables` |
| Git Exposure | `wget`, `git` | Cek `/git/config`, `.git/HEAD` |
| Path Traversal | Burp Suite, curl | `../../../../etc/passwd` |
| SSH Bypass | Simulasi manual & `hydra` | `hydra -l user -P passlist.txt ssh://IP` |
| LFI | curl | `?page=../../etc/passwd` |
| RCE | curl, bash | Simulasi payload injection di eval() atau include() |
| Priv Escalation | manual | Gunakan `linpeas.sh`, `sudo -l` |

---

### **8. Wawancara Teori**
📌 *Goal:* Pahami konsep dasar cybersecurity

#### Materi Penting:
- CIA Triad
- Perbedaan threat, vulnerability, attack
- Konsep least privilege & access control
- Ethical hacker vs blackhat
- IDS, firewall, VPN, email encryption
- User awareness
- Konsep log & audit trail

💡 *Latihan*: Simulasi tanya-jawab, latihan menjawab singkat dan tepat.

---

### **9. Dokumentasi (Wajib!)**
📌 *Goal:* Setiap aktivitas dibuktikan dengan report

#### Template:
```markdown
# [Nama Materi]

## Deskripsi
Penjelasan tentang apa yang dilakukan

## Langkah-langkah
Command yang dijalankan + screenshot

## Hasil Uji
Hasil pengujian keamanan (berhasil/tidak)

## Mitigasi
Jika ditemukan celah, cara menambalnya

## Tabel Ringkasan
| Vulnerability | Metode | Mitigasi |
```
