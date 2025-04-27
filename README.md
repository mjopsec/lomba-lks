## 📚 **REKAP MATERI & KONFIGURASI LKS CYBER SECURITY 2024**

### Update Repositori

Buat dan backup file konfigurasi repositori
```bash
mkdir -p /etc/yum.repos.d/old
mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/old/
```
Buat file untuk repositori Centos:
```
nano /etc/yum.repos.d/CentOS.repo
```

Masukan repositori berikut:
```
[base]
name=CentOS-7.9.2009 - Base
baseurl=http://vault.centos.org/7.9.2009/os/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
metadata_expire=never
 
#released updates
[updates]
name=CentOS-7.9.2009 - Updates
baseurl=http://vault.centos.org/7.9.2009/updates/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
metadata_expire=never
 
# additional packages that may be useful
[extras]
name=CentOS-7.9.2009 - Extras
baseurl=http://vault.centos.org/7.9.2009/extras/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=1
metadata_expire=never
 
# additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-7.9.2009 - CentOSPlus
baseurl=http://vault.centos.org/7.9.2009/centosplus/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=0
metadata_expire=never
 
#fasttrack - packages by Centos Users
[fasttrack]
name=CentOS-7.9.2009 - Contrib
baseurl=http://vault.centos.org/7.9.2009/fasttrack/$basearch/
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
enabled=0
metadata_expire=never
```

Buat file repo untuk epel
```
nano /etc/yum.repos.d/epel.repo
```

Lalu masukan repositori berikut ini:
```
[epel]
name=Extra Packages for Enterprise Linux 7 - $basearch
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
metadata_expire=never
 
[epel-debuginfo]
name=Extra Packages for Enterprise Linux 7 - $basearch - Debug
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/$basearch/debug
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=1
metadata_expire=never
 
[epel-source]
name=Extra Packages for Enterprise Linux 7 - $basearch - Source
baseurl=https://archives.fedoraproject.org/pub/archive/epel/7/SRPMS
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=1
metadata_expire=never
```

Cek konfigurasi
```
yum clean all
```
```
yum check-update
```

Tambahkan GPG Key Untuk CentOS 7

```
curl -o /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7 https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7
```

---

### **1. Linux Hardening**
📌 *Goal:* Meningkatkan keamanan sistem Linux dari eksploitasi umum

#### Materi & Konfigurasi:

| Sub Materi | Tujuan | Tools/Command |
|------------|--------|----------------|
| Host Info | Melihat dan mencatat detail sistem | `uname -a`, `hostnamectl`, `ifconfig`, `df -h` |
| Disk Encryption | Enkripsi partisi | `cryptsetup luksFormat /dev/sdX`, `cryptsetup luksOpen`, `mkfs.ext4`, `mount` |
| Closed Unusual Ports | Menutup port tidak dikenal | `netstat -tuln`, `ss`, `firewalld`, `iptables`, `ufw` |
| Whitelisting SELinux | Mengatur SELinux untuk hanya mengizinkan trusted apps | `sestatus`, `setenforce 1`, `semanage` |
| CHROOT Shell | Membatasi shell user ke direktori tertentu | `chroot /home/user/`, `debootstrap` |
| Certificate Shell Login | Login hanya jika memiliki sertifikat | `ssh-keygen`, `ssh-copy-id`, `sshd_config` (set `PasswordAuthentication no`) |
| Directory Listing | Mencegah directory listing di Apache | `Options -Indexes` dalam `/etc/httpd/conf.d/` |
| Remote Command Exec | Cegah remote exec via curl/wget | Audit `cron`, `rc.local`, `.bashrc`, juga mod_security rules |

---
Good catch MJ! Memang penjelasan sebelumnya masih kurang dalam pada **konfigurasi client** untuk **OpenVPN** dan **PGP**. Sekarang aku lengkapi langkah-langkahnya **secara detail dari sisi server dan client**, supaya bisa langsung kamu bawa ke lab anak-anak tanpa bingung.

---

## 🛡️ OPENVPN - SERVER & CLIENT SETUP

### 🎯 *Goal: Client bisa terhubung ke server VPN secara aman menggunakan sertifikat*

---

### ✅ **1. SERVER SIDE - OpenVPN Server (CentOS 7)**

#### Langkah 1: Install OpenVPN & Easy-RSA
```bash
yum install epel-release -y
yum install openvpn easy-rsa -y
```

#### Langkah 2: Setup PKI
```bash
cd /etc/openvpn/
mkdir easy-rsa
cp -r /usr/share/easy-rsa/3/* easy-rsa/
cd easy-rsa
./easyrsa init-pki
./easyrsa build-ca nopass
```

#### Langkah 3: Generate Server Cert & Key
```bash
./easyrsa gen-req server nopass
./easyrsa sign-req server server
```

#### Langkah 4: Generate Client Cert
```bash
./easyrsa gen-req client1 nopass
./easyrsa sign-req client client1
```

#### Langkah 5: Generate DH dan TLS-Auth
```bash
./easyrsa gen-dh
openvpn --genkey --secret ta.key
```

#### Langkah 6: Copy semua file ke `/etc/openvpn/`
```bash
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem ta.key /etc/openvpn/
```

#### Langkah 7: Buat file config server
```bash
vim /etc/openvpn/server.conf
```

Isi:
```conf
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
server 10.8.0.0 255.255.255.0
persist-key
persist-tun
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
```

#### Langkah 8: Enable & Start
```bash
systemctl enable openvpn@server
systemctl start openvpn@server
```

#### Langkah 9: Aktifkan IP Forwarding
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
Dan permanenkan di `/etc/sysctl.conf`:
```conf
net.ipv4.ip_forward = 1
```

---

### ✅ **2. CLIENT SIDE - Linux / Windows**

#### Copy dari server ke client:
- `ca.crt`
- `client1.crt`
- `client1.key`
- `ta.key`

#### Buat config `client.ovpn`:
```conf
client
dev tun
proto udp
remote <IP_SERVER> 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client1.crt
key client1.key
tls-auth ta.key 1
cipher AES-256-CBC
verb 3
```

Letakkan semua file di direktori:
- Linux: `~/.openvpn/`
- Windows: `C:\Program Files\OpenVPN\config\`

#### Jalankan:
- Linux: `sudo openvpn --config client.ovpn`
- Windows: klik kanan “Run as administrator” pada GUI OpenVPN

---

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

---

### **4. IDS: Snort / Suricata**
📌 *Goal:* Mendeteksi SQLi, Brute Force, XSS

#### Konfigurasi:
```bash
yum install snort -y
snort -c /etc/snort/snort.conf -A console -i eth0
```

#### Latihan:
- Simulasi SQLi: `sqlmap -u "http://target.com/page.php?id=1"`
- Rule Tambahan: Tambahkan di `/etc/snort/rules/local.rules`

---

### **5. Web Protection: ModSecurity & ModEvasive**
📌 *Goal:* Mencegah DoS dan input berbahaya ke server

#### Instalasi:
```bash
yum install mod_security mod_evasive -y
systemctl restart httpd
```

#### Konfigurasi:
- ModEvasive:
```conf
DOSHashTableSize 3097
DOSPageCount 2
DOSSiteCount 50
```
- Uji dengan `ab -n 1000 -c 100 http://localhost/`

---

### **6. Security Headers (Apache)**
📌 *Goal:* Menambal header yang lemah agar tidak bisa di-exploit

#### Konfigurasi:
Tambahkan di `/etc/httpd/conf/httpd.conf` atau `.htaccess`:
```apache
Header always set Strict-Transport-Security "max-age=31536000"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "no-referrer"
Header always set Permissions-Policy "camera=(), microphone=()"
Header always set Content-Security-Policy "default-src 'self'"
```

---

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
