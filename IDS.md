# Dokumentasi Instalasi dan Konfigurasi Snort di CentOS 7

## 1. Requirement
Install paket yang dibutuhkan:

```bash
yum -y install gcc epel-release flex bison zlib libdnet-devel dnf
```

Cek apakah paket sudah terinstall:

```bash
rpm -qa | grep -E 'flex|bison|gcc|epel|zlib|libdnet'
```

---

## 2. Instalasi Snort
Setelah semua requirement terinstall, lanjutkan dengan menginstall Snort:

```bash
dnf install https://www.snort.org/downloads/snort/snort-2.9.20-1.centos.x86_64.rpm -y
```

Update shared library cache:

```bash
ldconfig
```

Buat hard link untuk file Snort:

```bash
ln -s /usr/lib64/libdnet.so.1.0.1 /usr/lib64/libdnet.1
```

Verifikasi instalasi Snort:

```bash
snort -v
```

---

## 3. Konfigurasi Snort di CentOS 7

Membuat Folder dan Mengatur Permission
```bash
mkdir -p /etc/snort/rules && mkdir -p /var/log/snort && mkdir -p /usr/local/lib/snort_dynamicrules && chmod -R 5755 /etc/snort && chmod -R 5755 /var/log/snort && chmod -R 5755 /usr/local/lib/snort_dynamicrules && chown -R snort:snort /var/log/snort && chown -R snort:snort /usr/local/lib/snort_dynamicrules && touch /etc/snort/rules/white_list.rules && touch /etc/snort/rules/black_list.rules && touch /etc/snort/rules/local.rules
```

Mengedit Konfigurasi `snort.conf`
Edit file `/etc/snort/snort.conf` menggunakan editor favorit kamu (contoh: `nano` atau `vi`):

```bash
nano /etc/snort/snort.conf
```

Lakukan perubahan berikut:

- Ganti `ipvar HOME_NET any` menjadi:

  ```bash
  ipvar HOME_NET [192.168.17.0/24]
  ```

- Ubah path rules:

  ```bash
  var RULE_PATH /etc/snort/rules
  var WHITE_LIST_PATH /etc/snort/rules
  var BLACK_LIST_PATH /etc/snort/rules
  ```

- Comment semua `include` rules, **kecuali**:

  ```bash
  include $RULE_PATH/local.rules
  ```

Cek Validasi Konfigurasi
```bash
snort -T -c /etc/snort/snort.conf
```

Menjalankan Snort di Background
```bash
snort -D -c /etc/snort/snort.conf -l /var/log/snort/
```

---

## 4. Mengaktifkan Snort Secara Manual

```bash
snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i <nama-interface>
```
Contoh interface: `eth0`, `ens33`, `enp0s3`, dll.

---

## 5. Menambahkan Aturan ke `local.rules`

Edit file `local.rules`:

```bash
nano /etc/snort/rules/local.rules
```

Tambahkan rules berikut:

### 5.1 SQL Injection Detection

```bash
alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "%27"; sid:100000011;)
alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "22"; sid:100000012;)
alert tcp any any -> any 80 (msg: "AND SQL Injection Detected"; content: "and"; nocase; sid:100000060;)
alert tcp any any -> any 80 (msg: "OR SQL Injection Detected"; content: "or"; nocase; sid:100000061;)
alert tcp any any -> any 80 (msg: "Form Based SQL Injection Detected"; content: "%27"; sid:1000003;)
alert tcp any any -> any 80 (msg: "Order by SQL Injection"; content: "order"; sid:1000005;)
alert tcp any any -> any 80 (msg: "UNION SELECT SQL Injection"; content: "union"; sid:1000006;)
```

### 5.2 Brute Force Attack Detection

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg: "Brute Force Detected"; sid:10; rev:1;)
```

### 5.3 XSS Attack Detection

```bash
alert tcp any any -> any any (msg:"XSS Attack"; content:"script"; sid:10000007; rev:002;)
alert tcp any any -> $HOME_NET any (msg:"XSS Attack"; content:"img"; sid:10000002; rev:002;)
alert tcp any any -> $HOME_NET any (msg:"XSS Attack"; content:"%3C"; sid:10000003; rev:002;)
alert tcp any any -> $HOME_NET any (msg:"XSS Attack"; content:"%3E"; sid:10000004; rev:002;)
alert tcp any any -> $HOME_NET any (msg:"XSS Attack"; content:"%22"; sid:10000005; rev:002;)
alert tcp any any -> $HOME_NET any (msg:"XSS Attack"; content:"%27"; sid:10000006; rev:002;)
```

---

## 6. Restart Snort

```bash
systemctl daemon-reload && systemctl start snortd && systemctl status snortd
```