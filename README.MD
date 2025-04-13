# OAuth Login Backend (Go + Fiber)

Sebuah backend sederhana menggunakan Golang, Fiber, dan OAuth2 untuk autentikasi user. Proyek ini juga mendukung login dengan email & password, serta menyimpan histori login dan token ke Redis.

## 🧹 Fitur

### 🔐 Login dengan OAuth

- Mendukung login menggunakan akun GitHub (akan ditambah provider lain di masa depan).

### 🔐 Login Manual (Email & Password)

- Pengguna dapat login menggunakan email dan password.

### ✅ Validasi Token JWT

- Menggunakan JWT untuk validasi token.

### 📂 Penyimpanan Refresh Token di Redis

- Refresh token disimpan di Redis untuk performa yang lebih cepat.

### 🛥️ Login History Tracking

- Menyimpan riwayat login pengguna.

### 🔁 Middleware Autentikasi

- Middleware yang digunakan untuk validasi autentikasi di setiap request.

### 📧 Pengiriman Email Menggunakan SMTP

- Menggunakan SMTP untuk mengirimkan email (misalnya, untuk verifikasi atau reset password).

### 🧪 Validasi Request Body

- Melakukan validasi pada request body sebelum diproses.

### 🧱 Clean Architecture

- Menggunakan arsitektur bersih (Clean Architecture) untuk pengelolaan kode yang lebih terstruktur dan maintainable.

## ⚙️ Teknologi yang Digunakan

- **Golang**
- **Fiber**
- **GORM + PostgreSQL**
- **Golang Migration**
- **Redis**
- **OAuth2 (GitHub)**
- **JWT**
- **Viper**
- **Docker**
- **SMTP (email)**

## 🏃 Cara Menjalankan

### Jalankan Web Server

Untuk menjalankan server web, gunakan perintah berikut:

```bash
go run cmd/web/main.go
```
