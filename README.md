# 🔗 ShortURL – Simple URL Shortener

ShortURL adalah layanan pemendek tautan ringan berbasis Express.js yang di-deploy menggunakan **Vercel**, lengkap dengan antarmuka pengguna yang intuitif, pelacakan statistik, QR code, dan proteksi tautan dengan kata sandi.

Dibuat untuk kebutuhan pribadi maupun bisnis kecil yang menginginkan kontrol penuh atas tautan pendek mereka — tanpa iklan, tanpa pelacakan pihak ketiga.

---

## 🚀 Fitur Utama

- ✂️ Buat tautan pendek dalam sekejap  
- 📊 Lihat statistik klik real-time  
- 🖼️ Hasilkan QR code instan untuk setiap tautan  
- 🔒 Lindungi tautan dengan kata sandi opsional  
- 🌐 Antarmuka web responsif & modern  
- ☁️ Deploy instan di Vercel (serverless)

---

## 📁 Struktur Proyek

```
├── views/
│   ├── index.ejs          # Halaman utama
│   ├── dashboard.ejs      # Daftar tautan pengguna
│   ├── stats.ejs          # Statistik klik
│   ├── qr.ejs             # Tampilan QR code
│   ├── password.ejs       # Form proteksi kata sandi
│   └── 404.ejs            # Halaman tidak ditemukan
├── index.js               # Entry point aplikasi Express
├── package.json
├── .env                   # Konfigurasi lingkungan (tidak di-commit)
└── README.md
```

---

## ⚙️ Cara Menjalankan di Vercel

### 1. Siapkan Database MongoDB di Vercel
1. Buka [Vercel Dashboard](https://vercel.com/dashboard)
2. Pilih proyek Anda → **Storage** → **Add Storage**
3. Pilih **MongoDB**
4. Atur koneksi dan salin **Connection String**
5. Simpan sebagai environment variable bernama `MONGODB_URL`

### 2. Tambahkan Environment Variables
Di **Vercel Project Settings > Environment Variables**, tambahkan:

| Key             | Value                          |
|-----------------|--------------------------------|
| `MONGODB_URL`   | `mongodb+srv://...` (dari MongoDB Atlas atau Vercel Storage) |
| `APP_DOMAIN`    | `https://yourdomain.vercel.app` *(atau custom domain)* |

> 💡 Pastikan `APP_DOMAIN` mencakup protokol (`https://`) agar tautan yang dihasilkan valid.

### 3. Deploy!
Push kode ke repositori GitHub yang terhubung ke Vercel — deploy otomatis akan berjalan.

---

## 🛠 Pengembangan Lokal (Opsional)

Jika ingin menjalankan di lokal:

```bash
npm install
cp .env.example .env  # lalu isi MONGODB_URL & APP_DOMAIN
npm start
```

> Catatan: `.env` tidak boleh di-commit ke repositori publik.

---

## 🎨 Desain & UX
Antarmuka dirancang dengan prinsip **modern, nyaman, dan fungsional** — fokus pada kejelasan visual dan kemudahan navigasi, tanpa elemen berlebihan.

---

Dibuat dengan ❤️ oleh [Aditia Nugraha Putra](https://ditss.store)  
Untuk pertanyaan atau kolaborasi, silakan hubungi melalui [social media](https://ditss.store/contact).
```
