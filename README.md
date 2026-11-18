# NetPulse // Network Traffic & PCAP Analyzer

Aplikasi web sederhana berbasis **Python (Flask)** dan **Scapy** untuk memantau lalu lintas jaringan lokal secara langsung (*live sniffing*) maupun menganalisis file dump jaringan dari Wireshark (`.pcap`, `.pcapng`, `.cap`), memvisualisasikan statistik paket data, mendeteksi anomali trafik secara otomatis, serta menampilkan log aktivitas jaringan.

## Fitur Utama

- **Live Packet Capture Lokal:** Menangkap paket lalu lintas jaringan secara langsung dari interface jaringan lokal menggunakan **Scapy**, dilengkapi pemilihan interface, pengaturan durasi tangkapan (1â€“30 detik), batas jumlah paket (1â€“500 paket), serta dukungan **BPF Filter** (misalnya `tcp port 80`, `icmp`, `host 192.168.1.1`).
- **Upload & Analisis File PCAP:** Mendukung unggahan tangkapan paket Wireshark (`.pcap`, `.pcapng`, `.cap`) hingga 32 MB untuk dianalisis secara instan.
- **Statistik Paket & Protokol:** Menampilkan total paket, total volume byte, durasi tangkapan, rata-rata paket per detik (`pkt/s`), jumlah host/IP unik, grafik distribusi protokol (`HTTP`, `HTTPS/TLS`, `DNS`, `SSH`, `TCP`, `UDP`, `ICMP`, `ARP`), serta daftar *Top Source & Destination IP*.
- **Deteksi Anomali Sederhana:**
  - **Traffic Spike:** Mendeteksi lonjakan volume paket per detik yang melampaui ambang batas rata-rata.
  - **Port Scanning:** Mendeteksi satu alamat IP yang memindai banyak port tujuan berbeda dalam satu sesi.
  - **SYN Burst / Flood:** Mendeteksi pengiriman paket TCP `SYN` tanpa `ACK` secara berlebihan.
  - **ARP Storm / Spoof Risk:** Mendeteksi lonjakan paket ARP dari satu sumber.
- **Log Aktivitas Paket Interaktif:** Tabel log detail (waktu, IP asal, IP tujuan, protokol, ukuran paket, dan informasi port/flag) yang dilengkapi kolom pencarian instan.
- **Mode Demo Data:** Dilengkapi simulasi data bawaan sehingga dashboard dapat langsung diuji tanpa harus menyiapkan file PCAP atau hak akses sniffer.

## Tech Stack

- **Backend:** Python 3, Flask, Scapy
- **Frontend:** HTML5, Tailwind CSS, Chart.js, JavaScript (Fetch API)

## Prasyarat Sistem (Untuk Fitur Live Capture)

- **Windows:** Memerlukan driver **Npcap** (instal dengan opsi *WinPcap API-compatible Mode*) dan menjalankan terminal/VS Code sebagai **Administrator**.
- **Linux / macOS:** Memerlukan **libpcap** dan menjalankan server dengan hak akses **sudo / root** (atau memberikan capability `cap_net_raw` pada binary Python).

> *Catatan: Fitur **Upload File PCAP** dan **Mode Demo Data** tetap dapat berjalan normal tanpa hak akses Administrator/root.*

## Cara Menjalankan

1. **Clone repositori:**
   ```bash
   git clone [https://github.com/Iqbalarbani/Network-Packet-Analyzer-Security-Log-Dashboard.git](https://github.com/Iqbalarbani/Network-Packet-Analyzer-Security-Log-Dashboard.git)
   cd Network-Packet-Analyzer-Security-Log-Dashboard
   ```

2. **Install dependensi:**
   ```bash
   python -m pip install -r requirements.txt
   ```

3. **Jalankan aplikasi:**
   ```bash
   python app.py
   ```

4. **Buka di browser:**
   Akses `http://127.0.0.1:5000`

## License

MIT License Â© 2026
