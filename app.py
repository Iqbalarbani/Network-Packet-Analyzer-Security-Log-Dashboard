from flask import Flask, render_template, jsonify, request
from scapy.all import rdpcap, sniff, get_if_list, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
from collections import Counter, defaultdict
from datetime import datetime
import tempfile
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # Limit upload 32MB

ALLOWED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}


def is_allowed_file(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS


def classify_protocol(pkt):
    if pkt.haslayer(DNS):
        return 'DNS'
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        ports = {tcp.sport, tcp.dport}
        if 80 in ports or 8080 in ports:
            return 'HTTP'
        if 443 in ports or 8443 in ports:
            return 'HTTPS/TLS'
        if 22 in ports:
            return 'SSH'
        return 'TCP'
    if pkt.haslayer(UDP):
        return 'UDP'
    if pkt.haslayer(ICMP):
        return 'ICMP'
    if pkt.haslayer(ARP):
        return 'ARP'
    return 'OTHER'


def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%H:%M:%S.%f')[:-3]
    except Exception:
        return '00:00:00.000'


def analyze_packet_list(packets):
    total_packets = len(packets)

    if total_packets == 0:
        return {
            'summary': {
                'total_packets': 0,
                'total_bytes': 0,
                'duration_sec': 0,
                'avg_pps': 0,
                'unique_ips': 0,
                'status': 'EMPTY'
            },
            'protocols': {},
            'top_sources': [],
            'top_destinations': [],
            'traffic_timeline': [],
            'anomalies': [],
            'logs': []
        }

    protocol_counts = Counter()
    src_ip_counts = Counter()
    dst_ip_counts = Counter()
    pps_buckets = defaultdict(int)
    bps_buckets = defaultdict(int)
    src_dst_ports = defaultdict(set)
    syn_counts = Counter()
    arp_counts = Counter()
    timestamps = []
    total_bytes = 0
    logs = []

    for idx, pkt in enumerate(packets, start=1):
        pkt_len = len(pkt)
        total_bytes += pkt_len
        ts = float(pkt.time)
        timestamps.append(ts)
        sec_bucket = int(ts)
        pps_buckets[sec_bucket] += 1
        bps_buckets[sec_bucket] += pkt_len

        proto = classify_protocol(pkt)
        protocol_counts[proto] += 1

        src = 'N/A'
        dst = 'N/A'
        info = pkt.summary()

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            src_ip_counts[src] += 1
            dst_ip_counts[dst] += 1
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            src_ip_counts[src] += 1
            dst_ip_counts[dst] += 1
        elif pkt.haslayer(ARP):
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            src_ip_counts[src] += 1
            dst_ip_counts[dst] += 1
            arp_counts[src] += 1

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_dst_ports[src].add(tcp.dport)
            flags = str(tcp.flags)
            if 'S' in flags and 'A' not in flags:
                syn_counts[src] += 1
            info = f"{tcp.sport} -> {tcp.dport} [Flags: {flags}] Len={pkt_len}"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_dst_ports[src].add(udp.dport)
            info = f"{udp.sport} -> {udp.dport} Len={pkt_len}"
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info = f"Type={icmp.type} Code={icmp.code} Len={pkt_len}"

        if len(logs) < 250:
            logs.append({
                'no': idx,
                'time': format_timestamp(ts),
                'src': src,
                'dst': dst,
                'protocol': proto,
                'length': pkt_len,
                'info': info
            })

    min_ts = min(timestamps)
    max_ts = max(timestamps)
    duration_sec = round(max(max_ts - min_ts, 0.001), 2)
    avg_pps = round(total_packets / duration_sec, 2)

    sorted_secs = sorted(pps_buckets.keys())
    base_sec = sorted_secs[0]
    traffic_timeline = []
    pps_values = []
    for sec in sorted_secs:
        count = pps_buckets[sec]
        pps_values.append(count)
        traffic_timeline.append({
            'offset_sec': sec - base_sec,
            'label': datetime.fromtimestamp(sec).strftime('%H:%M:%S'),
            'packets': count,
            'bytes': bps_buckets[sec]
        })

    anomalies = []
    mean_pps = sum(pps_values) / len(pps_values)
    peak_pps = max(pps_values)

    # 1. Traffic Spike Detection
    if len(pps_values) >= 2 and peak_pps > max(mean_pps * 2.5, 15):
        peak_entry = max(traffic_timeline, key=lambda x: x['packets'])
        anomalies.append({
            'severity': 'HIGH',
            'type': 'Traffic Spike',
            'source': 'Multiple / Burst',
            'detail': f"Lonjakan trafik terdeteksi pada {peak_entry['label']} ({peak_pps} pkt/s vs rata-rata {round(mean_pps, 1)} pkt/s)."
        })

    # 2. Port Scan Detection
    for ip, ports in src_dst_ports.items():
        if ip != 'N/A' and len(ports) >= 12:
            anomalies.append({
                'severity': 'HIGH',
                'type': 'Port Scanning',
                'source': ip,
                'detail': f"IP {ip} memindai {len(ports)} port tujuan berbeda dalam satu sesi capture."
            })

    # 3. SYN Flood / Burst Detection
    for ip, count in syn_counts.items():
        if ip != 'N/A' and count >= 25:
            anomalies.append({
                'severity': 'MEDIUM',
                'type': 'SYN Burst / Flood',
                'source': ip,
                'detail': f"IP {ip} mengirim {count} paket TCP SYN tanpa ACK (indikasi SYN flood atau scan agresif)."
            })

    # 4. ARP Broadcast Storm Detection
    for ip, count in arp_counts.items():
        if ip != 'N/A' and count >= 20:
            anomalies.append({
                'severity': 'MEDIUM',
                'type': 'ARP Storm / Spoof Risk',
                'source': ip,
                'detail': f"Aktivitas ARP tinggi dari {ip} ({count} paket ARP terdeteksi)."
            })

    status = 'ALERT' if any(a['severity'] == 'HIGH' for a in anomalies) else ('WARNING' if anomalies else 'SECURE')
    unique_ips = len(set(src_ip_counts.keys()) | set(dst_ip_counts.keys()))

    return {
        'summary': {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'duration_sec': duration_sec,
            'avg_pps': avg_pps,
            'unique_ips': unique_ips,
            'status': status
        },
        'protocols': dict(protocol_counts.most_common()),
        'top_sources': [{'ip': ip, 'count': cnt} for ip, cnt in src_ip_counts.most_common(5)],
        'top_destinations': [{'ip': ip, 'count': cnt} for ip, cnt in dst_ip_counts.most_common(5)],
        'traffic_timeline': traffic_timeline[:120],
        'anomalies': anomalies,
        'logs': logs
    }


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/interfaces', methods=['GET'])
def api_interfaces():
    try:
        interfaces = get_if_list()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'interfaces': [], 'error': str(e)}), 500


@app.route('/api/live-capture', methods=['POST'])
def api_live_capture():
    payload = request.get_json(silent=True) or {}
    iface = (payload.get('interface') or '').strip() or None
    bpf_filter = (payload.get('bpf_filter') or '').strip() or None

    try:
        duration = int(payload.get('duration', 5))
        packet_count = int(payload.get('count', 100))
    except (TypeError, ValueError):
        return jsonify({'error': 'Parameter durasi atau jumlah paket harus berupa angka.'}), 400

    duration = max(1, min(duration, 30))
    packet_count = max(1, min(packet_count, 500))

    try:
        sniff_kwargs = {
            'timeout': duration,
            'count': packet_count,
            'store': True
        }
        if iface:
            sniff_kwargs['iface'] = iface
        if bpf_filter:
            sniff_kwargs['filter'] = bpf_filter

        captured = sniff(**sniff_kwargs)
        result = analyze_packet_list(captured)
        result['source_label'] = f"Live Capture ({iface or 'Default Interface'} - {len(captured)} pkt)"
        return jsonify(result)
    except PermissionError:
        return jsonify({
            'error': 'Akses ditolak: jalankan terminal/VS Code sebagai Administrator (Windows) atau root/sudo (Linux/macOS) dan pastikan Npcap/libpcap terpasang.'
        }), 403
    except Exception as e:
        return jsonify({
            'error': f'Gagal melakukan live capture: {str(e)}. Pastikan Npcap (Windows) atau libpcap terpasang dan filter BPF valid.'
        }), 500


@app.route('/api/analyze-pcap', methods=['POST'])
def api_analyze_pcap():
    if 'pcap_file' not in request.files:
        return jsonify({'error': 'File PCAP tidak ditemukan pada request.'}), 400

    file = request.files['pcap_file']
    if not file or file.filename == '':
        return jsonify({'error': 'Pilih file .pcap atau .pcapng terlebih dahulu.'}), 400

    if not is_allowed_file(file.filename):
        return jsonify({'error': 'Format file tidak didukung. Gunakan .pcap, .pcapng, atau .cap'}), 400

    tmp_path = None
    try:
        _, ext = os.path.splitext(file.filename)
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            file.save(tmp.name)
            tmp_path = tmp.name

        packets = rdpcap(tmp_path)
        result = analyze_packet_list(packets)
        result['source_label'] = f"File: {file.filename}"
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': f'Gagal memproses file PCAP: {str(e)}'}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
