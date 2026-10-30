import json
import subprocess
from pathlib import Path

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATADIR = WORKDIR / "data" / "fase1_trace"
RESULTS = WORKDIR / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

TARGETS = [
    ("valparaiso", "138.204.230.242", "Valparaíso (Sonda 6652)"),
    ("habana", "200.14.48.134", "La Habana (Sonda 12734)"),
    ("rusia", "37.79.226.46", "Rusia (Sonda 3959)"),
]
METHODS = ["udp", "icmp", "udp-paris", "icmp-paris", "tcp", "tcp-ack"]

# 1. Parse all JSON files from scamper
all_routes = {}
for slug, ip, label in TARGETS:
    all_routes[slug] = {}
    for m in METHODS:
        jfile = DATADIR / f"trace_{slug}_{ip}_{m}.json"
        hops = {}
        stop_reason = ""
        meta = {}
        with open(jfile, "r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                if obj.get("type") == "trace":
                    stop_reason = obj.get("stop_reason", "")
                    meta = {
                        "sport": obj.get("sport"),
                        "dport": obj.get("dport"),
                        "icmp_id": obj.get("icmp_id"),
                        "probe_size": obj.get("probe_size"),
                        "wait_timeout": obj.get("wait_timeout"),
                        "attempts": obj.get("attempts"),
                        "hoplimit": obj.get("hoplimit"),
                        "hop_count": obj.get("hop_count"),
                        "stop_reason": stop_reason,
                    }
                    for h in obj.get("hops", []):
                        ttl = h.get("probe_ttl")
                        addr = h.get("addr", "*")
                        rtt = h.get("rtt")
                        icmp_t = h.get("icmp_type")
                        icmp_c = h.get("icmp_code")
                        tcp_f = h.get("tcp_flags")
                        hops[ttl] = {
                            "addr": addr,
                            "rtt": rtt,
                            "icmp_type": icmp_t,
                            "icmp_code": icmp_c,
                            "tcp_flags": tcp_f,
                        }
        all_routes[slug][m] = {"meta": meta, "hops": hops}

# Save summary JSON
with open(RESULTS / "fase1_routes_summary.json", "w", encoding="utf-8") as f:
    json.dump(all_routes, f, indent=2, ensure_ascii=False)

# 2. Print Markdown tables and stats
md_out = []
for slug, ip, label in TARGETS:
    md_out.append(f"## Destino: {label} — `{ip}`\n")
    max_hop = 0
    for m in METHODS:
        hc = all_routes[slug][m]["meta"].get("hop_count", 0) or 0
        if hc > max_hop:
            max_hop = hc
        if all_routes[slug][m]["hops"]:
            mh = max(all_routes[slug][m]["hops"].keys())
            if mh > max_hop:
                max_hop = mh

    header = "| HOP | " + " | ".join(m.upper() for m in METHODS) + " |"
    sep = "| :-: | " + " | ".join(":---:" for _ in METHODS) + " |"
    md_out.append(header)
    md_out.append(sep)
    for h in range(1, max_hop + 1):
        row = [str(h)]
        for m in METHODS:
            hc = all_routes[slug][m]["meta"].get("hop_count", 0) or 0
            if h > hc:
                row.append("—")
            else:
                hinfo = all_routes[slug][m]["hops"].get(h)
                if hinfo:
                    extra = ""
                    if hinfo.get("tcp_flags") is not None:
                        extra = f" (tcp_flags=0x{hinfo['tcp_flags']:02x})"
                    row.append(f"`{hinfo['addr']}`{extra}")
                else:
                    row.append("`*`")
        md_out.append("| " + " | ".join(row) + " |")

    md_out.append("\n### Resumen cuantitativo por método:")
    md_out.append("| Método | Hops Sondeados | Hops con Respuesta | IPs Únicas | Alcanzó Destino | Stop Reason | sport / dport / icmp_id |")
    md_out.append("| :--- | :-: | :-: | :-: | :-: | :--- | :--- |")
    for m in METHODS:
        meta = all_routes[slug][m]["meta"]
        hops = all_routes[slug][m]["hops"]
        hc = meta.get("hop_count", 0) or 0
        resp_hops = len(hops)
        unique_ips = len(set(v["addr"] for v in hops.values()))
        reached = "✅ Sí" if any(v["addr"] == ip for v in hops.values()) else "❌ No"
        ports = f"sport={meta.get('sport')}, dport={meta.get('dport')}, icmp_id={meta.get('icmp_id')}"
        md_out.append(f"| `{m}` | {hc} | {resp_hops} | {unique_ips} | {reached} | `{meta.get('stop_reason')}` | `{ports}` |")
    md_out.append("\n---\n")

# 3. Extract packet-by-packet fields using tshark for Valparaiso (138.204.230.242) across all 6 methods
md_out.append("# ANÁLISIS DE PAQUETES WIRESHARK (1.3) — VALPARAÍSO (6 MÉTODOS)\n")
fields = [
    "frame.number", "ip.src", "ip.dst", "ip.ttl", "ip.id", "ip.proto", "ip.len", "ip.checksum",
    "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq", "icmp.checksum",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.window_size_value", "tcp.checksum",
    "data.len", "data.data"
]

for m in METHODS:
    pcap = DATADIR / f"trace_valparaiso_138.204.230.242_{m}.pcap"
    cmd = [TSHARK, "-r", str(pcap), "-n", "-T", "fields"]
    for fl in fields:
        cmd.extend(["-e", fl])
    cmd.extend(["-E", "separator=|"])
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    md_out.append(f"## Método: `{m}` (`{pcap.name}`)")
    md_out.append("```text")
    md_out.append("|".join(fields))
    md_out.append(res.stdout.strip())
    md_out.append("```\n")

(RESULTS / "fase1_analysis_raw.md").write_text("\n".join(md_out), encoding="utf-8")
print("Análisis completado. Archivo generado en:", RESULTS / "fase1_analysis_raw.md")
