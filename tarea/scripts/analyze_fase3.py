import ipaddress
import json
import subprocess
from pathlib import Path
import requests

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATA3 = WORKDIR / "data" / "fase3_ripe_ida"
RESULTS = WORKDIR / "results"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

TARGETS = [
    ("valparaiso", "138.204.230.242", "Valparaíso (Sonda 6652)"),
    ("habana", "200.14.48.134", "La Habana (Sonda 12734)"),
    ("rusia", "37.79.226.46", "Rusia (Sonda 3959)"),
]
PROTOCOLS = ["udp", "icmp", "tcp"]

asn_cache = {}
CACHE_FILE = RESULTS / "asn_cache.json"
if CACHE_FILE.exists():
    asn_cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))

def resolve_asn(ip_str):
    if not ip_str or ip_str == "*":
        return {"asn": "—", "holder": "Sin respuesta (*)", "prefix": "—"}
    if ip_str in asn_cache:
        return asn_cache[ip_str]

    ip_obj = ipaddress.ip_address(ip_str)
    # Check RFC 6598 CGNAT (100.64.0.0/10) or RFC 1918 private inside ISP
    if ip_obj in ipaddress.ip_network("172.17.0.0/16"):
        info = {"asn": "Local (Docker)", "holder": "Bridge Docker Host", "prefix": "172.17.0.0/16"}
    elif ip_obj in ipaddress.ip_network("192.168.65.0/24") or ip_obj in ipaddress.ip_network("192.168.100.0/24"):
        info = {"asn": "Local (LAN/VM)", "holder": "Gateway Local / CPE", "prefix": str(ip_obj) + "/24"}
    elif ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        info = {"asn": "AS27651 (CGNAT)", "holder": "ENTEL CHILE S.A. (RFC6598 CGNAT)", "prefix": "100.64.0.0/10"}
    elif ip_obj.is_private:
        info = {"asn": "Privada (ISP MPLS)", "holder": "Red Interna ISP / Tránsito", "prefix": "RFC1918"}
    else:
        try:
            r = requests.get(f"https://stat.ripe.net/data/network-info/data.json?resource={ip_str}", timeout=15).json()
            asns = r.get("data", {}).get("asns", [])
            prefix = r.get("data", {}).get("prefix", "")
            if asns:
                asn_num = asns[0]
                r2 = requests.get(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}", timeout=15).json()
                holder = r2.get("data", {}).get("holder", f"AS{asn_num}")
                info = {"asn": f"AS{asn_num}", "holder": holder, "prefix": prefix}
            else:
                info = {"asn": "Desconocido", "holder": "No anunciado en BGP", "prefix": prefix or "—"}
        except Exception as e:
            info = {"asn": "Error", "holder": str(e), "prefix": "—"}

    asn_cache[ip_str] = info
    CACHE_FILE.write_text(json.dumps(asn_cache, indent=2, ensure_ascii=False), encoding="utf-8")
    return info

fase3_summary = {}
md_out = ["# RESULTADOS FASE 3 — RIPE ATLAS TRACEROUTE IDA (2.1, 2.2, 2.3, 2.4)\n"]

for slug, ip, label in TARGETS:
    fase3_summary[slug] = {}
    md_out.append(f"## Destino: {label} — `{ip}`\n")
    max_hop = 0

    for proto in PROTOCOLS:
        jfile = DATA3 / f"ripe_ida_{slug}_{ip}_{proto}.json"
        data = json.loads(jfile.read_text(encoding="utf-8"))
        msm_id = data["measurement_id"]
        res_list = data.get("results", [])
        hops_dict = {}
        unique_ips = set()
        if res_list:
            tr = res_list[0]
            for h in tr.get("result", []):
                hop_num = h.get("hop")
                if not hop_num or hop_num == 255:
                    continue
                if hop_num > max_hop:
                    max_hop = hop_num
                # Collect responses across the 3 packets for this hop
                pkts = h.get("result", [])
                hop_ips = []
                rtts = []
                for p in pkts:
                    if "from" in p:
                        f_ip = p["from"]
                        if f_ip not in hop_ips:
                            hop_ips.append(f_ip)
                        unique_ips.add(f_ip)
                    if "rtt" in p:
                        rtts.append(round(p["rtt"], 2))
                primary_ip = hop_ips[0] if hop_ips else "*"
                asn_info = resolve_asn(primary_ip)
                hops_dict[hop_num] = {
                    "ips": hop_ips if hop_ips else ["*"],
                    "primary_ip": primary_ip,
                    "asn": asn_info["asn"],
                    "holder": asn_info["holder"],
                    "prefix": asn_info["prefix"],
                    "rtts": rtts,
                }
        fase3_summary[slug][proto] = {
            "measurement_id": msm_id,
            "hops": hops_dict,
            "unique_ips": sorted(unique_ips),
            "unique_ip_count": len(unique_ips),
            "reached_target": ip in unique_ips,
        }

    # Build Table for 2.1 (HOP | UDP IP + AS | ICMP IP + AS | TCP IP + AS)
    md_out.append("### Tabla 2.1 — IPs por Hop y Sistema Autónomo (AS) por Protocolo:")
    md_out.append(f"- **IDs de Medición RIPE Atlas (Ida)**: `UDP = {fase3_summary[slug]['udp']['measurement_id']}` | `ICMP = {fase3_summary[slug]['icmp']['measurement_id']}` | `TCP = {fase3_summary[slug]['tcp']['measurement_id']}`\n")
    md_out.append("| HOP | UDP (IP / AS / ISP) | ICMP (IP / AS / ISP) | TCP (IP / AS / ISP) |")
    md_out.append("| :-: | :--- | :--- | :--- |")
    for h in range(1, max_hop + 1):
        row = [str(h)]
        for proto in PROTOCOLS:
            hi = fase3_summary[slug][proto]["hops"].get(h)
            if not hi:
                row.append("—")
            elif hi["primary_ip"] == "*":
                row.append("`*`")
            else:
                ips_str = ", ".join(f"`{x}`" for x in hi["ips"])
                row.append(f"{ips_str} — **{hi['asn']}** ({hi['holder']})")
        md_out.append("| " + " | ".join(row) + " |")

    md_out.append("\n### Resumen Comparativo de Protocolos RIPE Atlas (2.2):")
    md_out.append("| Protocolo | Measurement ID | Hops con Respuesta | IPs Únicas | ASNs Públicos Únicos | ¿Alcanzó Destino? |")
    md_out.append("| :--- | :-: | :-: | :-: | :-: | :-: |")
    for proto in PROTOCOLS:
        d = fase3_summary[slug][proto]
        resp_hops = sum(1 for v in d["hops"].values() if v["primary_ip"] != "*")
        pub_asns = sorted(set(v["asn"] for v in d["hops"].values() if v["asn"].startswith("AS")))
        reached = "✅ Sí" if d["reached_target"] else "❌ No"
        md_out.append(f"| `{proto.upper()}` | `{d['measurement_id']}` | {resp_hops} | **{d['unique_ip_count']}** | {len(pub_asns)} (`{', '.join(pub_asns)}`) | {reached} |")
    md_out.append("\n---\n")

with open(RESULTS / "fase3_ripe_ida_summary.json", "w", encoding="utf-8") as f:
    json.dump(fase3_summary, f, indent=2, ensure_ascii=False)

# Extract outgoing probe packets from Docker container (172.17.0.2) for Valparaiso (UDP, ICMP, TCP)
md_out.append("# ANÁLISIS DE PAQUETES WIRESHARK RIPE ATLAS (2.3) — VALPARAÍSO (UDP, ICMP, TCP)\n")
fields = [
    "frame.number", "ip.src", "ip.dst", "ip.ttl", "ip.id", "ip.proto", "ip.len", "ip.checksum",
    "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq", "icmp.checksum",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.window_size_value", "tcp.checksum", "tcp.options",
    "data.len", "data.data"
]

for proto in PROTOCOLS:
    pcap = DATA3 / f"ripe_ida_valparaiso_138.204.230.242_{proto}.pcap"
    cmd = [TSHARK, "-r", str(pcap), "-n", "-Y", "ip.dst == 138.204.230.242 && !(icmp.type == 11 || icmp.type == 3)", "-T", "fields"]
    for fl in fields:
        cmd.extend(["-e", fl])
    cmd.extend(["-E", "separator=|"])
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    lines = res.stdout.strip().splitlines()[:25]
    md_out.append(f"## Protocolo RIPE `{proto.upper()}` (`{pcap.name}` — sondas salientes hacia `138.204.230.242`)")
    md_out.append("```text")
    md_out.append("|".join(fields))
    md_out.extend(lines)
    md_out.append("```\n")

    # Also show incoming replies for this target
    cmd2 = [TSHARK, "-r", str(pcap), "-n", "-Y", "ip.src == 138.204.230.242 || ((icmp.type == 11 || icmp.type == 3) && ip.dst == 138.204.230.242)", "-T", "fields"]
    for fl in fields:
        cmd2.extend(["-e", fl])
    cmd2.extend(["-E", "separator=|"])
    res2 = subprocess.run(cmd2, capture_output=True, text=True, encoding="utf-8")
    lines2 = res2.stdout.strip().splitlines()[:15]
    md_out.append(f"### Respuestas recibidas en `{proto.upper()}` (`{pcap.name}`)")
    md_out.append("```text")
    md_out.extend(lines2)
    md_out.append("```\n")

(RESULTS / "fase3_analysis_raw.md").write_text("\n".join(md_out), encoding="utf-8")
print("Análisis de Fase 3 completado en:", RESULTS / "fase3_analysis_raw.md")
