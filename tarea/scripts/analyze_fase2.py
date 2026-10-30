import json
import subprocess
from pathlib import Path

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATA1 = WORKDIR / "data" / "fase1_trace"
DATA2 = WORKDIR / "data" / "fase2_tracelb"
RESULTS = WORKDIR / "results"
TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

TARGETS = [
    ("valparaiso", "138.204.230.242", "Valparaíso (Sonda 6652)"),
    ("habana", "200.14.48.134", "La Habana (Sonda 12734)"),
    ("rusia", "37.79.226.46", "Rusia (Sonda 3959)"),
]
MODES = ["udp-dport", "icmp-echo", "udp-sport", "tcp-sport", "tcp-ack-sport"]

# Load Fase 1 summary
with open(RESULTS / "fase1_routes_summary.json", "r", encoding="utf-8") as f:
    fase1 = json.load(f)

fase2_summary = {}
md_out = ["# RESULTADOS FASE 2 — SCAMPER TRACELB (1.5, 1.6, 1.7)\n"]

for slug, ip, label in TARGETS:
    fase2_summary[slug] = {}
    # Collect all unique IPs from Fase 1 for this target
    f1_all_ips = set()
    f1_by_method = {}
    for m, d in fase1[slug].items():
        ips = set(v["addr"] for v in d["hops"].values() if v.get("addr") and v["addr"] != "*")
        f1_by_method[m] = sorted(ips)
        f1_all_ips.update(ips)

    md_out.append(f"## Destino: {label} — `{ip}`\n")
    md_out.append("### Salidas de `tracelb` por modo (1.5):")
    for mode in MODES:
        tfile = DATA2 / f"tracelb_{slug}_{ip}_{mode}.txt"
        jfile = DATA2 / f"tracelb_{slug}_{ip}_{mode}.json"
        txt_content = tfile.read_text(encoding="utf-8").strip() if tfile.exists() else ""
        
        ips_found = set()
        probes_sent = 0
        node_count = 0
        link_count = 0
        meta = {}
        if jfile.exists():
            with open(jfile, "r", encoding="utf-8") as jf:
                for line in jf:
                    obj = json.loads(line)
                    if obj.get("type") == "tracelb":
                        probes_sent = obj.get("probec", 0)
                        node_count = obj.get("nodec", 0)
                        link_count = obj.get("linkc", 0)
                        meta = {
                            "sport": obj.get("sport"),
                            "dport": obj.get("dport"),
                            "probec": probes_sent,
                            "nodec": node_count,
                            "linkc": link_count,
                        }
                        for node in obj.get("nodes", []):
                            if node.get("addr") and node["addr"] != "*":
                                ips_found.add(node["addr"])
                            for link_set in node.get("links", []):
                                for lk in link_set:
                                    if lk.get("addr") and lk["addr"] != "*":
                                        ips_found.add(lk["addr"])

        new_vs_all_f1 = sorted(ips_found - f1_all_ips)
        fase2_summary[slug][mode] = {
            "meta": meta,
            "ips": sorted(ips_found),
            "ip_count": len(ips_found),
            "new_ips_vs_all_fase1": new_vs_all_f1,
            "txt": txt_content,
        }
        md_out.append(f"#### Modo `{mode}` (IPs únicas={len(ips_found)}, Nodos={node_count}, Enlaces={link_count}, Sondas={probes_sent})")
        md_out.append("```text")
        md_out.append(txt_content)
        md_out.append("```")
        if new_vs_all_f1:
            md_out.append(f"- **Nuevas IPs descubiertas que NO aparecieron en ningún método de Fase 1**: `{', '.join(new_vs_all_f1)}`\n")
        else:
            md_out.append("- **Nuevas IPs respecto al conjunto total de Fase 1**: Ninguna adicional (pero descubre bifurcaciones ECMP explícitas en una sola ejecución).\n")

    # Combined Fase 2 IPs
    f2_all_ips = set()
    for mode in MODES:
        f2_all_ips.update(fase2_summary[slug][mode]["ips"])
    total_new = sorted(f2_all_ips - f1_all_ips)
    md_out.append(f"### Comparación Cuantitativa Fase 1 (`trace`) vs Fase 2 (`tracelb`) para {label} (1.6):")
    md_out.append(f"- **Total IPs únicas sumando los 6 métodos de Fase 1**: **{len(f1_all_ips)}** (`{', '.join(sorted(f1_all_ips))}`)")
    md_out.append(f"- **Total IPs únicas sumando los 5 modos de Fase 2 (`tracelb`)**: **{len(f2_all_ips)}** (`{', '.join(sorted(f2_all_ips))}`)")
    md_out.append(f"- **IPs inéditas aportadas exclusivamente por `tracelb`**: **{len(total_new)}** (`{', '.join(total_new) if total_new else 'Ninguna'}`)\n")
    md_out.append("---\n")

with open(RESULTS / "fase2_tracelb_summary.json", "w", encoding="utf-8") as f:
    json.dump(fase2_summary, f, indent=2, ensure_ascii=False)

# Extract first 18 outgoing probe packets per mode for Valparaiso
md_out.append("# ANÁLISIS DE PAQUETES WIRESHARK (1.7) — VALPARAÍSO (5 MODOS TRACELB)\n")
fields = [
    "frame.number", "ip.src", "ip.dst", "ip.ttl", "ip.id", "ip.proto", "ip.len", "ip.checksum",
    "udp.srcport", "udp.dstport", "udp.length", "udp.checksum",
    "icmp.type", "icmp.code", "icmp.ident", "icmp.seq", "icmp.checksum",
    "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.window_size_value", "tcp.checksum",
    "data.len", "data.data"
]

for mode in MODES:
    pcap = DATA2 / f"tracelb_valparaiso_138.204.230.242_{mode}.pcap"
    cmd = [TSHARK, "-r", str(pcap), "-n", "-Y", "ip.src == 172.21.133.187 && !(icmp.type == 11 || icmp.type == 3)", "-T", "fields"]
    for fl in fields:
        cmd.extend(["-e", fl])
    cmd.extend(["-E", "separator=|"])
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    lines = res.stdout.strip().splitlines()[:20]
    md_out.append(f"## Modo `tracelb -P {mode}` (`{pcap.name}` — primeros 20 paquetes salientes)")
    md_out.append("```text")
    md_out.append("|".join(fields))
    md_out.extend(lines)
    md_out.append("```\n")

(RESULTS / "fase2_analysis_raw.md").write_text("\n".join(md_out), encoding="utf-8")
print("Análisis de Fase 2 completado en:", RESULTS / "fase2_analysis_raw.md")

