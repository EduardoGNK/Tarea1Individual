import ipaddress
import json
from pathlib import Path
import requests

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATA3 = WORKDIR / "data" / "fase3_ripe_ida"
DATA4 = WORKDIR / "data" / "fase4_ripe_vuelta"
RESULTS = WORKDIR / "results"

CACHE_FILE = RESULTS / "asn_cache.json"
asn_cache = json.loads(CACHE_FILE.read_text(encoding="utf-8")) if CACHE_FILE.exists() else {}

def resolve_asn(ip_str):
    if not ip_str or ip_str == "*":
        return {"asn": "—", "holder": "Sin respuesta (*)", "prefix": "—"}
    if ip_str in asn_cache:
        return asn_cache[ip_str]

    ip_obj = ipaddress.ip_address(ip_str)
    if ip_obj in ipaddress.ip_network("172.17.0.0/16"):
        info = {"asn": "Local (Docker)", "holder": "Bridge Docker Host", "prefix": "172.17.0.0/16"}
    elif ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        info = {"asn": "AS27651 (CGNAT)", "holder": "ENTEL CHILE S.A. (RFC6598 CGNAT)", "prefix": "100.64.0.0/10"}
    elif ip_obj.is_private:
        info = {"asn": "Privada (ISP/LAN)", "holder": "Red Interna ISP / Tránsito", "prefix": "RFC1918"}
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
                info = {"asn": "IXP / Peering", "holder": "Prefijo de Intercambio / Peering", "prefix": prefix or "—"}
        except Exception as e:
            info = {"asn": "Error", "holder": str(e), "prefix": "—"}

    asn_cache[ip_str] = info
    CACHE_FILE.write_text(json.dumps(asn_cache, indent=2, ensure_ascii=False), encoding="utf-8")
    return info

TARGETS = [
    ("valparaiso", "138.204.230.242", 6652, "Valparaíso (Sonda 6652)"),
    ("habana", "200.14.48.134", 12734, "La Habana (Sonda 12734)"),
    ("rusia", "37.79.226.46", 3959, "Rusia (Sonda 3959)"),
]
PROTOCOLS = ["udp", "icmp", "tcp"]
SCAMPER_MAP = {"udp": "udp-paris", "icmp": "icmp-paris", "tcp": "tcp"}

with open(RESULTS / "fase1_routes_summary.json", "r", encoding="utf-8") as f:
    fase1 = json.load(f)
with open(RESULTS / "fase3_ripe_ida_summary.json", "r", encoding="utf-8") as f:
    fase3 = json.load(f)

fase4_summary = {}
md_out = ["# RESULTADOS FASE 4 — RIPE ATLAS PATH WAY (IDA vs. VUELTA — 3.1)\n"]

for slug, ip, probe_id, label in TARGETS:
    fase4_summary[slug] = {}
    md_out.append(f"## Destino: {label} — `{ip}` $\\leftrightarrow$ `181.42.130.114` (Entel AS27651)\n")

    for proto in PROTOCOLS:
        jfile = DATA4 / f"ripe_vuelta_{slug}_{ip}_{proto}.json"
        data = json.loads(jfile.read_text(encoding="utf-8"))
        msm_vuelta = data["measurement_id"]
        msm_ida = fase3[slug][proto]["measurement_id"]
        res_list = data.get("results", [])

        vuelta_hops = {}
        vuelta_unique = set()
        max_vuelta_hop = 0
        if res_list:
            tr = res_list[0]
            for h in tr.get("result", []):
                hop_num = h.get("hop")
                if not hop_num or hop_num == 255:
                    continue
                if hop_num > max_vuelta_hop:
                    max_vuelta_hop = hop_num
                pkts = h.get("result", [])
                hop_ips = []
                rtts = []
                for p in pkts:
                    if "from" in p:
                        f_ip = p["from"]
                        if f_ip not in hop_ips:
                            hop_ips.append(f_ip)
                        vuelta_unique.add(f_ip)
                    if "rtt" in p:
                        rtts.append(round(p["rtt"], 2))
                primary_ip = hop_ips[0] if hop_ips else "*"
                asn_info = resolve_asn(primary_ip)
                vuelta_hops[hop_num] = {
                    "ips": hop_ips if hop_ips else ["*"],
                    "primary_ip": primary_ip,
                    "asn": asn_info["asn"],
                    "holder": asn_info["holder"],
                    "prefix": asn_info["prefix"],
                    "rtts": rtts,
                }

        # Trim trailing * hops after the last responding hop if excessive, or keep all reported hops
        ida_ripe_hops = {int(k): v for k, v in fase3[slug][proto]["hops"].items()}
        sc_m = SCAMPER_MAP[proto]
        ida_scamper_hops = {int(k): v for k, v in fase1[slug][sc_m]["hops"].items()}
        sc_max_hop = fase1[slug][sc_m]["meta"].get("hop_count", 0) or 0

        max_h = max(
            max(ida_ripe_hops.keys(), default=0),
            max_vuelta_hop,
            sc_max_hop,
        )

        fase4_summary[slug][proto] = {
            "msm_ida": msm_ida,
            "msm_vuelta": msm_vuelta,
            "vuelta_hops": vuelta_hops,
            "vuelta_unique_ips": sorted(vuelta_unique),
            "vuelta_unique_count": len(vuelta_unique),
            "ida_ripe_unique_ips": fase3[slug][proto]["unique_ips"],
            "ida_ripe_unique_count": fase3[slug][proto]["unique_ip_count"],
            "ida_scamper_unique_ips": sorted(set(v["addr"] for v in ida_scamper_hops.values() if v.get("addr") != "*")),
        }

        md_out.append(f"### Tabla 2 — {label} — Protocolo `{proto.upper()}`")
        md_out.append(f"- **Measurement ID IDA (Sonda `1018519` $\\to$ `{ip}`)**: `{msm_ida}`")
        md_out.append(f"- **Measurement ID VUELTA (Sonda `{probe_id}` $\\to$ `181.42.130.114`)**: `{msm_vuelta}`\n")
        md_out.append("| HOP | IP IDA (RIPE Atlas Docker) | IP IDA (Scamper Directo WSL2) | IP VUELTA (RIPE Atlas Remota $\\to$ BAF) | AS / Operador (Vuelta) |")
        md_out.append("| :-: | :--- | :--- | :--- | :--- |")
        for h in range(1, max_h + 1):
            # Ida RIPE
            ir = ida_ripe_hops.get(h)
            ir_str = "—" if not ir else ("`*`" if ir["primary_ip"] == "*" else ", ".join(f"`{x}`" for x in ir["ips"]))
            # Ida Scamper
            isc = ida_scamper_hops.get(h)
            if h > sc_max_hop:
                isc_str = "—"
            elif not isc:
                isc_str = "`*`"
            else:
                isc_str = f"`{isc['addr']}`"
            # Vuelta RIPE
            vr = vuelta_hops.get(h)
            if not vr:
                vr_str = "—"
                vr_asn = "—"
            elif vr["primary_ip"] == "*":
                vr_str = "`*`"
                vr_asn = "—"
            else:
                vr_str = ", ".join(f"`{x}`" for x in vr["ips"])
                vr_asn = f"**{vr['asn']}** ({vr['holder']})"
            md_out.append(f"| {h} | {ir_str} | {isc_str} | {vr_str} | {vr_asn} |")
        md_out.append("")

    md_out.append("---\n")

with open(RESULTS / "fase4_ripe_vuelta_summary.json", "w", encoding="utf-8") as f:
    json.dump(fase4_summary, f, indent=2, ensure_ascii=False)

(RESULTS / "fase4_analysis_raw.md").write_text("\n".join(md_out), encoding="utf-8")
print("Análisis de Fase 4 completado en:", RESULTS / "fase4_analysis_raw.md")

