#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FASE 5 - PUBLIC PATH (NDExBio)
Construye la ruta más completa para cada una de las 3 IPs destino (Valparaíso, La Habana, Rusia)
combinando los hallazgos de Scamper (trace + tracelb) y RIPE Atlas (Ida + Vuelta),
genera los 3 grafos con ndex2 (nodos con atributos IP, hop, AS, ISP, prefijo, sentido;
aristas dirigidas; coordenadas cartesianas para visualización limpia), los publica en
https://www.ndexbio.org/ con visibilidad PUBLIC, incluye en la descripción los 2 IDs de
medición RIPE (ida y vuelta) y registra los 3 UUIDs.
"""

import json
import re
from pathlib import Path
import requests
import ndex2
from ndex2.nice_cx_network import NiceCXNetwork

BASE = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATA_F5 = BASE / "data" / "fase5_ndex"
RES_DIR = BASE / "results"
DATA_F5.mkdir(parents=True, exist_ok=True)

import os
NDEX_USER = os.environ.get("NDEX_USER", "gnk")
NDEX_PASS = os.environ.get("NDEX_PASS", "<NDEX_PASSWORD>")
NDEX_SERVER = "http://public.ndexbio.org"

# Cargar resúmenes previos
f1_sum = json.loads((RES_DIR / "fase1_routes_summary.json").read_text(encoding="utf-8"))
f2_sum = json.loads((RES_DIR / "fase2_tracelb_summary.json").read_text(encoding="utf-8"))
f3_sum = json.loads((RES_DIR / "fase3_ripe_ida_summary.json").read_text(encoding="utf-8"))
f4_sum = json.loads((RES_DIR / "fase4_ripe_vuelta_summary.json").read_text(encoding="utf-8"))

# Diccionario maestro de metadatos ASN/ISP conocidos + resolución automática
KNOWN_ASN = {
    "181.42.130.114": ("AS27651", "ENTEL CHILE S.A. (BAF Origen)", "181.42.128.0/21"),
    "172.17.0.1": ("Docker-Bridge", "Docker Desktop NAT Gateway (Sonda 1018519)", "172.17.0.0/16"),
    "172.21.128.1": ("WSL2-HyperV", "Gateway Virtual WSL2 (Windows Host)", "172.21.128.0/20"),
    "192.168.100.1": ("LAN-CPE", "Router Fibra Óptica Hogar (ONT Entel)", "192.168.100.0/24"),
    "100.80.96.1": ("AS27651-CGNAT", "ENTEL CHILE S.A. (CGNAT RFC6598)", "100.64.0.0/10"),
    "10.253.198.77": ("AS27651-Core", "ENTEL CHILE S.A. (Backbone MPLS Core)", "10.0.0.0/8"),
    "10.253.198.78": ("AS27651-Core", "ENTEL CHILE S.A. (Backbone MPLS Core)", "10.0.0.0/8"),
    "10.253.197.25": ("AS27651-Core", "ENTEL CHILE S.A. (Backbone MPLS Core)", "10.0.0.0/8"),
    "192.168.8.133": ("AS27651-Borde", "ENTEL CHILE S.A. (Router Borde Internacional)", "192.168.0.0/16"),
    "192.168.9.138": ("AS27651-Borde", "ENTEL CHILE S.A. (Router Borde Internacional)", "192.168.0.0/16"),
    "45.68.16.129": ("AS61522-IXP", "PIT Chile SpA (Punto de Intercambio de Tráfico)", "45.68.16.0/23"),
    "45.68.17.13": ("AS61522-IXP", "PIT Chile SpA (Punto de Intercambio de Tráfico)", "45.68.16.0/23"),
    "10.100.154.1": ("AS61506-Int", "INSACOM SpA (Enlace Interno /30 Ida)", "10.100.154.0/30"),
    "10.100.154.2": ("AS61506-Int", "INSACOM SpA (Enlace Interno /30 Vuelta)", "10.100.154.0/30"),
    "10.100.163.1": ("AS61506-Int", "INSACOM SpA (Core Interno Valparaíso)", "10.100.163.0/24"),
    "138.204.228.164": ("AS61506", "INSACOM SpA (Router Distribución Valparaíso)", "138.204.228.0/24"),
    "138.204.228.162": ("AS61506", "INSACOM SpA (Router Agregación Valparaíso)", "138.204.228.0/24"),
    "138.204.228.163": ("AS61506", "INSACOM SpA (Router Agregación Valparaíso)", "138.204.228.0/24"),
    "138.204.230.193": ("AS61506", "INSACOM SpA (Gateway Acceso Sonda 6652)", "138.204.230.0/24"),
    "138.204.230.242": ("AS61506", "INSACOM SpA (Sonda RIPE Atlas 6652 - Valparaíso)", "138.204.230.0/24"),
    "190.98.132.226": ("AS262195", "Transamerica Telecomunicacoes / Peering Regional", "190.98.132.0/24"),
    "5.53.7.51": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone)", "5.53.0.0/19"),
    "94.142.97.65": ("AS12956", "TELEFONICA GLOBAL SOLUTIONS (Telxius)", "94.142.96.0/19"),
    "213.140.35.110": ("AS12956", "TELEFONICA GLOBAL SOLUTIONS (Telxius)", "213.140.32.0/19"),
    "213.140.35.86": ("AS12956", "TELEFONICA GLOBAL SOLUTIONS (Telxius)", "213.140.32.0/19"),
    "193.251.143.67": ("AS5511", "ORANGE S.A. (OpenTransit International)", "193.251.128.0/19"),
    "200.0.16.62": ("AS11960", "ETECSA (IXP Cuba - Borde Internacional)", "200.0.16.0/24"),
    "200.0.16.21": ("AS11960", "ETECSA (IXP Cuba - Enlace /30 Ida)", "200.0.16.0/24"),
    "200.0.16.20": ("AS11960", "ETECSA (IXP Cuba - Enlace /30 Vuelta)", "200.0.16.0/24"),
    "200.0.16.25": ("AS11960", "ETECSA (IXP Cuba - Rama ECMP descubierta por tracelb)", "200.0.16.0/24"),
    "200.0.16.29": ("AS11960", "ETECSA (IXP Cuba - Enlace /30 Ida)", "200.0.16.0/24"),
    "200.0.16.28": ("AS11960", "ETECSA (IXP Cuba - Enlace /30 Vuelta)", "200.0.16.0/24"),
    "200.0.16.45": ("AS11960", "ETECSA (IXP Cuba - Distribución Retorno)", "200.0.16.0/24"),
    "200.0.16.84": ("AS11960", "ETECSA (IXP Cuba - Agregación Retorno)", "200.0.16.0/24"),
    "172.31.252.185": ("AS27725-Int", "ETECSA (Red Interna Transporte Cuba)", "172.16.0.0/12"),
    "192.168.118.89": ("AS27725-Int", "ETECSA (Red Interna Acceso La Habana)", "192.168.0.0/16"),
    "200.14.48.178": ("AS27725", "ETECSA (Router La Habana - Enlace /30 Ida)", "200.14.48.0/21"),
    "200.14.48.177": ("AS27725", "ETECSA (Router La Habana - Enlace /30 Vuelta)", "200.14.48.0/21"),
    "200.14.48.132": ("AS27725", "ETECSA (Gateway Local Sonda 12734)", "200.14.48.0/21"),
    "200.14.48.134": ("AS27725", "ETECSA (Sonda RIPE Atlas 12734 - La Habana)", "200.14.48.0/21"),
    "89.221.37.180": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Retorno)", "89.221.32.0/20"),
    "89.221.37.138": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Retorno)", "89.221.32.0/20"),
    "195.22.221.185": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Sudamérica)", "195.22.192.0/19"),
    "195.22.221.41": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Sudamérica)", "195.22.192.0/19"),
    "195.22.221.1": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Borde Chile)", "195.22.192.0/19"),
    "195.22.221.3": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Borde Chile)", "195.22.192.0/19"),
    "195.22.221.2": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Ingreso desde Entel)", "195.22.192.0/19"),
    "195.22.211.209": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Europa/Milán)", "195.22.192.0/19"),
    "195.22.211.61": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Rama ECMP descubierta por tracelb)", "195.22.192.0/19"),
    "195.22.214.161": ("AS6762", "TELECOM ITALIA SPARKLE S.p.A. (Seabone Hacia Rusia)", "195.22.192.0/19"),
    "2.63.212.246": ("AS12389", "PJSC ROSTELECOM (Enlace /30 Ida)", "2.60.0.0/14"),
    "2.63.212.245": ("AS12389", "PJSC ROSTELECOM (Enlace /30 Vuelta)", "2.60.0.0/14"),
    "37.79.226.46": ("AS12389", "PJSC ROSTELECOM (Sonda RIPE Atlas 3959 - Rusia)", "37.79.224.0/20"),
    "192.168.30.1": ("LAN-Sonda3959", "Gateway Local Sonda 3959 (Rusia)", "192.168.30.0/24"),
    "37.79.226.33": ("AS12389", "PJSC ROSTELECOM (Gateway Acceso Sonda 3959)", "37.79.224.0/20"),
    "172.29.8.149": ("AS12389-Int", "PJSC ROSTELECOM (Core MPLS Interno)", "172.16.0.0/12"),
    "172.29.8.151": ("AS12389-Int", "PJSC ROSTELECOM (Core MPLS Interno TCP)", "172.16.0.0/12"),
    "172.29.39.179": ("AS12389-Int", "PJSC ROSTELECOM (Core MPLS Salida Internacional)", "172.16.0.0/12"),
    "212.133.1.53": ("AS3356", "LEVEL 3 / LUMEN TECHNOLOGIES (Ingreso Europa Retorno)", "212.133.0.0/17"),
    "200.189.207.14": ("AS3549", "LEVEL 3 / GLOBAL CROSSING LATAM (Tránsito Sudamérica)", "200.189.192.0/18"),
    "200.189.207.6": ("AS3549", "LEVEL 3 / GLOBAL CROSSING LATAM (Tránsito Sudamérica)", "200.189.192.0/18"),
    "8.243.188.94": ("AS3356", "LEVEL 3 / LUMEN TECHNOLOGIES (Entrega hacia Entel Chile)", "8.243.176.0/20"),
    "8.243.188.86": ("AS3356", "LEVEL 3 / LUMEN TECHNOLOGIES (Entrega hacia Entel Chile)", "8.243.176.0/20"),
}


def get_ip_meta(ip: str):
    if ip in KNOWN_ASN:
        return KNOWN_ASN[ip]
    return ("Desconocido", "Nodo Intermedio", "—")


TARGETS_CFG = {
    "valparaiso": {
        "title": "UDP Path Discovery - Valparaiso (138.204.230.242 - Sonda 6652) <-> BAF Entel Chile (181.42.130.114 - AS27651)",
        "target_ip": "138.204.230.242",
        "probe_id": 6652,
        "location": "Valparaíso, Chile (Mayor velocidad)",
        "primary_msm_ida": 229621764,     # ICMP Ida
        "primary_msm_vuelta": 229638791,  # ICMP Vuelta
        "all_msm_ida": {"UDP": 229621225, "ICMP": 229621764, "TCP": 229622098},
        "all_msm_vuelta": {"UDP": 229638773, "ICMP": 229638791, "TCP": 229638809},
        "slash30_pairs": [
            ("10.100.154.1", "10.100.154.2", "Enlace /30 INSACOM (Hop 8 Ida <-> Hop 4 Vuelta)"),
            ("45.68.16.129", "45.68.17.13", "Peering IXP PIT Chile (Hop 7 Ida <-> Hop 5 Vuelta)"),
            ("138.204.228.162", "138.204.228.163", "Par Agregación INSACOM (Hop 10 Ida <-> Hop 7 Vuelta UDP)"),
        ],
    },
    "habana": {
        "title": "UDP Path Discovery - La Habana, Cuba (200.14.48.134 - Sonda 12734) <-> BAF Entel Chile (181.42.130.114 - AS27651)",
        "target_ip": "200.14.48.134",
        "probe_id": 12734,
        "location": "La Habana, Cuba (Menor velocidad)",
        "primary_msm_ida": 229623295,     # ICMP Ida
        "primary_msm_vuelta": 229638841,  # ICMP Vuelta (Ref pre-corte: 228016959)
        "all_msm_ida": {"UDP": 229622916, "ICMP": 229623295, "TCP": 229623665},
        "all_msm_vuelta": {
            "UDP": "229638824 (Ref. activa: 228016823)",
            "ICMP": "229638841 (Ref. activa: 228016959)",
            "TCP": "229638856 (Ref. activa: 228017080)",
        },
        "slash30_pairs": [
            ("200.14.48.178", "200.14.48.177", "Enlace /30 ETECSA La Habana (Hop 19 Ida <-> Hop 2 Vuelta)"),
            ("200.0.16.29", "200.0.16.28", "Enlace /30 IXP Cuba AS11960 (Hop 16 Ida <-> Hop 5 Vuelta)"),
            ("200.0.16.21", "200.0.16.20", "Enlace /30 IXP Cuba AS11960 (Hop 15 Ida <-> Hop 6/7 Vuelta)"),
        ],
    },
    "rusia": {
        "title": "UDP Path Discovery - Rusia (37.79.226.46 - Sonda 3959) <-> BAF Entel Chile (181.42.130.114 - AS27651)",
        "target_ip": "37.79.226.46",
        "probe_id": 3959,
        "location": "Rusia (Mayor censura reciente)",
        "primary_msm_ida": 229624261,     # ICMP Ida
        "primary_msm_vuelta": 229638887,  # ICMP Vuelta
        "all_msm_ida": {"UDP": 229623802, "ICMP": 229624261, "TCP": 229624325},
        "all_msm_vuelta": {"UDP": 229638870, "ICMP": 229638887, "TCP": 229638899},
        "slash30_pairs": [
            ("2.63.212.246", "2.63.212.245", "Enlace /30 PJSC Rostelecom AS12389 (Hop 14 Ida <-> Hop 3 Vuelta)"),
            ("195.22.221.2", "8.243.188.86", "Asimetría Interdominio Tier-1: Ida Sparkle AS6762 vs Vuelta Level3 AS3356"),
        ],
    },
}


def build_complete_graph_for_target(slug: str, cfg: dict):
    """
    Construye el grafo más completo combinando:
    1. Todos los saltos y métodos de IDA de Fase 1 (Scamper 6 métodos), Fase 2 (tracelb 5 modos) y Fase 3 (RIPE Atlas Ida).
    2. Todos los saltos y métodos de VUELTA de Fase 4 (RIPE Atlas Vuelta UDP, ICMP, TCP).
    3. Enlaces de emparejamiento /30 entre las interfaces de ida y vuelta del mismo router.
    """
    target_ip = cfg["target_ip"]
    origin_ip = "181.42.130.114"

    # Estructura de nodos: ip -> {hops_ida: set, hops_vuelta: set, methods_ida: set, methods_vuelta: set}
    nodes_info = {}

    def ensure_node(ip):
        if ip not in nodes_info:
            asn, holder, prefix = get_ip_meta(ip)
            nodes_info[ip] = {
                "ip": ip,
                "asn": asn,
                "holder": holder,
                "prefix": prefix,
                "hops_ida": set(),
                "hops_vuelta": set(),
                "methods_ida": set(),
                "methods_vuelta": set(),
            }
        return nodes_info[ip]

    # Asegurar nodo origen (BAF) y nodo destino (Sonda)
    n_orig = ensure_node(origin_ip)
    n_orig["hops_ida"].add(0)
    n_orig["methods_ida"].add("Origen BAF (Entel AS27651)")

    n_dest = ensure_node(target_ip)

    # Aristas: (u, v, direction) -> {methods: set, hop_label: str}
    edges_info = {}

    def add_edge(u, v, direction, method_label, hop_label=""):
        if not u or not v or u == "*" or v == "*" or u == v:
            return
        key = (u, v, direction)
        if key not in edges_info:
            edges_info[key] = {"methods": set(), "hop_labels": set()}
        edges_info[key]["methods"].add(method_label)
        if hop_label:
            edges_info[key]["hop_labels"].add(hop_label)

    # 1. Agregar rutas de Fase 1 (Scamper trace 6 métodos)
    for m, mdata in f1_sum[slug].items():
        hops_dict = mdata["hops"]
        sorted_h = sorted(int(k) for k in hops_dict.keys())
        prev_ip = origin_ip
        prev_h = 0
        for h in sorted_h:
            ip = hops_dict[str(h)]["addr"]
            if not ip or ip == "*":
                continue
            nd = ensure_node(ip)
            nd["hops_ida"].add(h)
            nd["methods_ida"].add(f"scamper-{m}")
            hop_lbl = f"Ida Hop {prev_h}->{h}" if h == prev_h + 1 else f"Ida Hop {prev_h}->..->{h}"
            add_edge(prev_ip, ip, "IDA", f"scamper-{m}", hop_lbl)
            prev_ip = ip
            prev_h = h

    # 2. Agregar rutas y enlaces de Fase 2 (Scamper tracelb 5 modos)
    for mode, mdata in f2_sum[slug].items():
        for ip in mdata["ips"]:
            if ip and ip != "*":
                nd = ensure_node(ip)
                nd["methods_ida"].add(f"tracelb-{mode}")
        # Parsear enlaces explícitos del texto de tracelb (formato 'A -> B')
        txt = mdata.get("txt", "")
        for line in txt.splitlines():
            if "->" not in line or line.startswith("tracelb from"):
                continue
            parts = [p.strip() for p in line.split("->")]
            for i in range(len(parts) - 1):
                left_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", parts[i])
                right_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", parts[i + 1])
                for lip in left_ips:
                    for rip in right_ips:
                        ensure_node(lip)["methods_ida"].add(f"tracelb-{mode}")
                        ensure_node(rip)["methods_ida"].add(f"tracelb-{mode}")
                        add_edge(lip, rip, "IDA", f"tracelb-{mode}", "Enlace tracelb (ECMP)")

    # 3. Agregar rutas de Fase 3 (RIPE Atlas Ida: UDP, ICMP, TCP)
    for proto, pdata in f3_sum[slug].items():
        hops_dict = pdata["hops"]
        sorted_h = sorted(int(k) for k in hops_dict.keys())
        prev_ip = origin_ip
        prev_h = 0
        for h in sorted_h:
            ip = hops_dict[str(h)]["primary_ip"]
            if not ip or ip == "*":
                continue
            nd = ensure_node(ip)
            nd["hops_ida"].add(h)
            nd["methods_ida"].add(f"ripe-ida-{proto}")
            add_edge(prev_ip, ip, "IDA", f"ripe-ida-{proto}", f"RIPE Ida Hop {prev_h}->{h}")
            prev_ip = ip
            prev_h = h

    # 4. Agregar rutas de Fase 4 (RIPE Atlas Vuelta: UDP, ICMP, TCP)
    for proto, pdata in f4_sum[slug].items():
        vhops = pdata["vuelta_hops"]
        sorted_h = sorted(int(k) for k in vhops.keys())
        prev_ip = target_ip
        prev_h = 0
        for h in sorted_h:
            ips_at_hop = [x for x in vhops[str(h)]["ips"] if x and x != "*"]
            if not ips_at_hop:
                continue
            for ip in ips_at_hop:
                nd = ensure_node(ip)
                nd["hops_vuelta"].add(h)
                nd["methods_vuelta"].add(f"ripe-vuelta-{proto}")
                hop_lbl = f"Vuelta Hop {prev_h}->{h}" if h == prev_h + 1 else f"Vuelta Hop {prev_h}->..->{h}"
                add_edge(prev_ip, ip, "VUELTA", f"ripe-vuelta-{proto}", hop_lbl)
            prev_ip = ips_at_hop[0]
            prev_h = h
        # Conectar el último salto visible de vuelta hacia nuestra IP pública BAF (indicando salto tras borde/CGNAT)
        if prev_ip != target_ip:
            add_edge(prev_ip, origin_ip, "VUELTA", f"ripe-vuelta-{proto}", f"Llegada a BAF Entel (tras Hop {prev_h} vuelta)")

    # 5. Agregar enlaces de correlación de router (/30 o asimetría documentada)
    for u_ip, v_ip, label in cfg["slash30_pairs"]:
        if u_ip in nodes_info and v_ip in nodes_info:
            add_edge(u_ip, v_ip, "PAR_ROUTER_/30", "Correlación Subred /30 Ida-Vuelta", label)

    # Construir NiceCXNetwork
    cx = NiceCXNetwork()
    cx.set_name(cfg["title"])

    desc = (
        f"Grafo de Topología Completa (Ida y Vuelta) — Tarea Individual Path Discovery (UDP).\n"
        f"- ISP Origen (BAF): ENTEL CHILE S.A. (AS27651) | IP Pública: 181.42.130.114 | Prefijo BGP: 181.42.128.0/21 | Sonda RIPE Atlas Origen: 1018519 (Docker)\n"
        f"- Sonda Destino: {cfg['location']} | IP: {target_ip} (Sonda RIPE Atlas ID {cfg['probe_id']})\n"
        f"- IDs de Medición RIPE Atlas Principales (Requisito 4.3): IDA = {cfg['primary_msm_ida']} | VUELTA = {cfg['primary_msm_vuelta']}\n"
        f"- Todos los IDs RIPE Atlas IDA (Sonda 1018519 -> {target_ip}): UDP={cfg['all_msm_ida']['UDP']}, ICMP={cfg['all_msm_ida']['ICMP']}, TCP={cfg['all_msm_ida']['TCP']}\n"
        f"- Todos los IDs RIPE Atlas VUELTA (Sonda {cfg['probe_id']} -> 181.42.130.114): UDP={cfg['all_msm_vuelta']['UDP']}, ICMP={cfg['all_msm_vuelta']['ICMP']}, TCP={cfg['all_msm_vuelta']['TCP']}\n"
        f"- Criterio de Ruta Más Completa (Requisito 4.1): Fusión de la ruta directa de Scamper v20260902 (ICMP/ICMP-Paris/UDP/UDP-Paris/TCP-ACK + ramas ECMP descubiertas por tracelb) "
        f"con la ruta de RIPE Atlas de Ida y la ruta de RIPE Atlas de Vuelta, maximizando la visibilidad de nodos IP ({len(nodes_info)} IPs únicas y {len(edges_info)} enlaces dirigidos)."
    )
    cx.set_network_attribute("description", desc)
    cx.set_network_attribute("version", "1.0 - Scamper 20260902 + RIPE Atlas")
    cx.set_network_attribute("isp_origen", "ENTEL CHILE S.A. (AS27651)")
    cx.set_network_attribute("ip_publica_baf", "181.42.130.114")
    cx.set_network_attribute("prefijo_bgp_baf", "181.42.128.0/21")
    cx.set_network_attribute("probe_id_origen", "1018519")
    cx.set_network_attribute("probe_id_destino", str(cfg["probe_id"]))
    cx.set_network_attribute("ip_destino", target_ip)
    cx.set_network_attribute("ripe_measurement_id_ida", str(cfg["primary_msm_ida"]))
    cx.set_network_attribute("ripe_measurement_id_vuelta", str(cfg["primary_msm_vuelta"]))

    # Crear nodos y asignar coordenadas para layout limpio
    ip_to_node_id = {}
    cartesian_layout = []

    # Ordenar nodos para layout:
    # - Fila superior (y = -180 a -80): Nodos exclusivos de IDA ordenados por hop_ida mínimo
    # - Fila central (y = 0): Origen (x=0), Nodos compartidos IDA y VUELTA, Destino (x=max)
    # - Fila inferior (y = +180 a +80): Nodos exclusivos de VUELTA ordenados inversamente para cerrar el ciclo
    for ip, info in nodes_info.items():
        h_ida = sorted(info["hops_ida"])
        h_vuelta = sorted(info["hops_vuelta"])
        if ip == origin_ip:
            role = "ORIGEN_BAF"
        elif ip == target_ip:
            role = "DESTINO_SONDA"
        elif h_ida and h_vuelta:
            role = "IDA_Y_VUELTA"
        elif h_ida or info["methods_ida"]:
            role = "IDA"
        else:
            role = "VUELTA"
        info["role"] = role

        hop_ida_str = ",".join(str(x) for x in h_ida) if h_ida else ("ECMP-tracelb" if info["methods_ida"] else "N/A")
        hop_vuelta_str = ",".join(str(x) for x in h_vuelta) if h_vuelta else "N/A"
        hop_combined = f"Ida:{hop_ida_str} | Vuelta:{hop_vuelta_str}"

        label = f"{ip}\n({info['asn']})"
        nid = cx.create_node(node_name=ip, node_represents= f"{ip} [{info['asn']} - {info['holder']}]")
        ip_to_node_id[ip] = nid

        cx.set_node_attribute(nid, "ip", ip)
        cx.set_node_attribute(nid, "label", label)
        cx.set_node_attribute(nid, "hop", hop_combined)
        cx.set_node_attribute(nid, "hop_ida", hop_ida_str)
        cx.set_node_attribute(nid, "hop_vuelta", hop_vuelta_str)
        cx.set_node_attribute(nid, "as", info["asn"])
        cx.set_node_attribute(nid, "isp", info["holder"])
        cx.set_node_attribute(nid, "prefix", info["prefix"])
        cx.set_node_attribute(nid, "direction", role)
        all_methods = sorted(info["methods_ida"] | info["methods_vuelta"])
        cx.set_node_attribute(nid, "methods", ", ".join(all_methods))

        # Calcular coordenadas (x, y)
        if role == "ORIGEN_BAF":
            x, y = 0.0, 0.0
        elif role == "DESTINO_SONDA":
            x, y = 1600.0, 0.0
        elif role == "IDA_Y_VUELTA":
            min_h = min(h_ida) if h_ida else 10
            x = min_h * 110.0
            y = 0.0
        elif role == "IDA":
            min_h = min(h_ida) if h_ida else 12
            # Desplazar ligeramente en Y si hay varios nodos en el mismo hop (ECMP)
            offset_y = (hash(ip) % 3 - 1) * 55.0
            x = min_h * 100.0
            y = -180.0 + offset_y
        else:  # VUELTA
            min_hv = min(h_vuelta) if h_vuelta else 5
            offset_y = (hash(ip) % 3 - 1) * 55.0
            x = max(120.0, 1600.0 - min_hv * 130.0)
            y = 180.0 + offset_y

        cartesian_layout.append({"node": nid, "x": float(x), "y": float(y)})

    # Agregar aspecto cartesianLayout para que NDExBio muestre el grafo ordenado
    cx.set_opaque_aspect("cartesianLayout", cartesian_layout)

    # Crear aristas
    for (u_ip, v_ip, direction), edata in edges_info.items():
        u_id = ip_to_node_id[u_ip]
        v_id = ip_to_node_id[v_ip]
        eid = cx.create_edge(edge_source=u_id, edge_target=v_id, edge_interaction=direction)
        cx.set_edge_attribute(eid, "direction", direction)
        cx.set_edge_attribute(eid, "methods", ", ".join(sorted(edata["methods"])))
        cx.set_edge_attribute(eid, "hop_transition", "; ".join(sorted(edata["hop_labels"])))

    return cx, nodes_info, edges_info


def main():
    print(f"Conectando a NDExBio ({NDEX_SERVER}) con usuario '{NDEX_USER}'...")
    client = ndex2.client.Ndex2(NDEX_SERVER, NDEX_USER, NDEX_PASS)
    client.update_status()
    print("Autenticación en NDExBio exitosa.")

    summary_out = {}

    for slug, cfg in TARGETS_CFG.items():
        print(f"\nConstruyendo grafo completo para {slug.upper()} ({cfg['target_ip']})...")
        cx, nodes_info, edges_info = build_complete_graph_for_target(slug, cfg)

        # Guardar respaldo local CX
        local_cx_path = DATA_F5 / f"ndex_graph_{slug}_{cfg['target_ip']}.cx"
        with open(local_cx_path, "w", encoding="utf-8") as f:
            json.dump(cx.to_cx(), f, indent=2, ensure_ascii=False)
        print(f"Respaldo local CX guardado en: {local_cx_path.name} ({len(nodes_info)} nodos, {len(edges_info)} aristas)")

        # Subir a NDExBio
        raw_url = client.save_new_network(cx.to_cx(), visibility="PUBLIC")
        uuid = raw_url.rstrip("/").split("/")[-1]
        print(f"Subido a NDExBio -> UUID: {uuid}")

        # Asegurar visibilidad PUBLIC explícitamente
        try:
            client.make_network_public(uuid)
        except Exception as e:
            print(f"Nota make_network_public: {e}")
        try:
            client.update_network_system_properties(uuid, {"visibility": "PUBLIC"})
        except Exception as e:
            print(f"Nota update_network_system_properties: {e}")

        # Verificar resumen público vía API REST sin credenciales
        ver_resp = requests.get(f"https://www.ndexbio.org/v2/network/{uuid}/summary", timeout=15)
        ver_json = ver_resp.json() if ver_resp.status_code == 200 else {}
        vis = ver_json.get("visibility", "UNKNOWN")
        node_cnt = ver_json.get("nodeCount", len(nodes_info))
        edge_cnt = ver_json.get("edgeCount", len(edges_info))
        print(f"Verificación pública HTTP {ver_resp.status_code}: visibility={vis}, nodes={node_cnt}, edges={edge_cnt}")

        # Contar nodos por sentido
        ida_ips = sorted([ip for ip, d in nodes_info.items() if d["role"] in ("ORIGEN_BAF", "DESTINO_SONDA", "IDA", "IDA_Y_VUELTA")])
        vuelta_ips = sorted([ip for ip, d in nodes_info.items() if d["role"] in ("ORIGEN_BAF", "DESTINO_SONDA", "VUELTA", "IDA_Y_VUELTA")])
        shared_ips = sorted([ip for ip, d in nodes_info.items() if d["role"] == "IDA_Y_VUELTA"])

        summary_out[slug] = {
            "title": cfg["title"],
            "target_ip": cfg["target_ip"],
            "probe_id": cfg["probe_id"],
            "uuid": uuid,
            "viewer_url": f"https://www.ndexbio.org/viewer/networks/{uuid}",
            "api_summary_url": f"https://www.ndexbio.org/v2/network/{uuid}/summary",
            "visibility": vis,
            "node_count": node_cnt,
            "edge_count": edge_cnt,
            "primary_msm_ida": cfg["primary_msm_ida"],
            "primary_msm_vuelta": cfg["primary_msm_vuelta"],
            "all_msm_ida": cfg["all_msm_ida"],
            "all_msm_vuelta": cfg["all_msm_vuelta"],
            "total_unique_ips": sorted(nodes_info.keys()),
            "ida_ips": ida_ips,
            "vuelta_ips": vuelta_ips,
            "shared_ips": shared_ips,
            "nodes_detail": [
                {
                    "ip": ip,
                    "role": d["role"],
                    "hop_ida": sorted(d["hops_ida"]),
                    "hop_vuelta": sorted(d["hops_vuelta"]),
                    "asn": d["asn"],
                    "holder": d["holder"],
                    "prefix": d["prefix"],
                    "methods": sorted(d["methods_ida"] | d["methods_vuelta"]),
                }
                for ip, d in sorted(nodes_info.items(), key=lambda x: (min(x[1]["hops_ida"]) if x[1]["hops_ida"] else 99, x[0]))
            ],
        }

    # Guardar resumen JSON
    sum_path = RES_DIR / "fase5_ndex_summary.json"
    sum_path.write_text(json.dumps(summary_out, indent=2, ensure_ascii=False), encoding="utf-8")

    # Generar reporte Markdown de Fase 5
    md_lines = [
        "# RESULTADOS FASE 5 — PUBLIC PATH EN NDExBio (Puntos 4.1, 4.2 y 4.3)\n",
        "## Resumen de Grafos Publicados y UUIDs (Requisito 4.3)\n",
        "| Destino | IP Sonda (ID) | Nodos Totales | Aristas | ID RIPE IDA | ID RIPE VUELTA | Visibilidad | UUID en NDExBio | Enlace Público NDExBio |",
        "| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :--- | :--- |",
    ]
    for slug, s in summary_out.items():
        md_lines.append(
            f"| **{slug.capitalize()}** | `{s['target_ip']}` (`{s['probe_id']}`) | **{s['node_count']}** | **{s['edge_count']}** | "
            f"`{s['primary_msm_ida']}` | `{s['primary_msm_vuelta']}` | `{s['visibility']}` | **`{s['uuid']}`** | "
            f"[Ver Grafo]({s['viewer_url']}) |"
        )

    for slug, s in summary_out.items():
        md_lines.append(f"\n---\n\n## Detalle de Nodos del Grafo — {slug.capitalize()} (`{s['target_ip']}`) — UUID: `{s['uuid']}`\n")
        md_lines.append(f"- **URL Pública del Grafo**: {s['viewer_url']}")
        md_lines.append(f"- **IDs de Medición RIPE Atlas incluidos en la descripción**: IDA = `{s['primary_msm_ida']}` | VUELTA = `{s['primary_msm_vuelta']}`\n")
        md_lines.append("| IP Nodo | Sentido / Rol | Hop Ida | Hop Vuelta | AS | ISP / Operador | Prefijo BGP |")
        md_lines.append("| :--- | :--- | :-: | :-: | :--- | :--- | :--- |")
        for nd in s["nodes_detail"]:
            hi = ",".join(str(x) for x in nd["hop_ida"]) if nd["hop_ida"] else "—"
            hv = ",".join(str(x) for x in nd["hop_vuelta"]) if nd["hop_vuelta"] else "—"
            md_lines.append(
                f"| `{nd['ip']}` | `{nd['role']}` | {hi} | {hv} | **{nd['asn']}** | {nd['holder']} | `{nd['prefix']}` |"
            )

    md_path = RES_DIR / "fase5_analysis_raw.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"\nReporte de Fase 5 guardado en: {md_path}")


if __name__ == "__main__":
    main()

