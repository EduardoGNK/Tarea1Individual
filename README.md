# Path Discovery — Comparación de Tráfico entre RIPE Atlas y Scamper

**Universidad Diego Portales — Facultad de Ingeniería y Ciencias**  
**Escuela de Informática y Telecomunicaciones — Algoritmos de Ruteo y Redes**  
**Autor:** Eduardo Escalona

---

## 1. Infraestructura de Medición (Banda Ancha Fija — BAF) y Destinos

| Parámetro | Valor |
| :--- | :--- |
| **ISP de Origen (BAF)** | `ENTEL CHILE S.A.` (`AS27651`) |
| **Dirección IPv4 Pública BAF** | `181.42.130.114` |
| **Prefijo BGP Anunciado** | `181.42.128.0/21` |
| **Sonda RIPE Atlas Propia (Origen)** | `Probe ID 1018519` (*Home Software Probe — Docker*, `Connected`) |
| **Motor Scamper Compilado** | `scamper version 20260902` (CAIDA CVS en WSL2 Ubuntu) |
| **Destino 1 — Valparaíso, Chile (Mayor velocidad)** | `138.204.230.242` (`Probe ID 6652`, `AS61506` INSACOM SpA) |
| **Destino 2 — La Habana, Cuba (Menor velocidad)** | `200.14.48.134` (`Probe ID 12734`, `AS27725` ETECSA) |
| **Destino 3 — Rusia (Mayor censura reciente)** | `37.79.226.46` (`Probe ID 3959`, `AS12389` PJSC Rostelecom) |

---

## 2. Estructura del Proyecto

```text
├── README.md
└── tarea/
    ├── data/
    │   ├── config_fase0.json                 # Configuración de red, ASN y sondas destino
    │   ├── fase1_trace/                      # 18 trazas Scamper trace (.warts, .pcap, .json, .txt)
    │   ├── fase2_tracelb/                    # 15 trazas Scamper tracelb (.warts, .pcap, .json, .txt)
    │   ├── fase3_ripe_ida/                   # 9 mediciones RIPE Atlas de Ida (.json) + capturas .pcap
    │   ├── fase4_ripe_vuelta/                # 9 mediciones RIPE Atlas de Vuelta (.json)
    │   └── fase5_ndex/                       # 3 grafos topológicos en formato CX (.cx)
    ├── results/
    │   ├── asn_cache.json                    # Caché de resolución ASN / ISP / Prefijos BGP (RIPEstat)
    │   ├── fase1_routes_summary.json         # Resumen estructurado Parte 1.1–1.4 (Scamper trace)
    │   ├── fase2_tracelb_summary.json        # Resumen estructurado Parte 1.5–1.7 (Scamper tracelb)
    │   ├── fase3_ripe_ida_summary.json       # Resumen estructurado Parte 2 (RIPE Atlas Ida)
    │   ├── fase4_ripe_vuelta_summary.json    # Resumen estructurado Parte 3 (RIPE Atlas Vuelta)
    │   └── fase5_ndex_summary.json           # Resumen estructurado Parte 4 (NDExBio UUIDs y nodos)
    └── scripts/
        ├── run_fase1_scamper_trace.sh        # Ejecución de Scamper trace (6 métodos × 3 IPs) + tcpdump
        ├── analyze_fase1.py                  # Análisis de rutas y paquetes de Scamper trace
        ├── run_fase2_scamper_tracelb.sh      # Ejecución de Scamper tracelb (5 modos × 3 IPs) + tcpdump
        ├── analyze_fase2.py                  # Análisis de balanceadores ECMP y flow-ids en tracelb
        ├── run_fase3_ripe_ida.py             # Creación y recolección de traceroutes RIPE Atlas de Ida
        ├── analyze_fase3.py                  # Análisis de rutas, ASNs y paquetes de RIPE Atlas de Ida
        ├── run_fase4_ripe_vuelta.py          # Creación y recolección de traceroutes RIPE Atlas de Vuelta
        ├── analyze_fase4.py                  # Construcción de Tablas 2 y análisis de asimetría Ida/Vuelta
        └── run_fase5_ndex.py                 # Construcción y publicación de los 3 grafos en NDExBio (ndex2)
```

---

## 3. Identificadores de Medición RIPE Atlas y Grafos Públicos en NDExBio

### 3.1. Mediciones RIPE Atlas (`port = 33435`)
* **Valparaíso (`138.204.230.242` — Sonda `6652`)**:
  * **Ida** (`1018519` $\to$ `138.204.230.242`): `UDP = 229621225` | `ICMP = 229621764` | `TCP = 229622098`
  * **Vuelta** (`6652` $\to$ `181.42.130.114`): `UDP = 229638773` | `ICMP = 229638791` | `TCP = 229638809`
* **La Habana (`200.14.48.134` — Sonda `12734`)**:
  * **Ida** (`1018519` $\to$ `200.14.48.134`): `UDP = 229622916` | `ICMP = 229623295` | `TCP = 229623665`
  * **Vuelta** (`12734` $\to$ `181.42.130.114`): `UDP = 229638824` (Ref: `228016823`) | `ICMP = 229638841` (Ref: `228016959`) | `TCP = 229638856` (Ref: `228017080`)
* **Rusia (`37.79.226.46` — Sonda `3959`)**:
  * **Ida** (`1018519` $\to$ `37.79.226.46`): `UDP = 229623802` | `ICMP = 229624261` | `TCP = 229624325`
  * **Vuelta** (`3959` $\to$ `181.42.130.114`): `UDP = 229638870` | `ICMP = 229638887` | `TCP = 229638899`

### 3.2. Grafos Públicos en NDExBio (Usuario: `gnk`)
1. **Valparaíso (`138.204.230.242` — 18 nodos, 27 aristas)**:
   * **UUID**: `d7f709ad-d441-11f1-bda1-005056ae3c32`
   * **URL**: https://www.ndexbio.org/viewer/networks/d7f709ad-d441-11f1-bda1-005056ae3c32
2. **La Habana, Cuba (`200.14.48.134` — 35 nodos, 55 aristas)**:
   * **UUID**: `d91b1750-d441-11f1-bda1-005056ae3c32`
   * **URL**: https://www.ndexbio.org/viewer/networks/d91b1750-d441-11f1-bda1-005056ae3c32
3. **Rusia (`37.79.226.46` — 27 nodos, 37 aristas)**:
   * **UUID**: `da0ec623-d441-11f1-bda1-005056ae3c32`
   * **URL**: https://www.ndexbio.org/viewer/networks/da0ec623-d441-11f1-bda1-005056ae3c32
