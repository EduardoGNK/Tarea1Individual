import json
import time
from datetime import datetime
from pathlib import Path
import requests

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATADIR = WORKDIR / "data" / "fase4_ripe_vuelta"
DATADIR.mkdir(parents=True, exist_ok=True)
LOGFILE = DATADIR / "execution_log_fase4.txt"

with open(WORKDIR / "data" / "config_fase0.json", "r", encoding="utf-8-sig") as f:
    CONFIG = json.load(f)

API_KEY = CONFIG["ripe_api_key"]
MY_PUBLIC_IP = CONFIG["public_ip"]  # 181.42.130.114
HEADERS = {
    "Authorization": f"Key {API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Las 3 sondas origen que ahora miden hacia nuestra IP publica BAF (181.42.130.114)
SOURCES = [
    ("valparaiso", "138.204.230.242", 6652),
    ("habana", "200.14.48.134", 12734),
    ("rusia", "37.79.226.46", 3959),
]
PROTOCOLS = ["UDP", "ICMP", "TCP"]
SCAMPER_PORT = 33435

def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOGFILE, "a", encoding="utf-8") as lf:
        lf.write(line + "\n")

def create_reverse_measurement(slug, src_ip, src_probe_id, proto):
    definition = {
        "target": MY_PUBLIC_IP,
        "af": 4,
        "type": "traceroute",
        "description": f"UDP Tarea 1 Vuelta {proto} from {slug} (probe {src_probe_id}) to {MY_PUBLIC_IP}",
        "protocol": proto,
        "resolve_on_probe": True,
        "skip_dns_check": False,
        "packets": 3,
        "size": 48,
        "first_hop": 1,
        "max_hops": 32,
        "paris": 16,
        "response_timeout": 4000,
        "dont_fragment": False,
        "is_oneoff": True,
    }
    if proto in ("UDP", "TCP"):
        definition["port"] = SCAMPER_PORT

    payload = {
        "definitions": [definition],
        "probes": [
            {
                "value": str(src_probe_id),
                "type": "probes",
                "requested": 1,
            }
        ],
        "is_oneoff": True,
    }

    log(f"Creando medición VUELTA: {proto} desde {slug} (probe {src_probe_id}) -> {MY_PUBLIC_IP}...")
    for attempt in range(5):
        try:
            resp = requests.post("https://atlas.ripe.net/api/v2/measurements/", headers=HEADERS, json=payload, timeout=30)
            if resp.status_code in (200, 201):
                msm_id = resp.json()["measurements"][0]
                log(f"Medición VUELTA creada: ID = {msm_id} ({slug} {proto})")
                return msm_id, payload
            log(f"Aviso POST ({resp.status_code}): {resp.text}. Reintentando en 10s...")
            time.sleep(10)
        except Exception as e:
            log(f"Excepción en POST (intento {attempt+1}): {e}")
            time.sleep(10)
    raise RuntimeError(f"No se pudo crear medición vuelta para {slug} {proto}")

def main():
    LOGFILE.write_text("================================================================\n", encoding="utf-8")
    log(f"FASE 4 - RIPE ATLAS TRACEROUTE VUELTA (3 SONDAS -> {MY_PUBLIC_IP} x 3 PROTOCOLOS)")

    # Lanzar las 9 mediciones en paralelo para ahorrar tiempo (son sondas remotas distintas)
    pending = []
    manifest = {}
    for slug, src_ip, src_probe_id in SOURCES:
        manifest[slug] = {}
        for proto in PROTOCOLS:
            p_low = proto.lower()
            json_name = f"ripe_vuelta_{slug}_{src_ip}_{p_low}.json"
            jpath = DATADIR / json_name
            if jpath.exists():
                existing = json.loads(jpath.read_text(encoding="utf-8"))
                if len(existing.get("results", [])) > 0:
                    log(f"Saltando {slug} {proto} (ya existe con msm_id={existing['measurement_id']}).")
                    manifest[slug][p_low] = {
                        "measurement_id": existing["measurement_id"],
                        "json": json_name,
                        "has_results": True,
                    }
                    continue
            msm_id, req_payload = create_reverse_measurement(slug, src_ip, src_probe_id, proto)
            pending.append((slug, src_ip, src_probe_id, proto, msm_id, req_payload, jpath, json_name))
            time.sleep(2)

    # Esperar resultados de las 9 mediciones
    start_time = time.time()
    completed_ids = set()
    while len(completed_ids) < len(pending) and (time.time() - start_time) < 360:
        time.sleep(8)
        for slug, src_ip, src_probe_id, proto, msm_id, req_payload, jpath, json_name in pending:
            if msm_id in completed_ids:
                continue
            try:
                r = requests.get(f"https://atlas.ripe.net/api/v2/measurements/{msm_id}/results/", headers=HEADERS, timeout=25)
                if r.status_code == 200 and len(r.json()) > 0:
                    results_data = r.json()
                    out_obj = {
                        "measurement_id": msm_id,
                        "timestamp": datetime.now().isoformat(),
                        "source_probe": src_probe_id,
                        "source_ip": src_ip,
                        "source_slug": slug,
                        "target_ip": MY_PUBLIC_IP,
                        "protocol": proto,
                        "port": SCAMPER_PORT if proto in ("UDP", "TCP") else None,
                        "request_payload": req_payload,
                        "results": results_data,
                    }
                    jpath.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
                    manifest[slug][proto.lower()] = {
                        "measurement_id": msm_id,
                        "json": json_name,
                        "has_results": True,
                    }
                    completed_ids.add(msm_id)
                    log(f"Recibido y guardado resultado de {slug} {proto} (msm_id={msm_id}) [{len(completed_ids)}/{len(pending)}].")
            except Exception as e:
                log(f"Reintentando consulta de {msm_id}: {e}")

    # Para cualquiera que no haya entregado resultado en 360s, guardar estado igualmente
    for slug, src_ip, src_probe_id, proto, msm_id, req_payload, jpath, json_name in pending:
        if msm_id not in completed_ids:
            log(f"Aviso: medición {msm_id} ({slug} {proto}) aún sin resultados tras timeout.")
            manifest[slug][proto.lower()] = {
                "measurement_id": msm_id,
                "json": json_name,
                "has_results": False,
            }

    (DATADIR / "manifest_fase4.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    log("FASE 4 EJECUCIÓN COMPLETADA.")

if __name__ == "__main__":
    main()

