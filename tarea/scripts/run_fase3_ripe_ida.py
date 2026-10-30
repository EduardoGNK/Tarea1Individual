import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
import requests

WORKDIR = Path(r"h:\VisualStudio.js\Alg Rut Tarea 1 Individual\tarea")
DATADIR = WORKDIR / "data" / "fase3_ripe_ida"
DATADIR.mkdir(parents=True, exist_ok=True)
LOGFILE = DATADIR / "execution_log_fase3.txt"

with open(WORKDIR / "data" / "config_fase0.json", "r", encoding="utf-8-sig") as f:
    CONFIG = json.load(f)

API_KEY = CONFIG["ripe_api_key"]
MY_PROBE_ID = CONFIG["my_probe_id"]  # 1018519
HEADERS = {
    "Authorization": f"Key {API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

TARGETS = [
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

def start_sniffer(pcap_filename, target_ip):
    subprocess.run(["docker", "rm", "-f", "ripe-sniffer"], capture_output=True)
    mount_path = str(DATADIR.resolve())
    bpf_filter = f"host {target_ip} or icmp"
    cmd = [
        "docker", "run", "-d", "--name", "ripe-sniffer",
        "--net", "container:ripe-atlas",
        "-v", f"{mount_path}:/captures",
        "ripe-sniffer:local",
        "tcpdump", "-i", "eth0", "-n", "-U", "-w", f"/captures/{pcap_filename}", bpf_filter
    ]
    log(f"Iniciando captura Docker: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    time.sleep(2)

def stop_sniffer():
    time.sleep(2)
    subprocess.run(["docker", "stop", "-t", "2", "ripe-sniffer"], capture_output=True)
    subprocess.run(["docker", "rm", "-f", "ripe-sniffer"], capture_output=True)

def create_and_wait_measurement(slug, target_ip, proto):
    definition = {
        "target": target_ip,
        "af": 4,
        "type": "traceroute",
        "description": f"UDP Tarea 1 Ida {proto} to {slug} ({target_ip})",
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
                "value": str(MY_PROBE_ID),
                "type": "probes",
                "requested": 1,
            }
        ],
        "is_oneoff": True,
    }

    log(f"Creando medición RIPE Atlas: {proto} -> {slug} ({target_ip}) desde sonda {MY_PROBE_ID}...")
    for attempt in range(5):
        try:
            resp = requests.post("https://atlas.ripe.net/api/v2/measurements/", headers=HEADERS, json=payload, timeout=30)
            if resp.status_code in (200, 201):
                break
            log(f"Aviso POST ({resp.status_code}): {resp.text}. Reintentando en 10s...")
            time.sleep(10)
        except Exception as e:
            log(f"Excepción en POST (intento {attempt+1}): {e}")
            time.sleep(10)
    else:
        raise RuntimeError("No se pudo crear la medición tras 5 intentos.")

    msm_id = resp.json()["measurements"][0]
    log(f"Medición creada exitosamente: ID = {msm_id}")

    result_url = f"https://atlas.ripe.net/api/v2/measurements/{msm_id}/results/"
    start_wait = time.time()
    results_data = []
    while time.time() - start_wait < 300:
        time.sleep(7)
        try:
            r = requests.get(result_url, headers=HEADERS, timeout=25)
            if r.status_code == 200 and len(r.json()) > 0:
                results_data = r.json()
                log(f"Resultado recibido en API para medición {msm_id} tras {int(time.time() - start_wait)}s.")
                break
        except Exception as e:
            log(f"Timeout/error temporal consultando {msm_id}, reintentando...: {e}")
    return msm_id, payload, results_data

def main():
    # Si la medición 229623295 (Habana ICMP) ya terminó y su pcap tiene paquetes, recuperémosla primero
    habana_icmp_json = DATADIR / "ripe_ida_habana_200.14.48.134_icmp.json"
    habana_icmp_pcap = DATADIR / "ripe_ida_habana_200.14.48.134_icmp.pcap"
    if not habana_icmp_json.exists() and habana_icmp_pcap.exists() and habana_icmp_pcap.stat().st_size > 200:
        try:
            r = requests.get("https://atlas.ripe.net/api/v2/measurements/229623295/results/", headers=HEADERS, timeout=25)
            if r.status_code == 200 and len(r.json()) > 0:
                out_obj = {
                    "measurement_id": 229623295,
                    "timestamp": datetime.now().isoformat(),
                    "source_probe": MY_PROBE_ID,
                    "target_slug": "habana",
                    "target_ip": "200.14.48.134",
                    "target_probe_id": 12734,
                    "protocol": "ICMP",
                    "port": None,
                    "results": r.json(),
                }
                habana_icmp_json.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
                log("Recuperado exitosamente JSON de medición 229623295 (Habana ICMP).")
        except Exception as e:
            log(f"No se pudo recuperar 229623295: {e}")

    manifest = {}
    for slug, target_ip, dst_probe_id in TARGETS:
        manifest[slug] = {}
        for proto in PROTOCOLS:
            p_low = proto.lower()
            pcap_name = f"ripe_ida_{slug}_{target_ip}_{p_low}.pcap"
            json_name = f"ripe_ida_{slug}_{target_ip}_{p_low}.json"
            jpath = DATADIR / json_name
            ppath = DATADIR / pcap_name

            if jpath.exists() and ppath.exists() and ppath.stat().st_size > 100:
                data = json.loads(jpath.read_text(encoding="utf-8"))
                if len(data.get("results", [])) > 0:
                    msm_id = data["measurement_id"]
                    log(f"Saltando {slug} {proto} (ya completado con msm_id={msm_id} y pcap válido).")
                    manifest[slug][p_low] = {
                        "measurement_id": msm_id,
                        "pcap": pcap_name,
                        "json": json_name,
                        "has_results": True,
                    }
                    continue

            start_sniffer(pcap_name, target_ip)
            try:
                msm_id, req_payload, results_data = create_and_wait_measurement(slug, target_ip, proto)
            finally:
                stop_sniffer()

            out_obj = {
                "measurement_id": msm_id,
                "timestamp": datetime.now().isoformat(),
                "source_probe": MY_PROBE_ID,
                "target_slug": slug,
                "target_ip": target_ip,
                "target_probe_id": dst_probe_id,
                "protocol": proto,
                "port": SCAMPER_PORT if proto in ("UDP", "TCP") else None,
                "request_payload": req_payload,
                "results": results_data,
            }
            jpath.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
            manifest[slug][p_low] = {
                "measurement_id": msm_id,
                "pcap": pcap_name,
                "json": json_name,
                "has_results": len(results_data) > 0,
            }
            log(f"Guardado {json_name} y {pcap_name} (msm_id={msm_id}).")

    (DATADIR / "manifest_fase3.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    log("FASE 3 EJECUCIÓN COMPLETADA.")

if __name__ == "__main__":
    main()
