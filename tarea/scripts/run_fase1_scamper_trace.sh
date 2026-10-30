#!/usr/bin/env bash
# Script: run_fase1_scamper_trace.sh
# Descripcion: Ejecuta scamper (version 20260902) para las 3 IPs destino con los 6 metodos de trace
#              capturando trafico individual en .pcap y guardando salidas .warts, .json y .txt.
set -e

WORKDIR="/mnt/h/VisualStudio.js/Alg Rut Tarea 1 Individual/tarea"
DATADIR="$WORKDIR/data/fase1_trace"
LOGFILE="$DATADIR/execution_log_fase1.txt"
mkdir -p "$DATADIR"

echo "================================================================" | tee "$LOGFILE"
echo "FASE 1 - SCAMPER TRACE (6 METODOS x 3 IPs)" | tee -a "$LOGFILE"
echo "Fecha inicio: $(date -Is)" | tee -a "$LOGFILE"
echo "Scamper version: $(scamper -v 2>&1)" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"

declare -A TARGETS=(
    ["valparaiso"]="138.204.230.242"
    ["habana"]="200.14.48.134"
    ["rusia"]="37.79.226.46"
)

# Los 6 metodos de trace en scamper (-P):
# udp, icmp, udp-paris, icmp-paris, tcp, tcp-ack
METHODS=("udp" "icmp" "udp-paris" "icmp-paris" "tcp" "tcp-ack")

for name in "valparaiso" "habana" "rusia"; do
    ip="${TARGETS[$name]}"
    for method in "${METHODS[@]}"; do
        prefix="${DATADIR}/trace_${name}_${ip}_${method}"
        pcap_file="${prefix}.pcap"
        warts_file="${prefix}.warts"
        json_file="${prefix}.json"
        txt_file="${prefix}.txt"

        echo "" | tee -a "$LOGFILE"
        echo "[$(date -Is)] >>> Ejecutando: Destino=$name ($ip) | Metodo=$method" | tee -a "$LOGFILE"
        echo "Comando tcpdump: tcpdump -i eth0 -n -U -w \"$pcap_file\" \"host $ip or icmp\"" | tee -a "$LOGFILE"
        echo "Comando scamper: scamper -O warts -o \"$warts_file\" -c \"trace -P $method\" -i $ip" | tee -a "$LOGFILE"

        # Iniciar captura tcpdump filtrando por IP destino o mensajes ICMP (Time Exceeded de routers intermedios)
        tcpdump -i eth0 -n -U -w "$pcap_file" "host $ip or icmp" >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        sleep 1

        # Ejecutar scamper con parametros por defecto para el metodo
        scamper -O warts -o "$warts_file" -c "trace -P $method" -i "$ip"

        # Esperar 1 segundo para capturar posibles respuestas tardias y cerrar tcpdump
        sleep 1
        kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true

        # Exportar .warts a .json y .txt
        sc_warts2json "$warts_file" > "$json_file"
        sc_warts2text "$warts_file" > "$txt_file"

        cat "$txt_file" | tee -a "$LOGFILE"
        pkt_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l)
        echo "[$(date -Is)] <<< Finalizado: $method -> $name ($pkt_count paquetes capturados en .pcap)" | tee -a "$LOGFILE"
    done
done

echo "" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"
echo "Fecha fin: $(date -Is)" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"

