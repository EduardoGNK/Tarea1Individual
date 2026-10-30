#!/usr/bin/env bash
# Script: run_fase2_scamper_tracelb.sh
# Descripcion: Ejecuta scamper (version 20260902) con la opcion tracelb en sus 5 modos
#              (udp-dport, icmp-echo, udp-sport, tcp-sport, tcp-ack-sport) para las 3 IPs destino,
#              capturando cada traza en un archivo .pcap independiente y exportando .warts, .json y .txt.
set -e

WORKDIR="/mnt/h/VisualStudio.js/Alg Rut Tarea 1 Individual/tarea"
DATADIR="$WORKDIR/data/fase2_tracelb"
LOGFILE="$DATADIR/execution_log_fase2.txt"
mkdir -p "$DATADIR"

echo "================================================================" | tee "$LOGFILE"
echo "FASE 2 - SCAMPER TRACELB (5 MODOS x 3 IPs)" | tee -a "$LOGFILE"
echo "Fecha inicio: $(date -Is)" | tee -a "$LOGFILE"
echo "Scamper version: $(scamper -v 2>&1)" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"

declare -A TARGETS=(
    ["valparaiso"]="138.204.230.242"
    ["habana"]="200.14.48.134"
    ["rusia"]="37.79.226.46"
)

# Los 5 modos de tracelb en scamper (-P):
# udp-dport, icmp-echo, udp-sport, tcp-sport, tcp-ack-sport
MODES=("udp-dport" "icmp-echo" "udp-sport" "tcp-sport" "tcp-ack-sport")

for name in "valparaiso" "habana" "rusia"; do
    ip="${TARGETS[$name]}"
    for mode in "${MODES[@]}"; do
        prefix="${DATADIR}/tracelb_${name}_${ip}_${mode}"
        pcap_file="${prefix}.pcap"
        warts_file="${prefix}.warts"
        json_file="${prefix}.json"
        txt_file="${prefix}.txt"

        echo "" | tee -a "$LOGFILE"
        echo "[$(date -Is)] >>> Ejecutando tracelb: Destino=$name ($ip) | Modo=$mode" | tee -a "$LOGFILE"
        echo "Comando tcpdump: tcpdump -i eth0 -n -U -w \"$pcap_file\" \"host $ip or icmp\"" | tee -a "$LOGFILE"
        echo "Comando scamper: scamper -O warts -o \"$warts_file\" -c \"tracelb -P $mode\" -i $ip" | tee -a "$LOGFILE"

        # Iniciar captura tcpdump filtrando por IP destino o mensajes ICMP
        tcpdump -i eth0 -n -U -w "$pcap_file" "host $ip or icmp" >/dev/null 2>&1 &
        TCPDUMP_PID=$!
        sleep 1

        # Ejecutar scamper tracelb con parametros por defecto
        scamper -O warts -o "$warts_file" -c "tracelb -P $mode" -i "$ip"

        # Esperar 1 segundo para capturar respuestas tardias y detener tcpdump
        sleep 1
        kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true

        # Exportar .warts a .json y .txt
        sc_warts2json "$warts_file" > "$json_file"
        sc_warts2text "$warts_file" > "$txt_file"

        cat "$txt_file" | tee -a "$LOGFILE"
        pkt_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l)
        echo "[$(date -Is)] <<< Finalizado tracelb: $mode -> $name ($pkt_count paquetes capturados en .pcap)" | tee -a "$LOGFILE"
    done
done

echo "" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"
echo "Fecha fin: $(date -Is)" | tee -a "$LOGFILE"
echo "================================================================" | tee -a "$LOGFILE"

