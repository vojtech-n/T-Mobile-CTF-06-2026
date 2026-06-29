#!/bin/bash

DOMAIN="t-mobile.cz"
RAW_S="subfinder_o.txt"
HOST_IP="host_w_ip.txt"
FINAL="final_report.txt"

echo "1 -- Starting subfinder for domain $DOMAIN..."

subfinder -d "$DOMAIN" >> "$RAW_S"

echo "2.0 -- Getting IP Address for each subdomain in $RAW_S..."
echo "Host,IP" > "$HOST_IP"

while read -r subd; do
  if [ -n "$subd" ]; then
    ips=$(dig +short "$subd" | grep -E "^[0-9.]+$")

    for ip in $ips; do
      echo "$subd,$ip" >> "$HOST_IP"
      echo "found: $subd has IP $ip"
    done
  fi
done < "$RAW_S"

echo "2.1 -- DNS collect complete"

echo "3 -- Performing ping sweep for collected IPs"
echo "Hostname,IP,Ping_Status" >> "$FINAL"

while IFS=',' read -r saved_subd saved_ip; do
  if [ -n "$saved_ip" ]; then
    if ping -c 1 -W 1 "$saved_ip" > /dev/null 2>&1; then
      status="ALIVE"
    else
      status="DEAD/FILTERED"
    fi

    echo "$saved_subd,$saved_ip,$status" >> "$FINAL"
  fi
done < "$HOST_IP"
