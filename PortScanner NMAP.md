
# Accorgimenti OPSEC

```
# Change User Agents
--script-args http.useragent="some ua"

# Change default value on `/usr/share/nmap/nselib/http.lua`
`local USER_AGENT = stdnse.get_script_args('http.useragent') or "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)"`
```

# Metodologia di scansione

- Prendi in input IP o subnet o file con host 
- Scansione degli host per trovare quelli alive
- Scansione degli host alive trovati su tutte le porte per individuare porte aperte 
- Scansione approfondita delle porte aperte per trovare le specifiche dei singoli servizi

```
## ALIVE HOSTS (no ping)
nmap -sn -PR 192.168.1.0/24
nmap -sn -PR --max-retries 2 --host-timeout 5s --scan-delay 10ms --spoof-mac Apple --randomize-hosts 192.168.1.0/24

###‏ Find open ports TCP/SYN
nmap -sS -Pn $H
nmap -sS -Pn -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 $H
nmap -sS -Pn --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f $H

### Find open ports UDP
nmap -sU -Pn x.x.x.x
nmap -sU -Pn -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 $H
nmap -sU -Pn --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f $H

###‏ Scan found ports TCP/SYN
nmap -sS -Pn -A -p $P $H
nmap -sS -Pn -sC -sV -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 -p $P $H
nmap -sS -Pn -sV --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f -p $P $H

### Scan found ports UDP
nmap -sU -Pn -A -p $P $H
nmap -sU -Pn -sC -sV -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 -p $P $H
nmap -sU -Pn -sV --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f -p $P $H
```

```
Test extra 

# Se serve sapere se delle porte sono filtrate o no dal firewall possiamo usare una scansione ACK

### TCP/ACK
nmap -sA -Pn $H
nmap -sA -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 -p 80,443,22 $H
nmap -sA --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f -p 80,443,22 $H
```
# Nmap Scanner

```
./scanner.sh -t 3 -i 192.168.1.1
./scanner.sh -i 192.168.1.1/24
./scanner.sh -t 1 -f hosts.txt
```

```
#!/bin/bash

# Funzione per mostrare l'uso dello script
usage() {
    echo "Uso: $0 -t [1|2|3] -i <IP/subnet> -f <file_host>"
    echo "  -t: Livello OPSEC (1=basso, 2=medio, 3=alto)"
    echo "  -i: IP o subnet (es. 192.168.1.0/24)"
    echo "  -f: File con lista di host"
    exit 1
}

# Variabili iniziali
targets=""
opsec_level=1  # Livello OPSEC di default a 1 (basso)

# Parsing degli argomenti
while getopts ":t:i:f:" opt; do
    case ${opt} in
        t ) # Livello OPSEC
            opsec_level=$OPTARG
            ;;
        i ) # IP/Subnet
            targets=$OPTARG
            ;;
        f ) # File con host
            if [[ -f "$OPTARG" ]]; then
                targets=$(cat "$OPTARG")
            else
                echo "Errore: File $OPTARG non trovato."
                exit 1
            fi
            ;;
        \? ) usage ;;
    esac
done

# Controllo se -i o -f sono stati specificati
if [[ -z "$targets" ]]; then
    usage
fi

# Funzione per la scansione degli host attivi
find_alive_hosts() {
    echo "Scansione per host attivi (senza ping)..."
    
    case $opsec_level in
        1)
            nmap -sn -PR $targets -oG - | awk '/Up$/{print $2}' > alive_hosts.txt
            ;;
        2|3)
            nmap -sn -PR --max-retries 2 --host-timeout 5s --scan-delay 10ms --spoof-mac Apple --randomize-hosts $targets -oG - | awk '/Up$/{print $2}' > alive_hosts.txt
            ;;
        *)
            echo "Livello OPSEC non valido. Usa 1, 2 o 3."
            exit 1
            ;;
    esac
    echo "Host attivi trovati:"
    cat alive_hosts.txt
}

# Funzione per la scansione delle porte aperte TCP/SYN
scan_tcp_syn() {
    echo "Scansione delle porte TCP/SYN su $1 (Livello OPSEC $opsec_level)"
    
    case $opsec_level in
        1)
            nmap -sS -Pn $1 -oG - | tee -a tcp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > tcp_open_ports.txt
            ;;
        2)
            nmap -sS -Pn -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 $1 -oG - | tee -a tcp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > tcp_open_ports.txt
            ;;
        3)
            nmap -sS -Pn --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f $1 -oG - | tee -a tcp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > tcp_open_ports.txt
            ;;
        *)
            echo "Livello OPSEC non valido. Usa 1, 2 o 3."
            exit 1
            ;;
    esac
    echo "Porte TCP aperte su $1:"
    cat tcp_open_ports.txt
}

# Funzione per la scansione delle porte aperte UDP
scan_udp() {
    echo "Scansione delle porte UDP su $1 (Livello OPSEC $opsec_level)"
    
    case $opsec_level in
        1)
            nmap -sU -Pn $1 -oG - | tee -a udp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > udp_open_ports.txt
            ;;
        2)
            nmap -sU -Pn -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 $1 -oG - | tee -a udp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > udp_open_ports.txt
            ;;
        3)
            nmap -sU -Pn --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f $1 -oG - | tee -a udp_open_ports.txt | grep 'open' | awk '{print $2 " " $3}' > udp_open_ports.txt
            ;;
        *)
            echo "Livello OPSEC non valido. Usa 1, 2 o 3."
            exit 1
            ;;
    esac
    echo "Porte UDP aperte su $1:"
    cat udp_open_ports.txt
}

# Funzione per la scansione approfondita dei servizi TCP sulle porte aperte
deep_scan_tcp_services() {
    echo "Scansione approfondita dei servizi TCP sulle porte aperte (Livello OPSEC $opsec_level)"
    
    case $opsec_level in
        1)
            nmap -sS -Pn -A -p $2 $1 -oN deep_tcp_scan.txt
            ;;
        2)
            nmap -sS -Pn -sC -sV -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 -p $2 $1 -oN deep_tcp_scan.txt
            ;;
        3)
            nmap -sS -Pn -sV --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f -p $2 $1 -oN deep_tcp_scan.txt
            ;;
        *)
            echo "Livello OPSEC non valido. Usa 1, 2 o 3."
            exit 1
            ;;
    esac
}

# Funzione per la scansione approfondita dei servizi UDP sulle porte aperte
deep_scan_udp_services() {
    echo "Scansione approfondita dei servizi UDP sulle porte aperte (Livello OPSEC $opsec_level)"
    
    case $opsec_level in
        1)
            nmap -sU -Pn -A -p $2 $1 -oN deep_udp_scan.txt
            ;;
        2)
            nmap -sU -Pn -sC -sV -g 21 --spoof-mac Apple --scan-delay 5ms --randomize-hosts --data-length 16 -p $2 $1 -oN deep_udp_scan.txt
            ;;
        3)
            nmap -sU -Pn -sV --source-port 1024-65535 --spoof-mac Apple -T2 --randomize-hosts --data-length 16 -f -p $2 $1 -oN deep_udp_scan.txt
            ;;
        *)
            echo "Livello OPSEC non valido. Usa 1, 2 o 3."
            exit 1
            ;;
    esac
}

# Workflow di scansione

# 1. Scansione per host attivi
find_alive_hosts

# 2. Scansione delle porte aperte TCP/SYN
while IFS= read -r host; do
    scan_tcp_syn $host
done < alive_hosts.txt

# 3. Scansione delle porte aperte UDP
while IFS= read -r host; do
    scan_udp $host
done < alive_hosts.txt

# 4. Scansione approfondita dei servizi TCP sulle porte aperte
while IFS= read -r host; do
    deep_scan_tcp_services $host $(cat tcp_open_ports.txt)
done < alive_hosts.txt

# 5. Scansione approfondita dei servizi UDP sulle porte aperte
while IFS= read -r host; do
    deep_scan_udp_services $host $(cat udp_open_ports.txt)
done < alive_hosts.txt
```