from scapy.all import *
import time
import random

# --- SETĂRI REȚEA ---
IFACE = "Ethernet 5"
MAC_DST = "ff:ff:ff:ff:ff:ff" # Păstrăm Broadcast ca să prindă placa STM32
IP_STM32 = "192.168.1.20"

print("--- START GENERATOR TRAFIC MIXT (NORMAL vs ATAC) ---")
print("Apasa Ctrl+C pentru a opri.\n")

def genereaza_normal_web():
    """Simulează un laptop din rețea care accesează un site (HTTPS)"""
    ip_sursa = f"192.168.1.{random.randint(10, 50)}"
    port_sursa = random.randint(10000, 60000)
    pachet = Ether(dst=MAC_DST) / IP(src=ip_sursa, dst=IP_STM32) / TCP(sport=port_sursa, dport=443, flags="S")
    sendp(pachet, iface=IFACE, verbose=False)
    print(f"[NORMAL] Web    | {ip_sursa}:{port_sursa} -> {IP_STM32}:443")

def genereaza_normal_dns():
    """Simulează o cerere de rezolvare nume (DNS)"""
    ip_sursa = f"192.168.1.{random.randint(10, 50)}"
    port_sursa = random.randint(10000, 60000)
    pachet = Ether(dst=MAC_DST) / IP(src=ip_sursa, dst="8.8.8.8") / UDP(sport=port_sursa, dport=53)
    sendp(pachet, iface=IFACE, verbose=False)
    print(f"[NORMAL] DNS    | {ip_sursa}:{port_sursa} -> 8.8.8.8:53")

def genereaza_atac_scanare():
    """Simulează un utilitar tip Nmap care scanează porturi la rând"""
    ip_atacator = "10.0.0.99" # IP suspect din afara rețelei locale
    port_scanat = random.randint(20, 1024)
    pachet = Ether(dst=MAC_DST) / IP(src=ip_atacator, dst=IP_STM32) / TCP(sport=4444, dport=port_scanat, flags="S")
    sendp(pachet, iface=IFACE, verbose=False)
    print(f"[ATAC]   Scan   | {ip_atacator}:4444 -> {IP_STM32}:{port_scanat} (Pachet suspicios!)")

def genereaza_atac_udp_flood():
    """Simulează un atacator care trimite pachete UDP masive și haotice"""
    ip_atacator = f"192.168.1.{random.randint(200, 250)}"
    port_dst = random.randint(1000, 9000)
    pachet = Ether(dst=MAC_DST) / IP(src=ip_atacator, dst=IP_STM32) / UDP(sport=random.randint(1000, 9000), dport=port_dst)
    # Trimitem o rafală mică, specifică unui flood
    for _ in range(10):
        sendp(pachet, iface=IFACE, verbose=False)
    print(f"[ATAC]   Flood  | {ip_atacator} a trimis o rafala UDP catre portul {port_dst}!")

# --- BUCLA PRINCIPALĂ DE INTERCALARE ---
try:
    pachete_trimise = 0
    while True: # Rulează la infinit până dai Ctrl+C
        # Alegem ce tip de pachet trimitem pe baza unor probabilități:
        # 60% trafic normal (40% web, 20% dns), 40% atacuri (20% scan, 20% flood)
        tip_trafic = random.choices(
            ['web', 'dns', 'scan', 'flood'], 
            weights=[10, 5, 50, 35],
            k=1
        )[0]

        if tip_trafic == 'web':
            genereaza_normal_web()
        elif tip_trafic == 'dns':
            genereaza_normal_dns()
        elif tip_trafic == 'scan':
            genereaza_atac_scanare()
        elif tip_trafic == 'flood':
            genereaza_atac_udp_flood()

        pachete_trimise += 1
        
        # Facem o mică pauză aleatorie între 0.1 și 1 secundă pentru a părea trafic natural
        time.sleep(random.uniform(0.05, 0.3))

except KeyboardInterrupt:
    print(f"\n--- OPRIRE ---")
    print(f"Am generat in total {pachete_trimise} evenimente de trafic mixt.")