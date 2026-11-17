# NDR pe STM32 - Network Detection and Response

Sistem embedded de monitorizare a traficului de retea care detecteaza anomalii (port scan, UDP flood) folosind Isolation Forest. 

## Cum functioneaza
1. `trafic.py` genereaza trafic mixt (web, DNS, port scan, UDP flood) cu Scapy, la Layer 2, catre MAC broadcast.
2. Placa captureaza frame-urile prin LAN8742A (RMII) + ETH DMA + LwIP, parseaza headerele Ethernet / IP / TCP / UDP si trimite pe UART un rand per pachet: `NDR,TCP,4444,80,S,60`.
3. `NDR.py` citeste UART-ul (COM7, 115200 baud), agrega pachetele pe ferestre de 2 secunde, calculeaza 5 features si ruleaza modelul.
4. Verdictul se trimite inapoi pe UART (`ALERT:1` anomalie, `ALERT:0` normal) si placa aprinde LED-ul corespunzator.

## Hardware
- STM32 Nucleo-H743ZI2 (Cortex-M7, 480 MHz, Ethernet MAC + PHY LAN8742A, ST-Link V3 cu Virtual COM Port)
- Adaptor USB-Ethernet (Realtek), IP static `192.168.1.10/24` pe laptop
- Cablu Ethernet + cablu USB (ST-Link)

## Firmware (bare-metal, C)
Generat cu STM32CubeMX + STM32CubeIDE, cu LwIP fara RTOS.
- `Core/Src/main.c` - bucla principala, polling UART pe registrele USART, LED-uri (verde / rosu cu latch), configurare MPU
- `LWIP/App/ethernetif.c` - `ndr_process_packet()`: parsarea pachetelor si trimiterea pe UART
- `LWIP/Target/lwipopts.h` - `LWIP_RAM_HEAP_POINTER 0x30008000`

Detalii importante pentru seria H7:
- Descriptorii DMA, `RX_POOL` si heap-ul LwIP sunt in SRAM D2 (`0x30000000`)
- Zona D2 este marcata non-cacheable prin MPU (regiunea 1, 512 KB) pentru coerenta cache-DMA
- Heap-ul LwIP este mutat la `0x30008000` ca sa nu se suprapuna cu `RX_POOL`

## Machine Learning
- Algoritm: Isolation Forest (nesupervizat), `n_estimators=100`, `contamination=0.01`
- Antrenat pe `Monday-WorkingHours.pcap_ISCX.csv` (CICIDS2017, trafic benign)
- Features: Destination Port, Flow Duration, Total Fwd Packets, SYN Flag Count, RST Flag Count
- Normalizare cu `StandardScaler`

## LED-uri
- Galben -> activitate Ethernet (toggle la fiecare pachet) 
- Verde -> ultimul verdict: trafic normal 
- Rosu -> anomalie detectata (ramane aprins un interval dupa alerta) 

## Limitari
- Verdictul este per fereastra de 2 secunde, nu per flow
- Se detecteaza doar port scan si UDP flood
- Comunicatia UART nu este criptata
