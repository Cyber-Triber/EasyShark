# EasyShark - Network Traffic Analyzer

![wireshark 256x256](https://github.com/user-attachments/assets/9fb25903-7977-4ebb-afb4-4fdb57924fee)


A lightweight network packet analyzer with a Qt-based GUI for easy network traffic monitoring and analysis.

## Features

- Real-time packet capture and analysis
- Support for TCP, UDP, DNS, ARP, and ICMP protocols
- Dark/Light theme support
- DNS reverse lookup functionality
- Port security analysis and warnings
- Packet filtering and highlighting
- PCAP file export/import
- Detailed TCP flags analysis
- Network interface selection
- Customizable capture duration

## Requirements

- Python 3.7+
- PyQt5
- Scapy
- psutil
- dnspython

## Installation

```bash
pip install PyQt5 scapy psutil dnspython
```

## Usage

Run the script with administrative privileges:

```bash
python easyshark.py
```

1. Select a network interface from the list
2. Choose capture duration
3. View and analyze captured packets
4. Use highlighting for specific IPs or ports
5. Toggle between dark/light themes
6. Save captures to PCAP files

## Security Features

- TCP/UDP suspicious port detection
- ARP spoofing detection
- SYN flood monitoring
- DNS analysis
- Detailed port security information

---

# EasyShark - Analyzátor síťového provozu

Jednoduchý analyzátor síťových paketů s GUI postavený na Qt pro snadné monitorování a analýzu síťového provozu.

## Funkce

- Zachytávání a analýza paketů v reálném čase
- Podpora protokolů TCP, UDP, DNS, ARP a ICMP
- Tmavý/Světlý režim
- Reverzní DNS vyhledávání
- Analýza zabezpečení portů a varování
- Filtrování a zvýrazňování paketů
- Export/Import PCAP souborů
- Detailní analýza TCP flagů
- Výběr síťového rozhraní
- Nastavitelná doba zachytávání

## Požadavky

- Python 3.7+
- PyQt5
- Scapy
- psutil
- dnspython

## Instalace

```bash
pip install PyQt5 scapy psutil dnspython
```

## Použití

Spusťte skript s administrátorskými právy:

```bash
python easyshark.py
```

1. Vyberte síťové rozhraní ze seznamu
2. Zvolte délku zachytávání
3. Prohlížejte a analyzujte zachycené pakety
4. Používejte zvýrazňování pro konkrétní IP adresy nebo porty
5. Přepínejte mezi tmavým/světlým režimem
6. Ukládejte zachycené pakety do PCAP souborů

## Bezpečnostní funkce

- Detekce podezřelých TCP/UDP portů
- Detekce ARP spoofingu
- Monitorování SYN flood útoků
- DNS analýza
- Detailní informace o zabezpečení portů
