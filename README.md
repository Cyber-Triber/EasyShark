# EasyShark - Network Traffic Analyzer (for non IT guys)

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

## Additional Features

* Highlighting for selected IP addresses or ports
* Dark/Light mode
* Save/Load captured packets to/from a PCAP file
* Detection of suspicious TCP/UDP ports
* ARP spoofing detection
* SYN flood attack monitoring
* DNS analysis
* Detailed port security information


Build EXE file:
```bash
pyinstaller --onefile --noconsole --hidden-import "dns.resolver" --hidden-import "dn.reversename" --hidden-import "psutils" --hidden-import "cryptography" --hidden-import "scapy.layers.inet" --hidden-import "scapy.layers.dns" --hidden-import "scapy.layers.l2" --hidden-import "scapy.utils" --add-data "C:\Python312\Lib\site-packages\dns\*;dns" --icon=easyshark.ico .\easyshark.py
```

In case of error 'Packet capture failed: Error opening adapter. The file name, directory name, or volume label is incorrect. (123)(123)', you need to install [npcap](https://npcap.com/dist/npcap-1.82.exe) in your system

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

## Další funkce
- Zvýrazňování pro vybrané IP adresy nebo porty
- Tmavý/světlý režim
- Ukládání / načítání zachycených paketů do / z PCAP souboru
- Detekce podezřelých TCP/UDP portů
- Detekce ARP spoofingu
- Monitorování SYN flood útoků
- DNS analýza
- Detailní informace o zabezpečení portů

Build [EXE](https://stefula.cz/apps/easyshark/easyshark_v004.exe) souboru:
```bash
pyinstaller --onefile --noconsole --hidden-import "dns.resolver" --hidden-import "dn.reversename" --hidden-import "psutils" --hidden-import "cryptography" --hidden-import "scapy.layers.inet" --hidden-import "scapy.layers.dns" --hidden-import "scapy.layers.l2" --hidden-import "scapy.utils" --add-data "C:\Python312\Lib\site-packages\dns\*;dns" --icon=easyshark.ico .\easyshark.py
```

V případě chyby "Zachytávání paketů selhalo: Error opening adapter. Název souboru či adresáře nebo jmenovka svazku je nesprávná. (123)(123)" je potřeba doinstalovat do systému [npcap](https://npcap.com/dist/npcap-1.82.exe)
