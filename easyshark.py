from typing import List, Dict, Any, Optional, Tuple
import logging
import logging.handlers
import psutil
import socket
import warnings
from pathlib import Path
from cryptography.utils import CryptographyDeprecationWarning
from dataclasses import dataclass
from datetime import datetime
import dns.resolver
import dns.reversename
import subprocess
from functools import lru_cache
import time
import sys
import re

# Suppress cryptography deprecation warnings
with warnings.catch_warnings(action="ignore", category=CryptographyDeprecationWarning):
    from scapy.all import sniff
    from scapy.layers.inet import IP, UDP, TCP, ICMP
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import ARP
    from scapy.utils import wrpcap, rdpcap

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QTableWidget, QTableWidgetItem, QWidget,
    QMessageBox, QHeaderView, QTabWidget, QCheckBox, QLineEdit,
    QListWidget, QListWidgetItem, QDialog, QFileDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

# Constants
LOG_FILE = 'easyshark.log'
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
LOG_BACKUP_COUNT = 3
PACKET_BUFFER_SIZE = 10000
DEFAULT_DNS_SERVER = '8.8.8.8'
DEFAULT_CACHE_TIMEOUT = 300  # 5 minutes

# Theme stylesheets
LIGHT_THEME = """
    QMainWindow, QWidget {
        background-color: #ffffff;
        color: #000000;
    }
    QPushButton {
        background-color: #f0f0f0;
        border: 1px solid #c0c0c0;
        padding: 5px;
        border-radius: 3px;
    }
    QTableWidget {
        background-color: #ffffff;
        alternate-background-color: #f5f5f5;
    }
    QHeaderView::section {
        background-color: #f0f0f0;
        color: #000000;
        border: 1px solid #c0c0c0;
    }
    QTabWidget::pane {
        border: 1px solid #c0c0c0;
        background-color: #ffffff;
    }
    QTabBar::tab {
        background-color: #f0f0f0;
        color: #000000;
        padding: 8px 12px;
        border: 1px solid #c0c0c0;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    QTabBar::tab:selected {
        background-color: #ffffff;
        margin-bottom: -1px;
    }
"""

DARK_THEME = """
    QMainWindow, QWidget {
        background-color: #2d2d2d;
        color: #ffffff;
    }
    QPushButton {
        background-color: #3d3d3d;
        border: 1px solid #505050;
        padding: 5px;
        border-radius: 3px;
        color: #ffffff;
    }
    QTableWidget {
        background-color: #2d2d2d;
        alternate-background-color: #353535;
        color: #ffffff;
        gridline-color: #505050;
    }
    QHeaderView::section {
        background-color: #3d3d3d;
        color: #ffffff;
        border: 1px solid #505050;
    }
    QComboBox {
        background-color: #3d3d3d;
        color: #ffffff;
        border: 1px solid #505050;
    }
    QTabWidget::pane {
        border: 1px solid #505050;
        background-color: #2d2d2d;
    }
    QTabBar::tab {
        background-color: #3d3d3d;
        color: #ffffff;
        padding: 8px 8px;
        border: 1px solid #505050;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    QTabBar::tab:selected {
        background-color: #2d2d2d;
        margin-bottom: -1px;
    }
    QLabel {
        color: #ffffff;
    }
"""

# TCP Flag mappings
TCP_FLAGS = {
    'P': ('PSH', 'Data byla ihned odeslána', False),
    'U': ('URG', 'Paket obsahuje urgentní data', False),
    'E': ('ECE', 'Oznámení o zahlcení sítě', True),
    'C': ('CWR', 'Odesílatel snížil přenosové okno', True),
    'N': ('NS', 'ECN Nonce – indikátor zahlcení', True),
    'S': ('SYN', 'Požadavek na navázání spojení', False),
    'A': ('ACK', 'Potvrzení přijetí dat', False),
    'R': ('RST', 'Spojení bylo násilně ukončeno', True),
    'F': ('FIN', 'Ukončení spojení', False)
}

PORTS_HELP = {
    "445": """🛡️ Port 445 – Bezpečnostní upozornění
Port 445/TCP se používá pro přímé sdílení souborů mezi Windows zařízeními pomocí protokolu SMB (Server Message Block - sdílení souborů).

Tento port ale často zneužívají červi, trojské koně a útočníci, protože:
- Umožňuje přímý přístup k síťovým sdílením
- V minulosti obsahoval řadu kritických zranitelností
- Často bývá otevřený i do internetu, což je velmi nebezpečné

❗Doporučení:
- Zablokujte port 445 na firewallech a směrovačích (hlavně směrem ven)
- Nepovolujte SMB přístup z internetu
- V prostředí s Windows doporučujeme SMB používat pouze v lokální síti

🐛 Známé hrozby využívající port 445:
- W32.Sasser, W32.Conficker, Zotob – šíření a ovládnutí systému
- Backdoory – otevřou systém útočníkům
- Vzdálené spuštění kódu – umožní převzít kontrolu nad PC

Pokud není port 445 nutný pro provoz v síti, vypněte ho nebo zabezpečte jeho používání pouze v rámci důvěryhodné sítě.""",
    "23": """⚠️ Port 23 (Telnet) – Zastaralý a nebezpečný
Telnet je starý způsob vzdáleného připojení k zařízením (hlavně Unix/Linux). Dnes se už nedoporučuje používat, protože:

- Přenáší data včetně hesel nešifrovaně
- Obsahuje mnoho závažných bezpečnostních děr
- Umožňuje snadný vzdálený přístup útočníkům

 ❗Doporučení:
- Nepoužívejte Telnet vůbec, nahraďte ho bezpečnější alternativou SSH
- Pokud Telnet nepotřebujete, vypněte ho nebo zablokujte port 23 na firewallech

 🐛 Známé hrozby využívající port 23:
- Trojské koně a zadní vrátka, které poslouchají na portu 23
- Zařízení s výchozími nebo pevně danými hesly (např. gpon/gpon, root/root)
- Infekce malwarem, který útočníkům poskytuje plný přístup k zařízení

 📉 Proč je to problém?
Útočník se může připojit přes port 23:
- bez hesla nebo s výchozím heslem
- získat plný přístup jako správce (root)
- ovládnout zařízení, např. domácí router, kamery, nebo IoT zařízení


Pokud v síti najdete aktivní Telnet na portu 23, okamžitě prověřte zařízení a zabezpečte je.""",
"3389": """⚠️ Port 3389 – Vzdálená plocha (RDP)
Port 3389/TCP se používá pro připojení ke vzdálené ploše pomocí protokolu RDP (Remote Desktop Protocol). Tento port je běžný ve Windows pro:
- Vzdálenou správu počítače
- Terminálové služby (Windows Terminal Server)

 ❗Rizika:
- Port 3389 je častým cílem útoků z internetu
- Umožňuje přímé přihlášení do systému – při slabém hesle může být systém prolomen
- V minulosti se zde objevily závažné bezpečnostní chyby

 🐛 Známé hrozby:
- Denial of Service (DoS) – zahlcení serveru množstvím RDP připojení
- Získání přístupu přes zadní vrátka – trojské koně jako *Backdoor.Win32.Agent.cdm*
- Zneužití chyb v RDP protokolu – umožňuje spustit kód na napadeném počítači

 ❗Doporučení:
- Nikdy neotevírej port 3389 přímo do internetu
- Používej VPN nebo RDP gateway
- Zkontroluj, zda je RDP zabezpečené: silné heslo, 2FA, aktuální systém

🔒 Pokud RDP nepotřebuješ, vypni ho nebo zablokuj port 3389 na firewallu""",
"135": """⚠️ Port 135 – RPC (Remote Procedure Call)
Port 135/TCP se používá pro komunikaci mezi aplikacemi ve Windows – například při vzdálené správě, přístupu k Exchange serveru nebo při spuštění systémových služeb.

 ❗Rizika:
- Port je součástí služby RPC (Remote Procedure Call), která je častým cílem útoků
- V minulosti umožňoval:
  - převzetí kontroly nad systémem (RCE)
  - zahlcení systému (DoS útoky)
  - šíření červů jako *W32.Blaster* nebo *W32.Reatle*

 📢 Messenger spam:
Port 135 byl zneužíván k zobrazování nevyžádaných oken s reklamou ve starších verzích Windows (služba "Messenger" – neplést s MSN).

 🐛 Známé hrozby:
- W32.Blaster.Worm – zneužívá chybu v RPC, šíří se přes port 135
- W32.Reatle – rozesílá sám sebe e-mailem, otevírá zadní vrátka a spouští DDoS útoky
- Zranitelnosti v zařízeních (např. Siemens LOGO!8) – umožňují vzdálené čtení a úpravu konfigurace

 ❗Doporučení:
- Nepovoluj RPC přes internet
- Pokud port 135 nepotřebuješ, zablokuj ho ve firewallu
- Udržuj systém aktualizovaný, aby byly známé chyby opravené

Port 135 často spolupracuje s dalšími porty: 137/udp, 138/udp, 139/tcp, 445/tcp. Doporučujeme zablokovat celou tuto skupinu, pokud není výslovně potřebná.
""",
"1433": """⚠️ Port 1433 – Microsoft SQL Server
Port 1433/TCP se používá pro připojení k Microsoft SQL Serveru, databázovému systému běžnému ve firemním prostředí.

 ❗Rizika:
- Port je častým cílem útoků, zvláště pokud je SQL server dostupný z internetu
- V minulosti se objevily závažné chyby umožňující:
  - vzdálené spuštění kódu
  - šíření červů (např. *Gaobot*, *Digispid*, *Kelvir*)
  - přihlášení bez hesla při špatném zabezpečení

 🐛 Známé hrozby:
- Digispid.B.Worm – útočí na SQL servery s prázdným heslem
- W32.Kelvir.R – rozšiřuje se přes zranitelnosti v SQL Serveru
- Hello overflow (CVE-2002-1123) – umožňuje útočníkovi převzít kontrolu nad serverem

 ❗Doporučení:
- Nenechávej SQL Server přístupný z internetu
- Vždy nastav silné heslo pro účet `sa` (SQL admin)
- Udržuj SQL Server aktualizovaný a monitoruj provoz na portu 1433

🔐 SQL Server se často používá i s portem 1434/UDP (služba SQL Browser) – zkontroluj oba porty a zabezpeč jejich použití.
""",
"19": """⚠️ Port 19 – CHARGEN (Character Generator)
Port 19 (TCP/UDP) slouží ke generování náhodných znaků. Tento starý protokol byl původně určen pro testování sítě.

 ❗Rizika:
- V moderních sítích není potřeba – pokud ho nepotřebujete, mějte ho vypnutý
- Port 19 může být zneužit k DDoS útokům (odrážení paketů)
- Využíván některými trojskými koňmi (např. *Skun*)

 ❗Doporučení:
- Pokud CHARGEN aktivně nepoužíváte (např. pro testování zařízení), zablokujte port 19
- Zkontrolujte, zda žádné zařízení ve vaší síti tento port neočekávaně neposlouchá

Tento port je často zneužíván v kombinaci s jinými otevřenými službami pro reflektované útoky – jeho vypnutí je základním bezpečnostním opatřením.
""",
"123": """⚠️ Port 123 – NTP (Network Time Protocol)
Port 123/UDP se používá pro synchronizaci času mezi zařízeními v síti. Je to běžná a potřebná služba, ale může být i bezpečnostním rizikem.

 ❗Rizika:
- Útočník může získat informace o systému (čas běhu, paměť, síťová aktivita)
- Pokud je server špatně nakonfigurovaný, může útočník:
  - změnit systémový čas
  - ovlivnit logy nebo naplánované úlohy (cron)
  - provádět replay útoky (např. zneužití dočasných přístupových tokenů)

 🐛 Další zneužití:
- NTP servery bývají zneužívány pro DDoS útoky (tzv. "amplification" útoky)
- Některá zařízení (např. Vodafone Sure Signal) využívají port 123 bez možnosti zabezpečení

 ❗Doporučení:
- Nepovolujte přístup na NTP zvenčí (z internetu)
- Využívejte ověřené a důvěryhodné NTP servery
- Pravidelně kontrolujte, že čas na serverech odpovídá správné hodnotě

Synchronizace času je důležitá – ale NTP port by měl být otevřen jen tam, kde je to opravdu potřeba.""",
"1900": """⚠️ Port 1900 – SSDP / UPnP (Universal Plug and Play)
Port 1900/UDP se používá pro automatické vyhledávání zařízení v síti pomocí protokolu SSDP, který je součástí technologie UPnP (Universal Plug and Play).

 🧩 K čemu slouží:
- Automaticky detekuje zařízení v síti (např. tiskárny, chytré televize, routery)
- Používá se hlavně v domácích sítích

 ❗Rizika:
- UPnP bývá zapnuté automaticky i tam, kde není potřeba
- Port 1900 je často zranitelný vůči:
  - přetečení paměti (buffer overflow)
  - spuštění škodlivého kódu na zařízení
  - vzdálenému ovládnutí routeru nebo jiného zařízení
- Některé červy a útoky zneužívají UPnP ke šíření nebo přístupu do sítě

 🐛 Známé problémy:
- Zranitelnosti v zařízeních D-Link, NETGEAR, Xerox, Swisscom, CA BrightStor
- Stačí zaslat jeden upravený UDP paket, a útočník může převzít kontrolu nad zařízením

 ❗Doporučení:
- Pokud UPnP nepotřebujete, vypněte ho v nastavení routeru a zařízení
- Blokujte port 1900/UDP na firewallu – hlavně směrem z internetu
- Pravidelně aktualizujte firmware síťových zařízení

UPnP je pohodlné, ale zároveň velmi rizikové – zapnuté UPnP často znamená otevřená zadní vrátka do sítě.""",
"5353": """⚠️ Port 5353 – mDNS / Bonjour / Avahi
Port 5353/UDP slouží pro tzv. Multicast DNS (mDNS), což je technologie automatického vyhledávání zařízení v lokální síti (např. tiskárny, mediální servery).

Používá se například u:
- Apple zařízení (Bonjour)
- Linux (Avahi)
- Plex Media Server
- TeamViewer

 ❗Rizika:
- Port 5353 běží často i tam, kde není potřeba
- V minulosti obsahoval chyby umožňující:
  - přetížení zařízení (DoS útoky)
  - získání citlivých informací (např. názvy zařízení, IP adresy)
  - síťové zesílení útoků (amplifikace)

 🐛 Známé problémy:
- Avahi na Linuxu – možné přetížení nebo zacyklení služby
- Apple Bonjour – zbytečné odpovídání na nebezpečné dotazy
- Backdoor.Optix.04.E – trojan, který otevírá port 5353 a naslouchá na něm
- Cisco, IBM, Synology, BOSE zařízení – odpovídají na dotazy z internetu a lze je zneužít

 ❗Doporučení:
- Zakaž mDNS/Bonjour/Avahi, pokud službu nepotřebuješ
- Blokuj port 5353/UDP na firewallu, hlavně směrem z internetu
- V domácích sítích je port užitečný, ale v podnikových sítích často zbytečný a rizikový

mDNS (port 5353) usnadňuje práci v síti, ale bez správného nastavení může představovat bezpečnostní slabinu.""",
'67': """⚠️ Porty 67 a 68 – DHCP (Dynamic Host Configuration Protocol)

Porty 67/UDP (server) a 68/UDP (klient) se používají pro automatické přidělování IP adres a síťových nastavení zařízením v síti.

 🧩 K čemu slouží:
- DHCP server na portu 67 posílá adresy a další nastavení klientům, kteří komunikují na portu 68
- Umožňuje snadné připojení zařízení do sítě bez ruční konfigurace

 ❗Rizika:
- Některé starší firewally nebo VPN klienti nemusí správně filtrovat provoz na těchto portech, což může umožnit obejití bezpečnostních pravidel
- Útočník může zneužít tyto porty k útokům typu spoofing nebo neoprávněné konfiguraci

 ❗Doporučení:
- Firewall by měl správně filtrovat a povolovat DHCP provoz pouze uvnitř důvěryhodné sítě
- VPN a bezpečnostní klienti by měli správně ošetřit provoz na portech 67 a 68
- Pravidelně aktualizuj software síťových zařízení a klientů

DHCP porty jsou nezbytné pro fungování sítě, ale jejich správná konfigurace je důležitá pro bezpečnost.""",
'68': """⚠️ Porty 67 a 68 – DHCP (Dynamic Host Configuration Protocol)

Porty 67/UDP (server) a 68/UDP (klient) se používají pro automatické přidělování IP adres a síťových nastavení zařízením v síti.

 🧩 K čemu slouží:
- DHCP server na portu 67 posílá adresy a další nastavení klientům, kteří komunikují na portu 68
- Umožňuje snadné připojení zařízení do sítě bez ruční konfigurace

 ❗Rizika:
- Některé starší firewally nebo VPN klienti nemusí správně filtrovat provoz na těchto portech, což může umožnit obejití bezpečnostních pravidel
- Útočník může zneužít tyto porty k útokům typu spoofing nebo neoprávněné konfiguraci

 ❗Doporučení:
- Firewall by měl správně filtrovat a povolovat DHCP provoz pouze uvnitř důvěryhodné sítě
- VPN a bezpečnostní klienti by měli správně ošetřit provoz na portech 67 a 68
- Pravidelně aktualizuj software síťových zařízení a klientů

DHCP porty jsou nezbytné pro fungování sítě, ale jejich správná konfigurace je důležitá pro bezpečnost.""",
"21": """⚠️ Port 21 – FTP (File Transfer Protocol)
Port 21/TCP slouží k přenosu souborů mezi počítači v síti.

 ❗Rizika:
- FTP přenáší data včetně hesel nešifrovaně
- Často cílem odposlechu a útoků
- Může umožnit neoprávněný přístup ke sdíleným souborům

 🐛 Známé problémy:
- Útoky na slabá hesla
- Využití nezabezpečených FTP serverů k šíření škodlivého softwaru

 ❗Doporučení:
- Používej raději bezpečný protokol SFTP nebo FTPS
- Pokud FTP nepotřebuješ, port zablokuj""",
"23": """⚠️ Port 23 – Telnet
Port 23/TCP slouží ke vzdálenému přístupu k počítačům.

 ❗Rizika:
- Přenos dat a hesel je nešifrovaný
- Snadno zneužitelný pro průniky a převzetí kontroly

 🐛 Známé problémy:
- Časté útoky na výchozí nebo slabá hesla
- Vzdálené spuštění škodlivého kódu

 ❗Doporučení:
- Nahraď Telnet bezpečným SSH

Pokud Telnet nepotřebuješ, vypni ho nebo zablokuj port""",
"53": """⚠️ Port 53 – DNS (Domain Name System)
Port 53/UDP a TCP slouží k překladu doménových jmen na IP adresy.

 ❗Rizika:
- Útoky typu DNS spoofing a cache poisoning
- Může být použit k přesměrování uživatelů na podvodné weby

 🐛 Známé problémy:
- Zneužití DNS serverů pro DDoS útoky
- Neoprávněné změny DNS záznamů

 ❗Doporučení:
- Používej ověřené a zabezpečené DNS servery
- Filtrovat a monitorovat provoz na portu 53""",
"69": """⚠️ Port 69 – TFTP (Trivial File Transfer Protocol)
Port 69/UDP slouží k jednoduchému přenosu souborů bez autentizace.

 ❗Rizika:
- Nepodporuje šifrování ani ověřování uživatele
- Často zneužíván k neoprávněnému přenosu dat

 🐛 Známé problémy:
- Využíván ke šíření malware a konfigurací

 ❗Doporučení:
- Pokud TFTP nepotřebuješ, port zablokuj""",
"110": """⚠️ Port 110 – POP3 (Post Office Protocol 3)
Port 110/TCP slouží k přijímání e-mailů.

 ❗Rizika:
- Hesla a data se přenášejí nešifrovaně
- Snadné odposlechnutí přihlašovacích údajů

 🐛 Známé problémy:
- Útoky na hesla
- Zneužití pro přístup k e-mailům

 ❗Doporučení:
- Používej POP3S (šifrovaný POP3) nebo IMAPS
- Pokud port 110 nepotřebuješ, zablokuj ho""",
"139": """⚠️ Port 139 – NetBIOS Session Service

Port 139/TCP slouží pro sdílení souborů a tiskáren ve Windows přes NetBIOS.
 ❗Rizika:
- Častý cíl útoků na Windows sítě
- Může umožnit vzdálený přístup bez autentizace

 🐛 Známé problémy:
- Útoky typu SMB relay
- Šíření červů a malware

 ❗Doporučení:
- Zablokuj port mimo lokální síť
- Aktualizuj systémy na nejnovější verze""", 
"514": """⚠️ Port 514 – Syslog
Port 514/UDP slouží pro zasílání systémových logů.

 ❗Rizika:
- Nepodporuje šifrování
- Může být využit k podvržení logů

 🐛 Známé problémy:
- Zneužití k manipulaci s logy

 ❗Doporučení:
- Používej zabezpečené protokoly pro logování
- Filtrovat provoz na portu 514""",
"5900": """⚠️ Port 5900 – VNC (Virtual Network Computing)
Port 5900/TCP slouží pro vzdálený přístup k ploše přes VNC.

 ❗Rizika:
- Přenos nešifrovaný
- Snadno zneužitelný pro vzdálené přístupy

 🐛 Známé problémy:
- Útoky na slabá hesla
- Neoprávněný přístup

 ❗Doporučení:
- Používej VPN
- Zabezpeč přístup heslem a šifrováním""",
"6667": """⚠️ Port 6667 – IRC (Internet Relay Chat)
Port 6667/TCP se používá pro komunikaci v IRC sítích.

 ❗Rizika:
- Může být zneužíván pro ovládání botnetů
- Často cíl útoků a šíření malwaru

 🐛 Známé problémy:
- Šíření škodlivých příkazů botnetům

 ❗Doporučení:
- Pokud IRC nepoužíváš, port zablokuj""",
"8080": """⚠️ Port 8080 – HTTP Proxy
Port 8080/TCP často slouží jako alternativní port pro webové servery nebo proxy.

 ❗Rizika:
- Může být zneužit jako otevřený proxy server
- Útočníci ho využívají k anonymizaci útoků

 🐛 Známé problémy:
- Proxy open relay útoky
- Skrytí původu útoku

 ❗Doporučení:
- Zabezpeč proxy servery
- Filtrovat provoz na portu 8080"""
}




@dataclass
class PacketInfo:
    """Data class for storing packet information"""
    time: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    flags: str = ""
    desc: str = ""
    reseni: str = ""
    problem: bool = False

class DNSCache:
    """DNS cache implementation with timeout"""
    def __init__(self, timeout: int = DEFAULT_CACHE_TIMEOUT):
        self.cache: Dict[str, Tuple[float, str]] = {}
        self.timeout = timeout

    def get(self, ip: str) -> Optional[str]:
        """Get hostname from cache if not expired"""
        if ip in self.cache:
            timestamp, hostname = self.cache[ip]
            if time.time() - timestamp < self.timeout:
                return hostname
            del self.cache[ip]
        return None

    def set(self, ip: str, hostname: str) -> None:
        """Set hostname in cache with current timestamp"""
        self.cache[ip] = (time.time(), hostname)

def setup_logging() -> None:
    """Configure application logging with rotation and proper formatting"""
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Configure rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(log_formatter)
    
    # Configure console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

class PacketSniffer(QMainWindow):
    """Main application window for packet capturing and analysis"""
    def __init__(self) -> None:
        super().__init__()
        self.dns_cache = DNSCache()
        self.my_ip: Optional[str] = None
        self.syn_tracker = {}  # {(src_ip, dst_ip, dst_port): count}
        self.tcp_suspicious_ports = {23, 445, 3389, 135, 1433}
        self.udp_suspicious_ports = {19, 123, 1900, 5353, 67, 68}  # Chargen, NTP, SSDP, mDNS, DHCP
        self.udp_flood_tracker = {}  # {src_ip: {dst_ip: set(porty)}}
        self.setup_ui()
    
    def save_to_pcap(self, packets: List[Any]) -> None:
        """
        Save captured packets to a PCAP file.
        
        Args:
            packets: List of captured packets to save
        """
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self,
                "Uložit pakety",
                "",
                "PCAP files (*.pcap);;All files (*.*)"
            )
            
            if filename:
                # Add .pcap extension if not present
                if not filename.endswith('.pcap'):
                    filename += '.pcap'
                    
                wrpcap(filename, packets)
                self.update_statusbar(f"Pakety byly uloženy do: {filename}")
                logging.info(f"Pakety uloženy do souboru: {filename}")
                
        except Exception as e:
            self.update_statusbar("Chyba při ukládání paketů")
            logging.error(f"Chyba při ukládání paketů: {e}")
            QMessageBox.critical(self, "Error", f"Nelze uložit pakety: {str(e)}")
        
    def load_from_pcap(self) -> None:
        """Load and display packets from a PCAP file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self,
                "Načíst pakety",
                "",
                "PCAP files (*.pcap);;All files (*.*)"
            )
            
            if not filename:
                return
                
            self.update_statusbar(f"Načítám pakety z: {filename}")
            # Add error handling for empty files
            try:
                packets = rdpcap(filename)
                if not packets or len(packets) == 0:
                    QMessageBox.warning(self, "Warning", "Soubor neobsahuje žádné pakety")
                    return
            except Exception as e:
                QMessageBox.warning(self, "Error", "Soubor nelze načíst nebo je poškozen")
                return
                
            # Parse and display packets
            parsed_results = self.parse_packets(packets)
            if not any(parsed_results):
                QMessageBox.warning(self, "Warning", "Nenalezeny žádné pakety k zobrazení")
                return
                
            # Update display
            self.show_capture_summary(*parsed_results)
            self.update_tables(*parsed_results)
            self.update_statusbar(f"Pakety načteny ze souboru: {filename}")
            logging.info(f"Pakety načteny ze souboru: {filename}")
                
        except Exception as e:
            self.update_statusbar("Chyba při načítání paketů")
            logging.error(f"Chyba při načítání paketů: {e}")
            QMessageBox.critical(self, "Error", f"Nelze načíst pakety: {str(e)}")
                
        except Exception as e:
            self.update_statusbar("Chyba při načítání paketů")
            logging.error(f"Chyba při načítání paketů: {e}")
            QMessageBox.critical(self, "Error", f"Nelze načíst pakety: {str(e)}")

    def toggle_theme(self) -> None:
        """Toggle between light and dark theme"""
        if self.current_theme == "light":
            self.apply_theme(DARK_THEME)
            self.theme_button.setText("☀️")  # Sun emoji for light theme
            self.current_theme = "dark"
        else:
            self.apply_theme(LIGHT_THEME)
            self.theme_button.setText("🌙")  # Moon emoji for dark theme
            self.current_theme = "light"
        
        # Reset all table colors according to current theme
        for table in self.packet_tables.values():
            for row in range(table.rowCount()):
                reseni_item = table.item(row, 7)  # Doporučení column
                is_problem = reseni_item and reseni_item.text().strip() != ""
                
                # Always apply error background first for problem packets
                if is_problem:
                    error_color = QColor("#FF4040") if self.current_theme == "dark" else QColor("#FFB6C6")
                    for col in range(table.columnCount()):
                        item = table.item(row, col)
                        if item:
                            item.setBackground(error_color)
                else:
                    # Set theme background for non-problem packets
                    bg_color = QColor("#2d2d2d") if self.current_theme == "dark" else QColor("#ffffff")
                    for col in range(table.columnCount()):
                        item = table.item(row, col)
                        if item:
                            item.setBackground(bg_color)
        
        # Reapply any active highlights after theme change
        self.highlight_ips()
    
    def toggle_problem(self) -> None:
        if not self.problems_only:
            self.display_problem()
            self.problem_button.setText("‼️")  
            self.problems_only = True
        else:
            self.display_all()
            self.problem_button.setText("⭐") 
            self.problems_only = False
    
    def display_problem(self) -> None:
        """Show only problem packets in all tables"""
        for table in self.packet_tables.values():
            for row in range(table.rowCount()):
                desc_item = table.item(row, 6)  # Description column
                bg_color = desc_item.background().color() if desc_item else None
                is_problem = bg_color and (bg_color == QColor("#8B0000") or bg_color == QColor("#FFB6C6"))
                if not is_problem:
                    table.hideRow(row)
                else:
                    table.showRow(row)

    def display_all(self) -> None:
        """Show all packets in all tables"""
        for table in self.packet_tables.values():
            for row in range(table.rowCount()):
                table.showRow(row)
    
            
    def apply_theme(self, theme: str) -> None:
        """Apply the specified theme to the application"""
        self.setStyleSheet(theme)
        QApplication.processEvents()  # Ensure immediate update    
    
    def setup_ui(self) -> None:
        """Initialize the user interface"""
        self.setWindowTitle("EasyShark - Network Analyzer")
        self.setGeometry(100, 100, 1000, 700)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self._setup_ip_addresses_table()
        self._setup_controls()
        self._setup_highlights()
        self._setup_packet_tables()
        self._setup_statusbar()

    def _setup_ip_addresses_table(self) -> None:
        """Setup the IP addresses list"""
        self.ip_addresses_label = QLabel("Síťové interface a přiřazené adresy - kliknutím na interface spustíš sken")        
        self.ip_addresses_label.setStyleSheet("font-size: 8pt; font-weight: bold;")
        self.layout.addWidget(self.ip_addresses_label)
        self.ip_addresses_list = QListWidget()
        self.ip_addresses_list.setStyleSheet("font-size: 10pt;")
        self.ip_addresses_list.itemClicked.connect(self._on_interface_selected)
        
        ip_addresses = self._populate_ip_addresses_table()
        
        # Calculate dynamic height based on items
        item_height = 25  # Base height per item in pixels
        spacing = 2  # Spacing between items
        visible_items = sum(1 for ip_info in ip_addresses 
                          if not any(ip_info.split(" : ")[1].startswith(prefix) 
                                   for prefix in ["127.", "169.254."]))
        
        total_height = (item_height + spacing) * visible_items + 10  # +10 for padding
        max_height = 300  # Maximum height limit
        self.ip_addresses_list.setFixedHeight(min(total_height, max_height))
        
        for ip_info in ip_addresses:
            interface, ip_address = ip_info.split(" : ")
            if not (ip_address.startswith("127.") or ip_address.startswith("169.254.")):
                item_text = f"{interface} - {ip_address}"
                item = QListWidgetItem(item_text)
                self.ip_addresses_list.addItem(item)

        self.layout.addWidget(self.ip_addresses_list)

    def _setup_controls(self) -> None:
        ip_and_button_layout = QHBoxLayout()

        self.ip_to_hostname_checkbox = QCheckBox("IP → hostname")
        self.ip_to_hostname_checkbox.setStyleSheet("font-size: 10pt; font-weight: bold;")
        ip_and_button_layout.addWidget(self.ip_to_hostname_checkbox)
        ip_and_button_layout.addStretch()
        self.my_ip_label = QLabel("Moje IP adresa:")
        self.my_ip_label.setStyleSheet("font-size: 8pt;")
        self.my_ip_value = QLabel("")  # bude nastaveno později
        self.my_ip_label.setAlignment(Qt.AlignLeft)
        self.my_ip_value.setStyleSheet("font-size: 10pt; font-weight: bold;")
        self.my_ip_value.setAlignment(Qt.AlignLeft)
        ip_and_button_layout.addWidget(self.my_ip_label)
        ip_and_button_layout.addWidget(self.my_ip_value)
        ip_and_button_layout.addStretch()
        
        self.save_button = QPushButton("💾 Uložit pakety")
        self.save_button.setStyleSheet("font-size: 10pt;")
        self.save_button.clicked.connect(lambda: self.save_to_pcap(self.last_captured_packets))
        self.save_button.setEnabled(False)  # Enable after capture
        ip_and_button_layout.addWidget(self.save_button)
        
        self.load_button = QPushButton("📂 Načíst pakety")
        self.load_button.setStyleSheet("font-size: 10pt;")
        self.load_button.clicked.connect(self.load_from_pcap)
        ip_and_button_layout.addWidget(self.load_button)

        self.layout.addLayout(ip_and_button_layout)

    def _setup_highlights(self) -> None:
        self.highlight_layout = QHBoxLayout()
        self.highlight_label = QLabel("Zvýraznit IP (oddělené čárkou):")
        self.highlight_label.setStyleSheet("font-size: 8pt;")
        self.highlight_input = QLineEdit()
        self.highlight_input.setStyleSheet("font-size: 10pt; font-weight: bold;height: 30px;")
        
        self.highlight_button = QPushButton("Zvýraznit")
        self.highlight_button.setStyleSheet("font-size: 10pt;")
        self.clear_button = QPushButton("Vyčistit")
        self.clear_button.setStyleSheet("font-size: 10pt;")
        
        self.highlight_ports_l = QLabel("Zvýraznit porty (oddělené čárkou)")
        self.highlight_ports_l.setStyleSheet("font-size: 8pt;")
        
        self.highlight_ports_v = QLineEdit()
        self.highlight_ports_v.setStyleSheet("font-size: 10pt; font-weight: bold;height: 30px;")

        self.highlight_button.clicked.connect(self.highlight_ips)
        self.clear_button.clicked.connect(self.clear_highlight)


        self.highlight_layout.addWidget(self.highlight_label)
        self.highlight_layout.addWidget(self.highlight_input)
        self.highlight_layout.addWidget(self.highlight_ports_l)
        self.highlight_layout.addWidget(self.highlight_ports_v)
        self.highlight_layout.addWidget(self.highlight_button)
        self.highlight_layout.addWidget(self.clear_button)
        self.layout.addLayout(self.highlight_layout)

    def _setup_packet_tables(self) -> None:
        """Setup packet display tables"""
        self.tab_widget = QTabWidget()
        self.packet_tables = {}

        for packet_type in ["TCP", "UDP", "DNS", "ARP", "ICMP"]:
            table = self._create_packet_table()
            self.packet_tables[packet_type] = table
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            table.setStyleSheet("font-size: 10pt;")
            tab_layout.addWidget(table)
            self.tab_widget.addTab(tab, packet_type)

        # Set tab bar style to match table font
        self.tab_widget.setStyleSheet("""
            QTabBar::tab {
            width: 100%;
            height: 20px;
            font-size: 10pt;
            font-weight: bold;
            padding: 8px 16px;
            }
        """)

        self.layout.addWidget(self.tab_widget)

    def _create_packet_table(self) -> QTableWidget:
        """Create a new packet table with proper columns"""
        table = QTableWidget()
        table.setColumnCount(8)
        headers = [
            "Čas", "Zdroj IP/Host", "Zdroj Port",
            "Cíl IP/Host", "Cíl Port",
            "TCP Flagy", "Popis", "Doporučení"
        ]
        table.setHorizontalHeaderLabels(headers)
        
        # Set column widths
        for i in range(8):
            table.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.Interactive
            )
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _setup_statusbar(self):
        self.status_bar_layout = QHBoxLayout()
        status_bar_container = QWidget()
        status_bar_container.setLayout(self.status_bar_layout)
          # Add status label
        self.status_bar_label = QLabel(" Čekám na rozkazy šéfe ... ")
        self.status_bar_label.setStyleSheet("font-size: 8pt")
        self.status_bar_layout.addWidget(self.status_bar_label)
        
        # Add spacer to push theme button to the right
        self.status_bar_layout.addStretch()
        
        # Add theme toggle button
        self.problem_button = QPushButton("⭐")  # Star emoji
        self.problem_button.setStyleSheet("font-size: 10pt;")  
        self.problem_button.setFixedSize(60, 60)
        self.problem_button.clicked.connect(self.toggle_problem)
        self.problem_button.setToolTip("Zobrazit jen problémové / všechny")
        self.status_bar_layout.addWidget(self.problem_button)

        # Add theme toggle button
        self.theme_button = QPushButton("☀️")  # Moon emoji for dark theme
        self.theme_button.setStyleSheet("font-size: 10pt;")
        self.theme_button.setFixedSize(60, 60)
        self.theme_button.clicked.connect(self.toggle_theme)
        self.theme_button.setToolTip("Přepnout světlý/tmavý režim")
        self.status_bar_layout.addWidget(self.theme_button)
        
        self.layout.addWidget(status_bar_container)
        
        self.problems_only = False

        # Set initial theme
        self.current_theme = "dark"
        self.apply_theme(DARK_THEME)
    
    def update_statusbar(self, message: str) -> None:
        """
        Update the status bar label with a given message.
        
        Args:
            message (str): Message to display in the status bar
        """
        if hasattr(self, 'status_bar_label'):
            self.status_bar_label.setText(message)
            QApplication.processEvents()  # Ensure UI updates immediately

    def clear_highlight(self):
        """Clear all highlight colors from tables except for problem packets."""
        for packet_type, table in self.packet_tables.items():
            row_count = table.rowCount()
            col_count = table.columnCount() 
            
            for row in range(row_count):
                # Check the underlying data in the first column to determine if this is a problem packet
                desc_item = table.item(row, 6)  # Get first column item
                problem_flag = (desc_item.background().color() == QColor("#8B0000") or 
                              desc_item.background().color() == QColor("#FFB6C6")) if desc_item else False
                # Check explicit problem markers in the warning column
                reseni_item = table.item(row, 7)  # Doporučení column
                has_warning = reseni_item and reseni_item.text().strip() != ""
                # Combine both checks
                is_problem = problem_flag or has_warning
                
                for col in range(col_count):
                    item = table.item(row, col)
                    if item:
                        if is_problem:
                            # Use theme-appropriate error color
                            error_color = QColor("#8B0000") if self.current_theme == "dark" else QColor("#FFB6C6")
                            item.setBackground(error_color)
                        else:
                            # Use theme-appropriate background
                            bg_color = QColor("#2d2d2d") if self.current_theme == "dark" else Qt.white
                            item.setBackground(bg_color)
            
    def highlight_ips(self):
        highlight_text = self.highlight_input.text().strip()
        highlight_ports = self.highlight_ports_v.text().strip()
        
        ip_list = [ip.strip() for ip in highlight_text.split(",") if ip.strip()]
        port_list = [port.strip() for port in highlight_ports.split(",") if port.strip()]
    
        for packet_type, table in self.packet_tables.items():
            row_count = table.rowCount()

            # Apply highlight
            for row in range(row_count):
                src_ip = table.item(row, 1).text() if table.item(row, 1) else ""
                dst_ip = table.item(row, 3).text() if table.item(row, 3) else ""
                src_port = table.item(row, 2).text() if table.item(row, 2) else ""
                dst_port = table.item(row, 4).text() if table.item(row, 4) else ""
                  # Highlight only the matching column: 1 for src_ip, 3 for dst_ip
                # Choose colors based on current theme
                ip_highlight = QColor("#90EE90") if self.current_theme == "light" else QColor("#006400")  # Light/Dark green
                port_highlight = QColor("#FFFFE0") if self.current_theme == "light" else QColor("#8B8000")  # Light/Dark yellow
                
                if src_ip in ip_list:
                    item = table.item(row, 1)
                    if item:
                        item.setBackground(ip_highlight)
                if dst_ip in ip_list:
                    item = table.item(row, 3)
                    if item:
                        item.setBackground(ip_highlight)
                
                if src_port in port_list:
                    item = table.item(row, 2)
                    if item:
                        item.setBackground(port_highlight)
                if dst_port in port_list:
                    item = table.item(row, 4)
                    if item:
                        item.setBackground(port_highlight)
    
    def get_interface_ip(self, iface):
        """Get IP address for specified interface with proper error handling."""
        try:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET:
                        return addr.address
            return None
        except Exception as e:
            self.update_statusbar("Nepodařilo se získat IP adresu rozhraní")
            logging.error(f"Nepodařilo se získat IP adresu rozhraní: {str(e)}")
            return None
    
    def get_duration_in_seconds(self, duration_text: str) -> int:
        """Convert duration text to seconds."""
        mapping = {
            "10 vteřin": 10,
            "30 vteřin": 30,
            "1 minuta": 60,
            "5 minut": 300,
            "10 minut": 600
        }
        return mapping.get(duration_text, 10)

    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List[str]: List of interface names
        """
        try:
            interfaces = psutil.net_if_addrs().keys()
            return list(interfaces)
        except Exception as e:
            self.update_statusbar("Nelze získat seznam síťových rozhraní.")
            logging.error(f"Nelze získat seznam síťových rozhraní.: {e}")
            return []

    def _populate_ip_addresses_table(self) -> list[str]:
        try:
            """Retrieve a list of local IP addresses."""
            ip_addresses = []
            addrs = psutil.net_if_addrs()

            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:  # Check for IPv4 addresses
                        if addr.address.startswith("127."):
                            continue  # Skip loopback addresses
                        if addr.address.startswith("169.254."):
                            continue  # Skip link-local addresses
                        else:
                            ip_addresses.append(f"{iface} : {addr.address}")
                            break  # Only take the first IPv4 address for each interface
            return ip_addresses
        except Exception as e:
            self.update_statusbar("Nemohu získat IP adresu")
            logging.error(f"Nemohu získat IP adresu: {e}")

    def capture_packets(self) -> List[Any]:
        """
        Capture network packets based on selected interface and duration.
        
        Returns:
            List[Any]: List of captured packets
        """        
        try:
            interface = self.interface
            
            # Show duration selection dialog
            duration = self.show_duration_dialog()
            if duration is None:
                return []
            
            if not self.validate_capture_parameters():
                return []

            self.update_statusbar(f"Čuchám čuchám na {interface} po dobu {duration} vteřin.")
            logging.info(f"Zahajuji zachytávání paketů na {interface} po dobu {duration} vteřin.")
            packets = sniff(iface=interface, timeout=duration, count=PACKET_BUFFER_SIZE, store=True)
            self.last_captured_packets = packets  # Store for saving
            self.save_button.setEnabled(True)  # Enable save button
            return packets

        except Exception as e:
            self.update_statusbar("Chyba během zachytávání paketů.")
            logging.error(f"Chyba během zachytávání paketů.: {e}")
            QMessageBox.critical(self, "Error", f"Zachytávání paketů selhalo: {str(e)}")
            return []

    def _parse_duration(self, duration_text: str) -> int:
        """
        Convert duration text to seconds.
        
        Args:
            duration_text (str): Duration string (e.g., "10 seconds", "1 minute")
            
        Returns:
            int: Duration in seconds
        """
        duration_map = {
            "10 seconds": 10,
            "30 seconds": 30,
            "1 minute": 60,
            "5 minutes": 300,
            "10 minutes": 600
        }
        return duration_map.get(duration_text, 10)    
    
    def validate_capture_parameters(self) -> bool:
        """
        Validate capture parameters before starting capture.
        
        Returns:
            bool: True if parameters are valid, False otherwise
        """
        if not self.interface:
            QMessageBox.warning(self, "Error", "Není vybrán interface")
            return False

        if not self.check_interface_status(self.interface):
            QMessageBox.warning(self, "Error", "Vybraný interface není aktivní.")
            return False

        if not self.check_capture_permissions():
            QMessageBox.warning(self, "Error", "Nedostatečná práva pro zachycování paketů.")
            return False

        return True

    def check_interface_status(self, iface: str) -> bool:
        """
        Check if selected interface is active.
        
        Args:
            iface (str): Interface name
            
        Returns:
            bool: True if interface is active, False otherwise
        """
        try:
            stats = psutil.net_if_stats()
            return stats.get(iface, None) is not None and stats[iface].isup
        except Exception as e:
            self.update_statusbar("Nelze komunikovat s rozhraním.")
            logging.error(f"Nelze komunikovat s rozhraním: {e}")
            return False

    def check_capture_permissions(self) -> bool:
        """
        Check if application has necessary permissions for packet capture.
        
        Returns:
            bool: True if permissions are sufficient, False otherwise
        """
        try:
            # Try to create a raw socket to test permissions
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                return True
        except PermissionError:
            self.update_statusbar("Nedostatečná práva k zachytávání paketů.")
            logging.error("Nedostatečná práva k zachytávání paketů")
            return False
        except Exception as e:
            self.update_statusbar("Nemohu zjistit oprávnění.")
            logging.error(f"Nemohu zjistit oprávnění: {e}")
            return False

    def parse_packets(self, packets: List[Any]) -> Tuple[List[Dict], List[Dict], List[Dict], List[Dict], List[Dict]]:
        """
        Parse captured packets and categorize them by protocol.
        
        Args:
            packets (List[Any]): Raw captured packets
            
        Returns:
            Tuple containing lists of parsed TCP, UDP, DNS, ARP, and ICMP packets
        """
        parsed_tcp = []
        parsed_udp = []
        parsed_dns = []
        parsed_arp = []
        parsed_icmp = []        
        
        for packet in packets:
            try:
                # Convert packet time to proper format, handling EDecimal
                try:
                    packet_time = float(packet.time)  # Convert EDecimal to float first
                    packet_time = datetime.fromtimestamp(packet_time).strftime('%H:%M:%S.%f')[:-4]
                except (ValueError, TypeError, AttributeError):
                    packet_time = datetime.now().strftime('%H:%M:%S.%f')[:-4]
                
                if ARP in packet:
                    parsed_arp.append(self._parse_arp_packet(packet, packet_time))
                elif IP in packet:
                    if DNS in packet:
                        parsed_dns.append(self._parse_dns_packet(packet, packet_time))
                    elif TCP in packet:
                        parsed_tcp.append(self._parse_tcp_packet(packet, packet_time))
                    elif UDP in packet:
                        parsed_udp.append(self._parse_udp_packet(packet, packet_time))
                    elif ICMP in packet:
                        parsed_icmp.append(self._parse_icmp_packet(packet, packet_time))
                        
            except Exception as e:
                self.update_statusbar(f"Nepovedlo se zpracovat paket: {str(e)}")
                logging.error(f"Nepovedlo se zpracovat paket: {e}")
                continue
        
        # Clear trackers
        self.syn_tracker.clear()
        if hasattr(self, 'arp_request_counter'):
            self.arp_request_counter.clear()
        if hasattr(self, 'arp_ip_to_mac'):
            self.arp_ip_to_mac.clear()
        self.udp_flood_tracker.clear()

        return parsed_tcp, parsed_udp, parsed_dns, parsed_arp, parsed_icmp

    def _parse_tcp_packet(self, packet: Any, packet_time: str) -> Dict[str, Any]:
        """Parse TCP packet and extract relevant information"""
        try:
            flags = str(packet[TCP].flags)
            desc, popis, doporuceni, is_problem = self.describe_tcp_flags(flags)
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Safely convert ports using int() directly
            try:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
            except (ValueError, TypeError, AttributeError):
                src_port = 0
                dst_port = 0

            extra_notes = []

            if 'S' in flags and 'A' not in flags:
                key = (src_ip, dst_ip, dst_port)
                self.syn_tracker[key] = self.syn_tracker.get(key, 0) + 1
                if self.syn_tracker[key] > 3:
                    extra_notes.append(
                        f"Více než 3 SYN pakety bez odpovědi na {dst_ip}:{dst_port} – server nemusí být dostupný nebo spojení je blokováno."
                    )
                    is_problem = True

            if dst_port in self.tcp_suspicious_ports:
                extra_notes.append(f"Přístup na rizikový port {dst_port} – potenciální bezpečnostní riziko.")
                is_problem = True

            full_recommendation = doporuceni
            if extra_notes:
                full_recommendation += " " + " ".join(extra_notes)

            return PacketInfo(
                time=packet_time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags=desc,
                desc=popis,
                reseni=full_recommendation.strip(),
                problem=is_problem
            ).__dict__
        except Exception as e:
            logging.error(f"Chyba při zpracování TCP paketu: {e}")
            raise

    def _parse_udp_packet(self, packet: Any, packet_time: str) -> Dict[str, Any]:
        """Parse UDP packet and extract relevant information"""
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            try:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            except (ValueError, TypeError, AttributeError):
                src_port = 0
                dst_port = 0

            is_problem = False
            reseni = ""
            desc = "UDP komunikace"

            if dst_port in self.udp_suspicious_ports:
                reseni += f"Přístup na potenciálně zneužitelný port {dst_port} – zkontroluj aplikaci nebo firewall. "
                is_problem = True

            key = (src_ip, dst_ip)
            if key not in self.udp_flood_tracker:
                self.udp_flood_tracker[key] = set()
            self.udp_flood_tracker[key].add(dst_port)

            if len(self.udp_flood_tracker[key]) > 10:
                reseni += f" Zdroj {src_ip} se pokouší kontaktovat více než 10 různých portů na {dst_ip} – možný scan."
                is_problem = True

            return PacketInfo(
                time=packet_time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                desc=desc,
                reseni=reseni.strip(),
                problem=is_problem
            ).__dict__
        except Exception as e:
            logging.error(f"Chyba při zpracování UDP paketu: {e}")
            raise

    def _parse_dns_packet(self, packet: Any, packet_time: str) -> Dict[str, Any]:
        """Parse DNS packet and extract relevant information"""
        try:
            dns_info = packet[DNS]
            is_response = dns_info.qr == 1
            is_problem = False
            flags = []
            reseni = ""
            desc = ""

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Safely convert ports
            try:
                src_port = int(float(packet[UDP].sport))
                dst_port = int(float(packet[UDP].dport))
            except (ValueError, TypeError, AttributeError):
                src_port = 0
                dst_port = 0

            # DNS query/response
            if is_response:
                flags.append("Odpověď")
                rcode = dns_info.rcode

                if rcode == 0:
                    desc = "Odpověď v pořádku"
                elif rcode == 3:
                    desc = "NXDOMAIN – doména neexistuje"
                    reseni = "Zkontroluj správnost názvu domény. Server tvrdí, že doména neexistuje."
                    is_problem = True
                elif rcode == 2:
                    desc = "SERVFAIL – DNS server selhal"
                    reseni = "DNS server nedokázal odpovědět. Zkus použít jiný DNS server (např. 1.1.1.1 nebo 8.8.8.8)."
                    is_problem = True
                else:
                    desc = f"DNS chyba (RCODE={rcode})"
                    reseni = "DNS odpověď obsahuje chybu. Může jít o síťový problém nebo nesprávnou konfiguraci."
                    is_problem = True

            else:
                flags.append("Dotaz")
                desc = "Dotaz na doménu"

            return PacketInfo(
                time=packet_time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags=" | ".join(flags),
                desc=desc,
                reseni=reseni,
                problem=is_problem
            ).__dict__
        except Exception as e:
            logging.error(f"Chyba při zpracování DNS paketu: {e}")
            raise

    def _parse_arp_packet(self, packet: Any, packet_time: str) -> Dict[str, Any]:
        """Parse ARP packet and extract relevant information"""
        try:
            operation = packet[ARP].op
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            dst_ip = packet[ARP].pdst
            
            # ARP doesn't use ports, but we'll maintain consistent return structure
            src_port = None
            dst_port = None

            desc = "Dotaz" if operation == 1 else "Odpověď"
            is_problem = False
            reseni = ""

            # --- ARP odpověď bez předchozího dotazu ---
            if operation == 2:
                if dst_ip == "0.0.0.0" or not dst_ip:
                    reseni = "ARP odpověď bez platného cíle – může jít o pokus o podvržení MAC adresy."
                    is_problem = True

            # --- Sledování MAC/IP – konflikty ---
            key = src_ip
            if not hasattr(self, 'arp_ip_to_mac'):
                self.arp_ip_to_mac = {}

            previous_mac = self.arp_ip_to_mac.get(key)
            if previous_mac and previous_mac != src_mac:
                reseni += f" IP {src_ip} byla dříve spojena s jinou MAC adresou – možný konflikt nebo spoofing."
                is_problem = True
            else:
                self.arp_ip_to_mac[key] = src_mac

            # --- Detekce ARP floodu ---
            if not hasattr(self, 'arp_request_counter'):
                self.arp_request_counter = {}

            if operation == 1:
                self.arp_request_counter[src_ip] = self.arp_request_counter.get(src_ip, 0) + 1
                if self.arp_request_counter[src_ip] > 20:
                    reseni += f" Zařízení {src_ip} posílá velké množství ARP dotazů – možný flood nebo chyba."
                    is_problem = True

            return PacketInfo(
                time=packet_time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flags=desc,
                desc=f"{desc} na IP {dst_ip}",
                reseni=reseni.strip(),
                problem=is_problem
            ).__dict__
        except Exception as e:
            logging.error(f"Chyba při zpracování ARP paketu: {e}")
            raise

    def _parse_icmp_packet(self, packet: Any, packet_time: str) -> Dict[str, Any]:
        """Parse ICMP packet and extract relevant information"""
        try:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code

            # ICMP doesn't use ports, but we'll maintain consistent return structure
            src_port = None
            dst_port = None
            
            type_descriptions = {
                0: "PONG (odpověď)",
                3: "Destination Unreachable - Cíl je nedostupný",
                8: "PING (dotaz)",
                11: "Time Exceeded - Překročen časový limit"
            }
            
            is_problem = False
            reseni = ""

            description = type_descriptions.get(icmp_type, f"Type {icmp_type}")
            if icmp_type == 3:  # Destination Unreachable
                description += f" (Code {icmp_code})"
                reseni = "Zařízení odpovědělo, že nemůže doručit paket. Zkontroluj IP a port cílového zařízení."
                is_problem = True
            elif icmp_type == 11:
                reseni = "TTL vypršel během přenosu – může jít o chybu v routování nebo smyčku v síti."
                is_problem = True
            elif icmp_type not in [0, 8]:
                is_problem = True
                reseni = "Netypická ICMP zpráva – může značit problém nebo pokročilé síťové chování."
            else:
                reseni = ""                     

            return PacketInfo(
                time=packet_time,
                src_ip=packet[IP].src,
                src_port=src_port,
                dst_ip=packet[IP].dst,
                dst_port=dst_port,
                desc=description,
                reseni=reseni,
                problem=is_problem
            ).__dict__
        except Exception as e:
            logging.error(f"Chyba při zpracování ICMP paketu: {e}")
            raise

    def describe_tcp_flags(self, flags: str) -> tuple[str, str, str, bool]:
        """
        Analyze TCP flags and return their description.
        
        Args:
            flags (str): TCP flags string
            
        Returns:
            tuple: (flag description, explanation, recommendation, is_problem)
        """
        active_flags = []
        descriptions = []
        recommendations = []
        has_problem = False

        for flag in flags:
            if flag in TCP_FLAGS:
                name, desc, problem = TCP_FLAGS[flag]
                active_flags.append(name)
                descriptions.append(desc)
                has_problem |= problem
                if problem:
                    if "RST" in active_flags:
                        recommendations.append(f"Spojení bylo náhle ukončeno. Zkontroluj zda je stále aktivní a naslouchá na požadovaném portu. Zkontroluj Firewall nebo antivir.")
                    else:
                        recommendations.append(f"Zkontroluj {name} TCP flag: {desc}")

        return (
            " | ".join(active_flags) or " ",
            " | ".join(descriptions) or "Žádné flagy",
            " | ".join(recommendations) or "",
            has_problem
        )    
    
    @lru_cache(maxsize=1000)
    def reverse_dns(self, ip: str, dns_server: Optional[str] = None) -> str:
        """
        Perform reverse DNS lookup with caching.
        
        Args:
            ip (str): IP address to resolve
            dns_server (Optional[str]): DNS server to use
            
        Returns:
            str: Hostname or original IP if lookup fails
        """
        try:
            # Skip private/local IP addresses
            if any([
                ip.startswith(("192.168.", "10.", "172.16.")),  # Private ranges
                ip.startswith("169.254."),  # Link-local
                ip.startswith("127."),      # Loopback
                ip.startswith("224."),      # Multicast
                ip.startswith("239."),      # Multicast
            ]):
                return ip

            # Check cache first
            cached_hostname = self.dns_cache.get(ip)
            if cached_hostname:
                return cached_hostname            # Perform reverse DNS lookup with timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2  # 2 second timeout
            resolver.lifetime = 2  # 2 second total query time
            if dns_server:
                resolver.nameservers = [dns_server]
            else:
                resolver.nameservers = ['8.8.8.8']  # Use Google DNS as fallback
                
            addr = dns.reversename.from_address(ip)
            try:
                answers = resolver.resolve(addr, "PTR")
                hostname = str(answers[0]).rstrip('.')
                # Cache the result
                self.dns_cache.set(ip, hostname)
                return hostname
            except dns.resolver.NXDOMAIN:
                return ip  # No reverse DNS record exists
            except dns.resolver.NoNameservers:
                return ip  # DNS server refused to answer
            except dns.resolver.NoAnswer:
                return ip  # DNS server has no answer

        except Exception as e:
            self.update_statusbar(f"Selhal reverzní DNS dotaz pro {ip}")
            logging.debug(f"Selhal reverzní DNS dotaz pro {ip}: {e}")
            return ip

    def update_tables(
        self,
        packets_tcp: list[dict],
        packets_udp: list[dict],
        packets_dns: list[dict],
        packets_arp: list[dict],
        packets_icmp: list[dict]
    ) -> None:
        """
        Updates the packet display tables.
        
        Args:
            packets_tcp: List of TCP packets
            packets_udp: List of UDP packets
            packets_dns: List of DNS packets
            packets_arp: List of ARP packets
            packets_icmp: List of ICMP packets
        """
        # Clear existing table contents
        for table in self.packet_tables.values():
            table.setRowCount(0)

        # Update tables with new data
        packet_data = {
            "TCP": packets_tcp,
            "UDP": packets_udp,
            "DNS": packets_dns,
            "ARP": packets_arp,
            "ICMP": packets_icmp
        }

        for protocol, packets in packet_data.items():
            table = self.packet_tables[protocol]
            for packet in packets:
                row = table.rowCount()
                table.insertRow(row)
                
                # Resolve hostnames if enabled
                src_ip = packet.get("src_ip", "")
                dst_ip = packet.get("dst_ip", "")
                if self.ip_to_hostname_checkbox.isChecked():
                    src_display = self.reverse_dns(src_ip)
                    dst_display = self.reverse_dns(dst_ip)
                else:
                    src_display = src_ip
                    dst_display = dst_ip

                # Populate table row
                self._set_table_row(
                    table, row,
                    time=packet.get("time", ""),
                    src_ip=src_display,
                    src_port=packet.get("src_port", ""),
                    dst_ip=dst_display,
                    dst_port=packet.get("dst_port", ""),
                    flags=packet.get("flags", ""),
                    desc=packet.get("desc", ""),
                    reseni=packet.get("reseni", ""),
                    problem=packet.get("problem", False)
                )

    def _set_table_row(
        self, 
        table: QTableWidget,
        row: int,
        **kwargs
    ) -> None:
        """
        Set values for a table row with optional highlighting.
        
        Args:
            table: QTableWidget to update
            row: Row number
            **kwargs: Column values to set
        """
        columns = [
            "time", "src_ip", "src_port", "dst_ip",
            "dst_port", "flags", "desc", "reseni"
        ]
        
        for col, key in enumerate(columns):
            item = QTableWidgetItem(str(kwargs.get(key, "")))

            if key in ("src_port", "dst_port"):
                port_val = kwargs.get(key, "")
                port_str = str(port_val) if port_val is not None else ""
                if port_str in PORTS_HELP:
                    item.setToolTip(PORTS_HELP[port_str])

            if kwargs.get("problem", False):
                # Use darker red for dark theme, lighter red for light theme
                error_color = QColor("#8B0000") if self.current_theme == "dark" else QColor("#FFB6C6")
                item.setBackground(error_color)
            table.setItem(row, col, item)

    def show_capture_summary(
        self,
        parsed_packets_tcp: list[dict],
        parsed_packets_udp: list[dict],
        parsed_packets_dns: list[dict],
        parsed_packets_arp: list[dict],
        parsed_packets_icmp: list[dict]
    ) -> None:
        """
        Display a summary of captured packets in a message box and log the information.

        Args:
            parsed_packets_tcp: List of parsed TCP packets
            parsed_packets_udp: List of UDP packets
            parsed_packets_dns: List of DNS packets
            parsed_packets_arp: List of ARP packets
            parsed_packets_icmp: List of ICMP packets
        """
        total_packets = sum(len(packets) for packets in [
            parsed_packets_tcp, parsed_packets_udp,
            parsed_packets_dns, parsed_packets_arp, parsed_packets_icmp
        ])

        protocol_counts = {
            "TCP": len(parsed_packets_tcp),
            "UDP": len(parsed_packets_udp),
            "DNS": len(parsed_packets_dns),
            "ARP": len(parsed_packets_arp),
            "ICMP": len(parsed_packets_icmp)
        }

        # Create detailed summary
        summary_lines = ["Souhrn zachycených paketů:"]
        summary_lines.extend([
            f"• {proto}: {count} paketů"
            for proto, count in protocol_counts.items()
        ])
        summary_lines.append(f"Celkem: {total_packets} paketů.")
        summary_message = "\n".join(summary_lines)

        # Log the summary
        logging.info("Zpracování paketů dokončeno")
        logging.info("=" * 50)
        logging.info(f"Paketů celkem: {total_packets}")
        logging.info(" | ".join(f"{proto}: {count}" 
                              for proto, count in protocol_counts.items()))
        logging.info("=" * 50)

        # Show summary in GUI
        QMessageBox.information(self, "Souhrn", summary_message)

    def run(self) -> None:
        """Main execution method"""
        self.update_statusbar(f" Čekám na rozkazy šéfe ... ")
        try:
            # Validate and capture
            if not self.validate_capture_parameters():
                return

            # Perform capture
            raw_packets = self.capture_packets()
            if not raw_packets:
                QMessageBox.warning(self, "Warning", "Žádné pakety nebyly zachyceny")
                return

            # Parse captured packets
            parsed_results = self.parse_packets(raw_packets)
            if not any(parsed_results):
                QMessageBox.warning(self, "Warning", "Nenalezeny žádné pakety")
                return

            # Update display
            self.show_capture_summary(*parsed_results)
            self.update_tables(*parsed_results)

        except Exception as e:
            self.update_statusbar(f"Chyba během analýzy packetů.")
            logging.error(f"Chyba během analýzy paketů.: {str(e)}")
            QMessageBox.critical(self, "Error", f"Nastala chyba: {str(e)}")
        

        self.update_statusbar(f"A to je konec, Tadýdádýdá ... A teď se tím prohrab - příjemnou zábavu :-)")
        
    def _on_interface_selected(self, item: QListWidgetItem) -> None:
        """Handle interface selection from the list"""
        # Extract interface name from item text
        self.interface = item.text().split(" - ")[0]
        # Get IP address from selected interface
        self.my_ip = self.get_interface_ip(self.interface)
        self.my_ip_value.setText(self.my_ip)
        # Automatically start capture
        self.run()

    def show_duration_dialog(self) -> Optional[int]:
        """Show dialog for duration selection and return selected duration in seconds"""
        self.update_statusbar(f"Vyber si jak dlouho mám čmuchat.")
        dialog = QDialog(self)
        dialog.setWindowTitle("Vybrat délku zachytávání")
        layout = QVBoxLayout()
        dialog.setLayout(layout)

        durations = [
            ("10 vteřin", 10),
            ("30 vteřin", 30),
            ("1 minuta", 60),
            ("5 minut", 300),
            ("10 minut", 600)
        ]

        def select_duration(seconds: int):
            dialog.duration = seconds
            dialog.accept()

        for label, seconds in durations:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, s=seconds: select_duration(s))
            btn.setStyleSheet("font-size: 10pt; padding: 10px;")
            layout.addWidget(btn)

        dialog.duration = None
        dialog.exec_()
        return dialog.duration

def main():
    """Application entry point"""
    try:
        # Setup logging
        setup_logging()
        logging.info("Startuji EasyShark")

        # Create and run application
        app = QApplication(sys.argv)
        app.setStyleSheet("QMessageBox QPushButton { font-size: 10pt; }")
        window = PacketSniffer()
        window.show()

        # Start event loop
        sys.exit(app.exec_())

    except Exception as e:
        logging.critical(f"Nepodařilo se spustit aplikaci.: {str(e)}")
        if 'app' in locals():
            QMessageBox.critical(None, "Fatal Error", 
                               f"Chyba při spuštění.: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
