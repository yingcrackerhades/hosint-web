
#!/usr/bin/env python3

import requests
import socket
from datetime import datetime
import json
import ssl
import dns.resolver, dns.reversename
import re
import platform
import sys
import os
import threading

RED = "\x1B[31m"
BRED = "\x1B[41m"
GREEN = "\x1B[32m"
BGREEN = "\x1B[42m"
DEFAULT = "\x1B[0m"
nc="\033[1;37m"
yellow="\033[1;33m"

HELP = f""" {GREEN}   > METHODS:{DEFAULT} SHOWS LIST OF METHODS
 {GREEN}   > USAGE:{DEFAULT} SHOWS LIST OF METHODS USAGE"""

METHOD = f""" {GREEN}--{RED} URL:
 {GREEN}   > HINFO:{DEFAULT} HTTP HEADERS SCANNER
 {GREEN}   > HSECURE: {DEFAULT}HTTP SECURITY HEADERS SCANNER
 {GREEN}--{RED} DOMAIN:
 {GREEN}   > WEBTECH:{DEFAULT} WEBSITE TECHNOLOGY LOOKUP
 {GREEN}   > WHOIS:{DEFAULT} WHOIS LOOKUP
 {GREEN}   > RWHOIS: {DEFAULT}REVERSE WHOIS LOOKUP
 {GREEN}   > IPHISTORY: {DEFAULT}IP HISTORY LOOKUP
 {GREEN}   > DNSLOOK: {DEFAULT}DNS RECORDS LOOKUP
 {GREEN}   > SUBDOMAINS:{DEFAULT} SUBDOMAINS SCANNER
 {GREEN}   > CERTFILE: {DEFAULT}CERTIFICATE LOOKUP
 {GREEN}--{RED} IP:
 {GREEN}   > IPLOOK:{DEFAULT} IP ADDRESS LOOKUP
 {GREEN}   > RIPLOOK:{DEFAULT} REVERSE IP ADDRESS LOOKUP
 {GREEN}   > RDNSLOOK:{DEFAULT} REVERSE DNS LOOKUP
 {GREEN}   > TCPSCAN:{DEFAULT} TCP PORTS SCANNER
 {GREEN}   > UDPSCAN: {DEFAULT}UDP PORTS SCANNER"""

USAGE = f""" {GREEN}--{RED} URL:
 {GREEN}   > HINFO: HINFO [URL] {yellow}=>{DEFAULT} HINFO [https://example.com]
 {GREEN}   > HSECURE: HSECURE [URL] {yellow}=>{DEFAULT} HSECURE [https://example.com]
 {GREEN}--{RED} DOMAIN:
 {GREEN}   > WEBTECH: WEBTECH [DOMAIN] {yellow}=>{DEFAULT} WEBTECH [example.com]
 {GREEN}   > WHOIS: WHOIS [DOMAIN] {yellow}=>{DEFAULT} WHOIS [example.com]
 {GREEN}   > RWHOIS: RWHOIS [DOMAIN] {yellow}=>{DEFAULT} RWHOIS [example.com]
 {GREEN}   > IPHISTORY: IPHISTORY [DOMAIN] {yellow}=>{DEFAULT} IPHISTORY [example.com]
 {GREEN}   > DNSLOOK: DNSLOOK [DOMAIN] {yellow}=>{DEFAULT} DNSLOOK [example.com]
 {GREEN}   > SUBDOMAINS: SUBDOMAINS [DOMAIN] {yellow}=>{DEFAULT} SUBDOMAINS [example.com]
 {GREEN}   > CERTFILE: CERTFILE [DOMAIN] {yellow}=>{DEFAULT} CERTFILE [example.com]
 {GREEN}--{RED} IP:
 {GREEN}   > IPLOOK: IPLOOK [IP] {yellow}=>{DEFAULT} IPLOOK [1.1.1.1]
 {GREEN}   > RIPLOOK: RIPLOOK [DOMAIN, IP] {yellow}=>{DEFAULT} RIPLOOK [example.com, 1.1.1.1]
 {GREEN}   > RDNSLOOK: RDNSLOOK [IP] {yellow}=>{DEFAULT} RDNSLOOK [1.1.1.1]
 {GREEN}   > TCPSCAN: TCPSCAN [IP] [PORT {yellow}=>{DEFAULT} COMMON, OWN{GREEN}] {yellow}=>{DEFAULT} TCPSCAN [1.1.1.1] [COMMON, 80]
 {GREEN}   > UDPSCAN: UDPSCAN [IP] [PORT {yellow}=>{DEFAULT} COMMON, OWN{GREEN}] {yellow}=>{DEFAULT} UDPSCAN [1.1.1.1] [COMMON, 80]"""

EXIT = f"""{yellow} Are you sure to exit?{nc}({GREEN}y{nc}/{RED}t{nc}): """
def LOGO():
    os.system("clear")
    sistem = platform.uname()
    LOGO = f"""
	                {RED}.YYY555PPPPGGGG?
	                .BBB####&&&&&@@?
	                .GBBB:.....P&&@?
	         .~     .GBBG      5@&@?
	        ^BJ     .GBBG      5@&@?
	       ?B#J     .GBBG      5@&@?   {yellow}| {nc}System    : {GREEN}{sistem.system}{RED}
	      !BBBJ     .PGGG      5@&@?   {yellow}| {nc}Node Name : {GREEN}{sistem.node}{RED}
	      !BB#J                5@&@?   {yellow}| {nc}Machine   : {GREEN}{sistem.machine}{RED}
	      !BB#J     {GREEN}HADES{RED}      5@&@?   {yellow}| {nc}Release   : {GREEN}{sistem.release}
	     {nc} !BB#J        ..      5@&@?
	      !BB#J      #&&&.     5@&@?
	      !BB#J      &&@@.     5@@5
	      !BB#J      &&@&.     P&~
	      !BB#J      &&@&.     !.
	      !BBBY.....:&&@&.
	      !BBB###&&&&&@@@.
	      !YYYY555PPPGGGG.{nc}

	   [{RED}+{nc}]{GREEN}HOSINT{nc}({RED}Hades Information {nc}Gathering Tool)-{GREEN}WEB{nc}[{RED}+{nc}]
	"""
    print(LOGO)


def MAIN():
    PILIHAN = input(f" {GREEN}hosint{nc}>{DEFAULT} ")
    PILIHAN_INFO = PILIHAN.split(" ")[0]
    if PILIHAN_INFO.upper() == "HELP":
        print(HELP)
    elif PILIHAN_INFO.upper() == "METHODS":
        print(METHOD)
    elif PILIHAN_INFO.upper() == "USAGE":
        print(USAGE)
    elif PILIHAN_INFO.upper() == "EXIT":
        pilihan = input(EXIT)
        if pilihan == "Y" or pilihan == "y":
              sys.exit()
        else:
           return MAIN()
    elif PILIHAN_INFO.upper() == "HINFO":
        HINFO(PILIHAN)
    elif PILIHAN_INFO.upper() == "HSECURE":
        HSECURE(PILIHAN)
    elif PILIHAN_INFO.upper() == "WEBTECH":
        WEBTECH(PILIHAN)
    elif PILIHAN_INFO.upper() == "WHOIS":
        WHOIS(PILIHAN)
    elif PILIHAN_INFO.upper() == "RWHOIS":
        RWHOIS(PILIHAN)
    elif PILIHAN_INFO.upper() == "IPHISTORY":
        IPHISTORY(PILIHAN)
    elif PILIHAN_INFO.upper() == "DNSLOOK":
        DNSLOOK(PILIHAN)
    elif PILIHAN_INFO.upper() == "SUBDOMAINS":
        SUBDOMAINS(PILIHAN)
    elif PILIHAN_INFO.upper() == "CERTFILE":
        CERTFILE(PILIHAN)
    elif PILIHAN_INFO.upper() == "IPLOOK":
        IPLOOK(PILIHAN)
    elif PILIHAN_INFO.upper() == "RIPLOOK":
        RIPLOOK(PILIHAN)
    elif PILIHAN_INFO.upper() == "RDNSLOOK":
        RDNSLOOK(PILIHAN)
    elif PILIHAN_INFO.upper() == "TCPSCAN":
        TCPSCAN(PILIHAN)
    elif PILIHAN_INFO.upper() == "UDPSCAN":
        UDPSCAN(PILIHAN)
    print("")
    return MAIN()


def HINFO(PILIHAN):
    try:
        PILIHAN_INFO, URL = PILIHAN.split(" ")
        if URL == "":
            raise ValueError
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(URL.lower(), verify=True).headers
            for NAME, INFO in REQUEST.items():
                print(f" {GREEN}|{DEFAULT} {NAME}: {INFO}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] HINFO [URL] {GREEN}=>{DEFAULT} HINFO [https://example.com]")
        return MAIN()


def HSECURE(PILIHAN):
    SECURITY_LIST = ["Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options",
                     "Content-Security-Policy", "Referrer-Policy", "Cross-Origin-Embedder-Policy",
                     "Cross-Origin-Opener-Policy",
                     "Cross-Origin-Resource-Policy", "Cache-Control", "Permissions-Policy", "X-XSS-Protection"]
    SECURITY_LIST_ADD = []
    try:
        PILIHAN_INFO, URL = PILIHAN.split(" ")
        if URL == "":
            raise ValueError
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(URL.lower(), verify=True).headers
            for NAME, INFO in REQUEST.items():
                if NAME in SECURITY_LIST:
                    NAME = f"{BGREEN}{NAME}{DEFAULT}"
                    SECURITY_LIST_ADD.append(NAME.strip(f"{BGREEN}{DEFAULT}"))
                print(f" {GREEN}|{DEFAULT} {NAME}: {INFO}")
            for SUCCES_LIST in SECURITY_LIST_ADD:
                SECURITY_LIST.remove(SUCCES_LIST)
            print(f" {GREEN}|{DEFAULT} [{GREEN}INFO{DEFAULT}] HEADERS:")
            for FAIL_LIST in SECURITY_LIST:
                print(f" {GREEN}| |{DEFAULT} no {BRED}{FAIL_LIST}{DEFAULT}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] HSECURE [URL] {GREEN}=>{DEFAULT} HSECURE [https://example.com]")
        return MAIN()


def WEBTECH(PILIHAN):
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://w3techs.com/sites/info/{DOMAIN.lower()}")
            if "This site is currently under maintenance. We will be back soon." in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] w3techs.com: BLOCKED YOU")
                return MAIN()
            elif "W3Techs has not yet crawled this site!" in RESULT.text:
                print(f" [{GREEN}INFO{DEFAULT}] w3techs.com: NOTHING FOUND")
                return MAIN()
            for EXCEPTION, NAME, INFO in re.findall(
                    r"(<.*?>)<a href=\"https://w3techs.com/technologies/(.*?)/.*?>(.*?)</a>", REQUEST.text):
                if NAME == "details":
                    INFO = f"{GREEN}|{DEFAULT} {INFO}"
                if "<s>" in EXCEPTION:
                    INFO = f"{INFO}: {BRED}used until recently{DEFAULT}"
                print(f" {GREEN}|{DEFAULT} {INFO}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] WEBTECH: WEBTECH [DOMAIN] {GREEN}=>{DEFAULT} WEBTECH [example.com]")
        return MAIN()


def WHOIS(PILIHAN):
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://www.whois.com/whois/{DOMAIN.lower()}")
            if "<div id=\"securityBlk\" style=\"display: block\">" in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] www.whois.com: CAPTCHA")
            RAW_REQUEST = requests.post(f"https://whois-webform.markmonitor.com/whois",
                                        data={"btn": "getWhois", "domain": DOMAIN.lower()})
            RAW_JSON = json.loads(RAW_REQUEST.text)
            for NAME, INFO in zip(re.findall("df-label\">(.*?)</div>", REQUEST.text),
                                  re.findall("df-value\">(.*?)</div>", REQUEST.text)):
                INFO = INFO.replace("<br>", " ")
                print(f" {GREEN}|{DEFAULT} {NAME} {INFO}")
            print(f" [{GREEN}INFO{DEFAULT}] RAW VERSION:")
            for RAW in RAW_JSON["whois"].replace("<br>", "\n").split("\n"):
                if "Domain Name" in RAW or "Registrar:" in RAW or "Creation Date" in RAW or "Updated Date" in RAW or "Domain Status" in RAW:
                    RAW = f"{BGREEN}{RAW}{DEFAULT}"
                print(f" {GREEN}|{DEFAULT} {RAW}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] WHOIS [DOMAIN] {GREEN}=>{DEFAULT} WHOIS [example.com]")
        return MAIN()


def RWHOIS(PILIHAN):
    TIME_LIST = []
    REG_LIST = []
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://viewdns.info/reversewhois/?q={DOMAIN}", headers={
                "user-agent": "Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1"})
            if "There are 0 domains that matched this search query." in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] viewdns.info: NOTHING FOUND")
                return MAIN()
            elif "Search term is too short. Please be more specific in your search term." in REQUEST.text:
                print(
                    f" [{GREEN}INFO{DEFAULT}] viewdns.info: SEARCH TERM IS TOO SHORT. PLEASE BE MORE SPECIFIC IN YOUT SEARCH TERM")
                return MAIN()
            elif "Completing the CAPTCHA proves you are a human and gives you temporary access to the web property." in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] viewdns.info: CAPTCHA")
                return MAIN()
            INFO3 = re.findall(r"<td>([0-9]\w+-[0-9]\w+-.*?|())</td><td>(.*?)</td>", REQUEST.text)
            for TIME, EMPTY, REG in INFO3:
                if not TIME:
                    TIME = f"{BRED}          {DEFAULT} {RED}!{DEFAULT}  "
                if not REG:
                    REG = f"{BRED}          {DEFAULT} {RED}!{DEFAULT}"
                TIME_LIST.append(TIME)
                REG_LIST.append(REG)
            print(" %-1s %-47s %-1s %-5s %-1s %s" % (
                f"{GREEN}|{DEFAULT}", "Domain Name:", f"{GREEN}|{DEFAULT}", "Creation Date:", f"{GREEN}|{DEFAULT}",
                "Registrar:"))
            if len(re.findall("</td><td>.*?</td></tr><tr><td>(.*?)</td>", REQUEST.text)) >= 100:
                for NAME, TIME, REG in zip(re.findall("</td><td>.*?</td></tr><tr><td>(.*?)</td>", REQUEST.text)[0:100],
                                           TIME_LIST[0:100], REG_LIST[0:100]):
                    if len(NAME) >= 44:
                        NAME = f"{NAME[:44]}{GREEN}...{DEFAULT}"
                    print(" %-1s %-47s %-1s %-14s %-1s %s" % (
                        f"{GREEN}|{DEFAULT}", NAME, f"{GREEN}|{DEFAULT}", TIME, f"{GREEN}|{DEFAULT}", REG))
                print(f" [{GREEN}INFO{DEFAULT}] OUTPUT TOO BIG!")
            else:
                for NAME, TIME, REG in zip(re.findall("</td><td>.*?</td></tr><tr><td>(.*?)</td>", REQUEST.text),
                                           TIME_LIST, REG_LIST):
                    if len(NAME) >= 44:
                        NAME = f"{NAME[:44]}{GREEN}...{DEFAULT}"
                    print(" %-1s %-47s %-1s %-14s %-1s %s" % (
                        f"{GREEN}|{DEFAULT}", NAME, f"{GREEN}|{DEFAULT}", TIME, f"{GREEN}|{DEFAULT}", REG))
            FILE = open("rwhois.txt", "w+")
            FILE.write(f"[INFO] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nTARGET: {DOMAIN}\n\n")
            for NAME, TIME, REG in zip(re.findall("</td><td>.*?</td></tr><tr><td>(.*?)</td>", REQUEST.text),
                                       TIME_LIST, REG_LIST):
            	FILE.write(" %-1s %-47s %-1s %-14s %-1s %s" % (f"|", NAME, f"|", TIME, f"|", REG + "\n"))
            FILE.close()
            print(f" [{GREEN}INFO{DEFAULT}] SAVED: rwhois.txt")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] RWHOIS [DOMAIN] {GREEN}=>{DEFAULT} RWHOIS [example.com]")
        return MAIN()


def IPHISTORY(PILIHAN):
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://viewdns.info/iphistory/?domain={DOMAIN}", headers={
                "user-agent": "Mozilla/5.0 (Windows NT 5.1; rv:7.0.1) Gecko/20100101 Firefox/7.0.1"}, timeout=30)
            if "Unfortunately we do not have any records for this hostname." in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] viewdns.info: NOTHING FOUND")
                return MAIN()
            elif "Please complete the security check to access viewdns.info" in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] viewdns.info: CAPTCHA")
                return MAIN()
            elif "Completing the CAPTCHA proves you are a human and gives you temporary access to the web property." in REQUEST.text:
                print(f" [{GREEN}INFO{DEFAULT}] viewdns.info: CAPTCHA")
                return MAIN()
            print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                f"{GREEN}|{DEFAULT}", "IP Address:", f"{GREEN}|{DEFAULT}", "Location:", f"{GREEN}|{DEFAULT}",
                "IP Address Owner:", f"{GREEN}|{DEFAULT}", "Last seen on this IP:"))
            if len(re.findall(r"<td>(\d.*?)</td>", REQUEST.text)) >= 100:
                for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text)[0:100],
                                                     re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text)[0:100],
                                                     re.findall(
                                                         r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"",
                                                         REQUEST.text)[0:100],
                                                     re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)[
                                                     0:100]):
                    print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                        f"{GREEN}|{DEFAULT}", IP, f"{GREEN}|{DEFAULT}", LOCATION, f"{GREEN}|{DEFAULT}", OWNER,
                        f"{GREEN}|{DEFAULT}", TIME))
                print(f" [{GREEN}INFO{DEFAULT}] OUTPUT TOO BIG!")
            else:
                for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text),
                                                     re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text), re.findall(
                            r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"", REQUEST.text),
                                                     re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)):
                    print(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (
                        f"{GREEN}|{DEFAULT}", IP, f"{GREEN}|{DEFAULT}", LOCATION, f"{GREEN}|{DEFAULT}", OWNER,
                        f"{GREEN}|{DEFAULT}", TIME))
            FILE = open("iphistory.txt", "w+")
            FILE.write(f"[INFO] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nTARGET: {DOMAIN}\n\n")
            for IP, LOCATION, OWNER, TIME in zip(re.findall(r"<td>(\d.*?)</td>", REQUEST.text),
                                                 re.findall(r"\d</td><td>(.*?)</td>", REQUEST.text), re.findall(
                        r"\d</td><td>.*?\w+[a-zA-Z]</td><td>(.*?)</td><td align=\"center\"", REQUEST.text),
                                                 re.findall(r">([0-9]\w+-[0-9]\w+-[0-9]\w+)</td", REQUEST.text)):
            	FILE.write(" %-1s %-15s %-1s %-29s %-1s %-40s %-1s %s" % (f"|", IP, f"|", LOCATION, f"|", OWNER, f"|", TIME + "\n"))
            FILE.close()
            print(f" [{GREEN}INFO{DEFAULT}] SAVED: iphistory.txt")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] IPHISTORY [DOMAIN] {GREEN}=>{DEFAULT} IPHISTORY [example.com]")
        return MAIN()


def DNSLOOK(PILIHAN):
    RECORD_LIST = ["A", "A6", "AAAA", "AFSDB", "AVC", "CAA", "CNAME", "DNAME", "DNSKEY", "DS", "HINFO",
                   "ISDN", "KEY", "KX", "LOC", "MB", "MG", "MINFO", "MR", "MX", "NAPTR", "NULL", "NS", "NSAP", "NSEC",
                   "NSEC3", "NSEC3PARAM", "PTR", "PX", "RP", "RRSIG", "RT", "SIG", "SOA", "SRV", "SSHFP"]
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            for RECORD in RECORD_LIST:
                ANSWER = dns.resolver.resolve(DOMAIN, RECORD, raise_on_no_answer=False)
                for RESULT in ANSWER:
                    print(f" {GREEN}|{DEFAULT} {RECORD}: {RESULT}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] DNSLOOK [DOMAIN] {GREEN}=>{DEFAULT} DNSLOOK [example.com]")
        return MAIN()


def SUBDOMAINS(PILIHAN):
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://sonar.omnisint.io/subdomains/{DOMAIN}")
            JSON_REQUEST = json.loads(REQUEST.text)
            DICT_LIST = dict.fromkeys(JSON_REQUEST)
            DEDICT_LIST = list(DICT_LIST)
            if len(DEDICT_LIST) >= 50:
                for LIMIT in DEDICT_LIST[0:50]:
                    print(f" {GREEN}|{DEFAULT} {LIMIT}")
                print(f" [{GREEN}INFO{DEFAULT}] OUTPUT TOO BIG!")
            else:
                for INFO in DEDICT_LIST:
                    print(f" {GREEN}|{DEFAULT} {INFO}")
            FILE = open("subdomains.txt", "w+")
            FILE.write(f"[INFO] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nTARGET: {DOMAIN}\n\n")
            for INFO in DEDICT_LIST:
            	FILE.write(INFO + "\n")
            FILE.close()
            print(f" [{GREEN}INFO{DEFAULT}] SAVED: subdomains.txt")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] SUBDOMAINS [DOMAIN] {GREEN}=>{DEFAULT} SUBDOMAINS [example.com]")
        return MAIN()


def CERTFILE(PILIHAN):
    try:
        PILIHAN_INFO, DOMAIN = PILIHAN.split(" ")
        if DOMAIN == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN.lower()):
            try:
                socket.gethostbyname(DOMAIN)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN):
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] ONLY FOR DOMAIN")
                return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            SLL_CONTEXT = ssl.create_default_context()
            CONTEXT = SLL_CONTEXT.wrap_socket(socket.socket(socket.AF_INET), server_hostname=DOMAIN)
            CONTEXT.connect((DOMAIN, 443))
            INFO = CONTEXT.getpeercert()
            SUBJECT = dict(LIST[0] for LIST in INFO["subject"])
            ISSUER = dict(LIST[0] for LIST in INFO["issuer"])
            print(f" {GREEN}|{DEFAULT} SUBJECT:")
            for SUBJECT_NAME, SUBJECT_INFO in SUBJECT.items():
                print(f" {GREEN}| |{DEFAULT} {SUBJECT_NAME}: {SUBJECT_INFO}")
            print(f" {GREEN}|{DEFAULT} ISSUER:")
            for ISSUER_NAME, ISSUER_INFO in ISSUER.items():
                print(f" {GREEN}| |{DEFAULT} {ISSUER_NAME}: {ISSUER_INFO}")
            print(f" {GREEN}|{DEFAULT} VALIDITY:")
            print(f" {GREEN}| |{DEFAULT} notBefore: " + INFO["notBefore"])
            print(f" {GREEN}| |{DEFAULT} notAfter: " + INFO["notAfter"])
            print(f" {GREEN}|{DEFAULT} SERIAL NUMBER: " + INFO["serialNumber"])
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] CERTFILE: CERTFILE [DOMAIN] {GREEN}=>{DEFAULT} CERTFILE [example.com]")
        return MAIN()


def IPLOOK(PILIHAN):
    try:
        PILIHAN_INFO, IP = PILIHAN.split(" ")
        if IP == "":
            raise ValueError
        elif re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", IP):
            pass
        else:
            print(f" [{RED}ERROR{DEFAULT}] INVALID IP")
            return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            REQUEST = requests.get(f"https://ipapi.co/{IP}/json")
            JSON_REQUEST = json.loads(REQUEST.text)
            for NAME, INFO in JSON_REQUEST.items():
                print(f" {GREEN}|{DEFAULT} {NAME}: {INFO}")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] IPLOOK [IP] {GREEN}=>{DEFAULT} IPLOOK [1.1.1.1]")
        return MAIN()


def RIPLOOK(PILIHAN):
    IP_LIST = []
    RIP_NO = 0
    try:
        PILIHAN_INFO, DOMAIN_IP = PILIHAN.split(" ")
        if DOMAIN_IP == "":
            raise ValueError
        elif re.match(r"^([0-9a-z][-\w]*[0-9a-z]\.)+[a-z0-9\-]{2,15}$", DOMAIN_IP.lower()):
            try:
                DOMAIN_IP = socket.gethostbyname(DOMAIN_IP)
            except Exception as ERROR:
                print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
                return MAIN()
        else:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", DOMAIN_IP):
                pass
            else:
                print(f" [{RED}ERROR{DEFAULT}] INVALID IP")
                return MAIN()
        LIST = [f"https://sonar.omnisint.io/reverse/{DOMAIN_IP}", f"https://reverseip-tools.com/api?q={DOMAIN_IP}"]
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            for URL_LIST in LIST:
                REQUEST = requests.get(URL_LIST)
                if REQUEST.url == f"https://sonar.omnisint.io/reverse/{DOMAIN_IP}":
                    if "no results found" in REQUEST.text or "null" in REQUEST.text:
                        print(f" [{GREEN}INFO{DEFAULT}] sonar.omnisint.io: NOTHING FOUND")
                        RIP_NO += 1
                    else:
                        SONAR_JSON = json.loads(REQUEST.text)
                        for SONAR_INFO in SONAR_JSON:
                            IP_LIST.append(SONAR_INFO)
                if REQUEST.url == f"https://reverseip-tools.com/api?q={DOMAIN_IP}":
                    if "\"result\":[]" in REQUEST.text:
                        print(f" [{GREEN}INFO{DEFAULT}] reverseip-tools.com: NOTHING FOUND")
                        RIP_NO += 1
                    else:
                        REVIP_TOOLS_JSON = json.loads(REQUEST.text)
                        for REVIP_INFO in REVIP_TOOLS_JSON["result"]:
                            IP_LIST.append(REVIP_INFO)
            if RIP_NO == 2:
                print(f" [{GREEN}INFO{DEFAULT}] NOTHING FOUND")
                return MAIN()
            DICT_LIST = dict.fromkeys(IP_LIST)
            DEDICT_LIST = list(DICT_LIST)
            if len(DEDICT_LIST) >= 50:
                for LIMIT in DEDICT_LIST[0:50]:
                    print(f" {GREEN}|{DEFAULT} {LIMIT}")
                print(f" [{GREEN}INFO{DEFAULT}] OUTPUT TOO BIG!")
            else:
                for IP_INFO in DEDICT_LIST:
                    print(f" {GREEN}|{DEFAULT} {IP_INFO}")
            FILE = open("riplook.txt", "w+")
            FILE.write(f"[INFO] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\nTARGET: {DOMAIN_IP}\n\n")
            for IP_INFO in DEDICT_LIST:
            	FILE.write(IP_INFO + "\n")
            FILE.close()
            print(f" [{GREEN}INFO{DEFAULT}] SAVED: riplook.txt")
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] RIPLOOK [DOMAIN, IP] {GREEN}=>{DEFAULT} RIPLOOK [example.com, 1.1.1.1]")
        return MAIN()


def RDNSLOOK(PILIHAN):
    try:
        PILIHAN_INFO, IP = PILIHAN.split(" ")
        if IP == "":
            raise ValueError
        elif re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", IP):
            pass
        else:
            print(f" [{RED}ERROR{DEFAULT}] INVALID IP")
            return MAIN()
        try:
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            print(f" {GREEN}|{DEFAULT} " + str(dns.resolver.resolve(dns.reversename.from_address(IP), "PTR")[0]))
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(f" [{GREEN}INFO{DEFAULT}] RDNSLOOK [IP] {GREEN}=>{DEFAULT} RDNSLOOK [1.1.1.1]")
        return MAIN()


def TCPSCAN(PILIHAN):
    THREAD = threading.Lock()
    PORT_LIST = ["21", "22", "23", "80", "110", "143", "443", "3389"]
    try:
        PILIHAN_INFO, IP, PORT = PILIHAN.split(" ")
        if IP == "" or PORT == "":
            raise ValueError
        try:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", IP):
                if re.match(r"([0-9])", PORT):
                    if int(PORT[0]) != 0 and int(PORT) <= 65550:
                        PORT_LIST = [PORT]
                    else:
                        print(f" [{RED}ERROR{DEFAULT}] INVALID PORT")
                        return MAIN()
                elif PORT.upper() == "COMMON":
                    pass
                else:
                    print(f" [{RED}ERROR{DEFAULT}] INVALID PORT")
                    return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] INVALID IP")
                return MAIN()
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            for PORT_INFO in PORT_LIST:
                TCP_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                PORT_NAME = socket.getservbyport(int(PORT_INFO), "tcp")
                TCP_SOCKET.settimeout(1.1)
                try:
                    TCP_SOCKET.connect((IP, int(PORT_INFO)))
                    TCP_SOCKET.close()
                    with THREAD:
                        print(f" {GREEN}|{DEFAULT} PORT: {PORT_INFO}/{PORT_NAME} OPEN")
                except Exception as ERROR:
                    print(f" {GREEN}|{DEFAULT} PORT: {PORT_INFO}/{PORT_NAME} CLOSE, LOG: {BRED}{ERROR}{DEFAULT}")
        except OSError:
            print(f" [{RED}ERROR{DEFAULT}] USE UDPSCAN FOR UDP PORTS")
            return MAIN()
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(
            f" [{GREEN}INFO{DEFAULT}] TCPSCAN [IP] [PORT {GREEN}=>{DEFAULT} COMMON, OWN] {GREEN}=>{DEFAULT} TCPSCAN [1.1.1.1] [COMMON, 80]")
        return MAIN()


def UDPSCAN(PILIHAN):
    THREAD = threading.Lock()
    PORT_LIST = ["53", "69", "123", "161", "5353"]
    try:
        PILIHAN_INFO, IP, PORT = PILIHAN.split(" ")
        if IP == "" or PORT == "":
            raise ValueError
        try:
            if re.match(r"^((\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])\.){3}(\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])$", IP):
                if re.match(r"([0-9])", PORT):
                    if int(PORT[0]) != 0 and int(PORT) <= 65550:
                        PORT_LIST = [PORT]
                    else:
                        print(f" [{RED}ERROR{DEFAULT}] INVALID PORT")
                        return MAIN()
                elif PORT.upper() == "COMMON":
                    pass
                else:
                    print(f" [{RED}ERROR{DEFAULT}] INVALID PORT")
                    return MAIN()
            else:
                print(f" [{RED}ERROR{DEFAULT}] INVALID IP")
                return MAIN()
            print(f" [{GREEN}INFO{DEFAULT}] START: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            for PORT_INFO in PORT_LIST:
                UDP_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                PORT_NAME = socket.getservbyport(int(PORT_INFO), "udp")
                UDP_SOCKET.settimeout(1.1)
                try:
                    UDP_SOCKET.connect((IP, int(PORT_INFO)))
                    UDP_SOCKET.close()
                    with THREAD:
                        print(f" {GREEN}|{DEFAULT} PORT: {PORT_INFO}/{PORT_NAME} OPEN")
                except Exception as ERROR:
                    print(f" {GREEN}|{DEFAULT} PORT: {PORT_INFO}/{PORT_NAME} CLOSE, LOG: {BRED}{ERROR}{DEFAULT}")
        except OSError:
            print(f" [{RED}ERROR{DEFAULT}] USE TCPSCAN FOR TCP PORTS")
            return MAIN()
        except Exception as ERROR:
            print(f" [{RED}ERROR{DEFAULT}] {ERROR}")
            return MAIN()
    except ValueError:
        print(
            f" [{GREEN}INFO{DEFAULT}] UDPSCAN [IP] [PORT {GREEN}=>{DEFAULT} COMMON, OWN] {GREEN}=>{DEFAULT} UDPSCAN [1.1.1.1] [COMMON, 80]")
        return MAIN()


if __name__ == '__main__':
    LOGO()
    MAIN()
