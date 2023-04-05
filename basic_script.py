import pyshark
import matplotlib.pyplot as plt
import numpy as np

dns_query_types = {
    1: "A",
    2: "NS",
    3: "MD",
    4: "MF",
    5: "CNAME",
    6: "SOA",
    7: "MB",
    8: "MG",
    9: "MR",
    10: "NULL",
    11: "WKS",
    12: "PTR",
    13: "HINFO",
    14: "MINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    36: "KX",
    37: "CERT",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    44: "SSHFP",
    45: "IPSECKEY",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    55: "HIP",
    59: "CDS",
    60: "CDNSKEY",
    61: "OPENPGPKEY",
    62: "CSYNC",
    63: "ZONEMD",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    249: "TKEY",
    250: "TSIG",
    256: "URI",
    257: "CAA",
    32768: "TA",
    32769: "DLV"
}
hash_name_servers = set()

dns_types = set()

file_lst = ["Traces/trace_sans_actions.pcapng","Traces/ouverture_messenger.pcapng", "Traces/envois_msg_colet.pcapng","Traces/appel_réussi.pcapng","Traces/appel_sans_réponse.pcapng","Traces/envoie_fichier.pcapng", "Traces/envoie_de_message_antoine.pcapng", "Traces/appel_audio_uniquement.pcapng", "Traces/appel_vidéo.pcapng"]
autoritative = []
name_servers = []

def analyse_dns(filename):
    capture = pyshark.FileCapture(filename, display_filter="dns")
    all_dns = []
    for packet in capture:
        if packet.dns.flags_response.int_value:
            if hash(packet.dns.qry_name) not in hash_name_servers:
                hash_name_servers.add(hash(packet.dns.qry_name))
                name_servers.append(packet.dns.qry_name)
        if packet.dns.count_auth_rr.int_value > 0:
            autoritative.append(packet.dns.soa_mname)

        all_dns.append(dns_query_types.get(int(packet.dns.qry_type)))

        if dns_query_types.get(int(packet.dns.qry_type)) not in dns_types:
            dns_types.add(dns_query_types.get(int(packet.dns.qry_type)))
    #    if packet.dns.count_add_rr.int_value > 0:
    #s        print(packet.dns.field_names)
    #plt.hist(np.array(all_dns))
    #plt.show()

def analyse_udp(filename):
    capture = pyshark.FileCapture(filename, display_filter="udp")
    x = 0
    for packet in capture:
        #print(packet)
        x+=1
    print(x)
def analyse_tcp(filename):
    capture = pyshark.FileCapture(filename, display_filter="tcp")
    x = 0
    for packet in capture:
        # print(packet)
        x += 1
    print(x)

def analyse_taille_packet(filename):
    capture = pyshark.FileCapture(filename)
    x = 0
    y = 0
    for packet in capture:
        y += 1
        x += int(packet.length)
    return x, y

def quel_adresse(filename):
    adresse = set()
    capture = pyshark.FileCapture(filename)

    for packet in capture:
        if hasattr(packet, 'ipv6'):
            if packet["ipv6"].dst not in adresse:
                adresse.add(packet["ipv6"].dst)
        if hasattr(packet, 'ip'):
            if packet["ip"].dst not in adresse:
                adresse.add(packet["ip"].dst)
    print(len(adresse))
    for ip in adresse:
        print(ip, end=", ")
def run():
    for file in file_lst:
        analyse_dns(file)
    print(len(name_servers))
    print(name_servers)
    for i in autoritative:
        print(i+", ", end="")
    print(dns_types)

if __name__ == '__main__':
    quel_adresse("Traces/envoie_de_message_antoine.pcapng")
    analyse_dns("Traces/envoie_de_message_antoine.pcapng")
    print("okok")
    print(name_servers)
