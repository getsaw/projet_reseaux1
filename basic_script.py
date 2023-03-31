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

autoritative = []
name_servers = []

def analyse_dns(filename):
    capture = pyshark.FileCapture(filename, display_filter="dns")
    all_dns = []
    for packet in capture:
        if not packet.dns.flags_response.int_value:
            if hash(packet.dns.qry_name) not in hash_name_servers:
                hash_name_servers.add(hash(packet.dns.qry_name))
                name_servers.append(packet.dns.qry_name)
        if packet.dns.count_auth_rr.int_value > 0:
            autoritative.append(packet.dns.resp_name)
        all_dns.append(dns_query_types.get(int(packet.dns.qry_type)))

        if dns_query_types.get(int(packet.dns.qry_type.int_value)) not in dns_types:
            dns_types.add(dns_query_types.get(int(packet.dns.qry_type)))
    plt.hist(np.array(all_dns))
    plt.show()

def run():
    analyse_dns("Traces/trace_sans_actions.pcapng")
    analyse_dns("Traces/ouverture_messenger.pcapng")
    analyse_dns("Traces/envois_msg_colet.pcapng")
    print(len(name_servers))
    print(name_servers)
    print(autoritative)
    print(dns_types)

if __name__ == '__main__':
    run()