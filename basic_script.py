import pyshark

autoritative = []
name_servers = []

def analyse_dns(filename, list):
    capture = pyshark.FileCapture(filename, display_filter="dns")
    for packet in capture:
        if not packet.dns.flags_response.int_value:
            if hash(packet.dns.qry_name) not in list:
                list.add(hash(packet.dns.qry_name))
                name_servers.append(packet.dns.qry_name)
        if packet.dns.count_auth_rr.int_value > 0:
            autoritative.append(packet.dns.resp_name)


def run():
    hash_name_servers = set()
    analyse_dns("Traces/trace_sans_actions.pcapng", hash_name_servers)
    analyse_dns("Traces/ouverture_messenger.pcapng", hash_name_servers)
    print(len(name_servers))
    print(name_servers)
    print(autoritative)

if __name__ == '__main__':
    run()