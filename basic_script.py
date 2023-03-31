import pyshark

autoritative = []

def analyse(filename, list):
    capture = pyshark.FileCapture(filename, display_filter="dns")
    for packet in capture:
        if not packet.dns.flags_response.int_value:
            if hash(packet.dns.qry_name) not in list:
                list.add(hash(packet.dns.qry_name))
                print(packet.dns.qry_name)
        if packet.dns.count_auth_rr.int_value > 0:
            autoritative.append(packet.dns.soa_rname)


def run():
    name_servers = set()
    analyse("Traces/trace_sans_actions.pcapng", name_servers)
    analyse("Traces/ouverture_messenger.pcapng", name_servers)
    print(len(name_servers))
    print(autoritative)

if __name__ == '__main__':
    run()