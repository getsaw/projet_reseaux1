import pyshark
def analyse():
    capture = pyshark.FileCapture("Traces/trace_sans_actions.pcapng")
    for packet in capture:
        if "DNS" in packet and not packet.dns.flags_response.int_value:
            print(packet.dns.qry_name)

if __name__ == '__main__':
    analyse()