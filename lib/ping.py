from scapy.all import *
#imcp request to see if response come or not
def scan(url):
    ip_header = scapy.all.IP(dst=url)
    icmp_header = scapy.all.ICMP()
    pack = ip_header/icmp_header
    res = sr1(pack, timeout = 5)
    if res:
        s="Host is up"
    else:
        s="Host is down"

    print(s)
    return s

#scan('192.168.18.0')
#print(a)