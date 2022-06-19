from scapy.all import *
from scapy.layers.inet import IP, ICMP

#icmp request to see the ttl values
def det(url):
    os = ''
    pack = IP(dst=url)/ICMP()
    resp = sr1(pack, timeout=3)
    if resp:
        if IP in resp:
            ttl = resp.getlayer(IP).ttl
            if ttl <= 64: 
                os = 'Linux'
            elif ttl > 64:
                os = 'Windows'
            else:
                print('Not Found')
                os='Not Found'
            print(f'\n\nTTL = {ttl} \n*{os}* Operating System is Detected \n\n')
    else:   
        os='No Response Received'
    return os

#a=det('google.com')
#print(a)