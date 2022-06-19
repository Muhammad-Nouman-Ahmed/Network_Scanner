import logging
from scapy.all import *
from scapy.all import srp, Ether, ARP
import codecs

conf.verb=0 #disables scapy default verbose mode
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #disables 'No route found for IPv6 destination' warning

result=[]
b=[]

#scan the livehosts
def arp_scan(url):

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=url)

    ans, unans = srp(request, timeout=3, retry=1)
    #save ip and mac
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    #serach the mac address from file and print its vendors
    for client in result:
        print(client['IP'])
        print(client['MAC'])
        d = str(client['MAC'])
        c = d.upper()
        with codecs.open("data.txt", "r", "utf-8") as openfile:
            for line in openfile.readlines():
                if str(c[:7]) in line:  
                    b.append((client['IP'],client['MAC'],line[18:]))
                    print("{:16}    {}".format(client['IP'], client['MAC'] ), " " * 9, line[18:]," " * 9, 'UP' )
                    break
            else: 
                b.append((client['IP'],client['MAC'],'UNKNOWN'))
    if b:
        print(b)
    else:
        b.append(('_','_','No host found'))                        
    #return list                        
    return b

#b=arp_scan('10.120.156.1/24')
#print (b)
