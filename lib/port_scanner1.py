import socket

#scan 20 ports
top_20_ports=[20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
open_ports=[]
close_ports=[]

#scan ports and return open ports
def scanner1(url):
    target_IP = socket.gethostbyname(url)
    for port in top_20_ports: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        socket.setdefaulttimeout(1) 
            
        # returns an error indicator 
        result = s.connect_ex((target_IP,port)) 
        if result ==0: 
            open_ports.append(port)
            print(port)
        else:
            print(port,'closed')
        s.close() 
    if open_ports:
        pass
    else:
        open_ports.append('none')


    return(open_ports)
    
    

#a=scanner1('192.168.1.1')
#print(a)