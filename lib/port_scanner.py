import socket
import json
import sys
import urllib.request
import requests
from lxml import etree

#scan most common ports
top_20_ports=[20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
open_ports=[]
service=[]
b=[]
p=[]
open("MyFile1.txt", "w")
def scanner(url):
    target_IP = socket.gethostbyname(url)
    for port in top_20_ports: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        socket.setdefaulttimeout(5) 
        
            
        # returns an error indicator 
        result = s.connect_ex((target_IP,port)) 
        s.close()  
        if result ==0:
            open_ports.append(port)
            service.append(socket.getservbyport(port, 'TCP'))
            sev=socket.getservbyport(port, 'TCP')
        
            sock = socket.socket()
            socket.setdefaulttimeout(5)
            #clearing the services in readable format
            try:
                sock.connect((url, port))
                resp = sock.recv(1024)
                b.append((port,sev,resp))
                print(port)
                print(str(resp))
                try:
                    if port==22:
                        s=str(resp)
                        ss=s[10:26].replace("_", " ")
                        i=0
                        search1=''
                        for x in ss:
                            if " " in x:
                                x='+'
                            search1+=x

                        service_number_to_cv(search1)
                    elif port==21:  
                        print(resp)
                        s1=str(resp)
                        ss1=s1[27:36].replace("-", "")
                        print(ss1)
                        i=0
                        search1=''
                        for x in ss:
                            if " " in x:
                                x='+'
                            search1+=x

                        service_number_to_cv(search1)
                except:
                    pass
                    
                
            #if service no is not found get cve through service instead
            except:
                    try:
                        print(port)
                        print(f"[{port}] Connection Failed")
                        b.append((port,sev,'Connection Failed'))
                        service_number_to_cv(sev)
                    except:
                        print("error")
            sock.close()
        
           
        

    return b



#retrive CV details from cve number
def search_cve(_cve):
    """Simple CVE search"""
    print ("Searching: " + _cve)
    SEARCHURL = "http://cve.circl.lu/api/cve/" + _cve
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something has gone horribly wrong.")
    else:
        data = json.loads(r.text)
    return data['summary'],str(data['cvss']),data['Published']

f=[]
#service number or service to cve number
def service_number_to_cv(search1):
    print(search1)
    uf = urllib.request.urlopen('https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='+search1)
    html = uf.read()
    a=html.decode("utf-8")
    
    data = etree.HTML(a)
    anchor = data.xpath('//a/text()')
    i=0
    
    file1 = open("MyFile1.txt", "a")
    
    for x in anchor:
        if 'CVE-' in x and i < 1:
            h,e,g=search_cve(x)
            file1.write('\n====================================================')
            file1.write('\nService/Service No: {0}'.format(search1))
            file1.write('\n====================================================')
            file1.write('\nCVE ID: {0}'.format(x))
            file1.write('\n\nSummary: {0}'.format(h))
            file1.write('\n\nScore: {0}'.format(e))
            file1.write('\n\nPublished Date: {0}\n'.format(g))
            f.append((x,h,e,g))
            print(f)
            print("\n")
            i+=1
    file1.close()
    return f

#a=scanner('10.120.169.17')
#print(a)

