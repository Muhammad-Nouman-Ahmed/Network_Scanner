from flask import Flask, render_template, request
from lib.port_scanner import scanner
from lib.spyder import crawler
from lib.livehosts import arp_scan
from lib.osdetections import det
from lib.ping import scan
from lib.port_scanner1 import scanner1


app = Flask(__name__)

#======================================================================
#                          Main page
#======================================================================
@app.route('/')
def home():  
    return render_template('index.html')

#======================================================================
#                         Os Detection
#======================================================================
@app.route('/osdet')
def detect():
    return render_template('a.html')
k=[] 
@app.route('/osdetections-result',methods = ['POST'])
def det_result():
       if request.method == 'POST':
            form_data = request.form
            opt=det(form_data['url'])
            print(opt)
            k.append(("Os: %s" % opt))

            return render_template('a.html',data=k)

#======================================================================
#                        Service, Service Number, CVE
#======================================================================
@app.route('/portscanner')
def port():
    return render_template('ports.html')
i=[]
@app.route('/port-result',methods = ['POST'])
def port_result():
       if request.method == 'POST':
            form_data = request.form
            opt=scanner(form_data['url'])
            for data in opt:
                i.append(("Port Number: %s, Service: %s, Service Version: %s" % data))
                print(b)
            file3 = open("MyFile1.txt", "r")
            dataq=file3.readlines()
            return render_template('ports.html',data=i, data1=dataq)

#======================================================================
#                          Port Scans
#======================================================================
@app.route('/portscanner1')
def ports():
    return render_template('portscan.html')
d=[]
@app.route('/ports-result',methods = ['POST'])
def ports_result():
       if request.method == 'POST':
            form_data = request.form
            opt=scanner1(form_data['url'])
            return render_template('portscan.html',data=opt)

#======================================================================
#                          Live Hosts
#======================================================================
@app.route('/livehosts')
def livehost():
    return render_template('live.html')
b=[]
@app.route('/livehost-result',methods = ['POST'])
def livehost_result():
       if request.method == 'POST':
            form_data = request.form
            opt=arp_scan(form_data['url'])
            print(opt)
            for data in opt:
                b.append(("IP: %s, MAC: %s, Vendor: %s" % data))

            return render_template('live.html',data=b)
#======================================================================
#                          Web Crawler
#======================================================================
@app.route('/spyder')
def spyder():
    return render_template('spyder.html')

@app.route('/spyder-result',methods = ['POST'])
def spyder_result():
       if request.method == 'POST':
            form_data = request.form
            opt=crawler(form_data['url'])
            return render_template('spyder.html',data=opt)

#======================================================================
#                          Ping scan
#======================================================================
@app.route('/ping')
def ping():
    return render_template('ping.html')

@app.route('/ping-result',methods = ['POST'])
def ping_result():
       if request.method == 'POST':
            form_data = request.form
            opt=scan(form_data['url'])
            return render_template('ping.html',data=opt, data1=form_data['url'])


if __name__ == '__main__':
   app.run()