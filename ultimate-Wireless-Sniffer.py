from scapy.all import *
from datetime import datetime
import optparse, os

hidden = []
unhidden = []

def tt():
    t = datetime.now()
    h,m,s = t.hour, t.minute, t.second
    h,m,s = str(h), str(m), str(s)
    tt = h+"."+m+"."+s
    return tt
def addf(fname, mac, ch):
    f = open("stashbox","a")
    if ch == None:
        ch = None
        device = "[DE]"
    elif ch != None:
        device = "[AP]"
    content = "%s ESSID: %s    MAC: %s     Channel: %s\n"%(device,fname,mac,ch)
    f.write(content)
    f.close()
def addlog(logs):
    f = open("sniffer.log","a")
    content = logs+"\n"
    f.write(content)
    f.close()
def decloak(p):
    macaddr = p.getlayer(Dot11).addr2
    channel = ord(pkt[Dot11Elt:3].info)
    if addr2 not in hidden:
        log = ("[-] Detected Hidden SSID: "+"_ "+"with MAC: "+addr2+" on Channel: "+channel)
        print log
        addlog(log)
        hidden.append(macaddr)
        addf("hidden",macaddr,channel)
    if p.haslayer(Dot11ProbeResp):
        macaddr = p.getlayer(Dot11).addr2
        if (macaddr in hidden) & (macaddr not in unhidden):
            netname = p.getlayer(Dot11ProbeResp).info
            log = ("[+] Decloaked Hidden SSID: "+netname+" for MAC: "+macaddr)
            print log
            addlog(log)
            unhidden.append(macaddr)
            addf(netname,macaddr,None)
    if p.haslayer(Dot11AssoResp):
        macaddr = p.getlayer(Dot11).addr2
        if (macaddr in hidden) & (macaddr not in unhidden):
            netname = p.getlayer(Dot11AssoResp).info
            log = ("[+] Decloaked Hidden SSID: "+netname+" for MAC: "+macaddr)
            print log
            addlog(log)
            unhidden.append(macaddr)
            addf(netname,macaddr,None)
    if p.haslayer(Dot11ReassoResp):
        macaddr = p.getlayer(Dot11).addr2
        if (macaddr in hidden) & (macaddr not in unhidden):
            netname = p.getlayer(Dot11ReassoResp).info
            log = ("[+] Decloaked Hidden SSID: "+netname+" for MAC: "+macaddr)
            print log
            addlog(log)
            unhidden.append(macaddr)
            addf(netname,macaddr,None)
def beaconframe(pkt):
    ssid = pkt.getlayer(Dot11Beacon).info
    macaddr = pkt.getlayer(Dot11).addr2
    channel = ord(pkt[Dot11Elt:3].info)
    s = tt()
    log = ("%s [+] Detected Beacon Frame: %s     MAC: %s    Channel: %s"%(s,ssid,macaddr,channel))
    print log
    addlog(log)
    if macaddr not in unhidden:
        unhidden.append(macaddr)
        addf(ssid,macaddr,channel)
def preq(pkt):
    name = pkt.getlayer(Dot11ProbeReq).info
    mac2 = pkt.getlayer(Dot11).addr2
    s = tt()
    if len(name) == 0:
        name = "unknown"
    log = ("%s [+] Detected Probe Request: %s    MAC: %s"%(s,name,mac2))
    print log
    addlog(log)
    if mac2 not in unhidden:
        unhidden.append(mac2)
        addf(name,mac2,None)
def presp(pkt):
    ssid = pkt.getlayer(Dot11ProbeResp).info
    mac2 = pkt.getlayer(Dot11).addr2
    mac1 = pkt.getlayer(Dot11).addr1
    s = tt()
    log = ("%s [+] Detected Probe Response: %s   MAC: %s     Client: %s"%(s,ssid,mac2,mac1))
    print log
    addlog(log)
    if mac2 not in unhidden:
        unhidden.append(mac2)
        addf(ssid,mac2,None)
def main(p):
    #discover networks, Beacon Frames
    if p.haslayer(Dot11Beacon) and p.getlayer(Dot11Beacon).info != None:
        beaconframe(p)
    elif p.haslayer(Dot11Beacon) and p.getlayer(Dot11Beacon).info == None:
        decloak(p)
    #probes, Probe Requests and Probe Responses
    elif p.haslayer(Dot11ProbeReq):
        preq(p)
    if p.haslayer(Dot11ProbeResp):
        presp(p)
    
if __name__=="__main__":
    parser = optparse.OptionParser("usage: python2 %proc [option]\
    \n\t-i    <interface>   :Wireless Interface to use")
    
    parser.add_option("-i", dest="interface", type="string", help="Wireless Interface to use")
    (options, args) = parser.parse_args()

    interface = options.interface

    os.system("clear")
    
    print "-"*127+"\n"+" "*50+" Ultimate Wireless Sniffer "+""*50+"\n"+"_"*127,"\n"
    #setting date to add to logs and start of program
    t = datetime.now()
    y,m,d = str(t.year), str(t.month), str(t.day)
    s = tt()
    date = "*"*38+" Date: "+d+"/"+m+"/"+y+"/"+"_"*13+"Start Time: "+s+" "+"*"*38
    print date,"\n"
    addlog(date)
    
    if (options.interface != None):
        conf.iface = options.interface
        sniff(prn=main, store=0)
    elif (options.interface == None):
        interface = raw_input("Interface to use: ")
        conf.iface = interface
        sniff(prn=main)
    else:
        print parser.usage
