from scapy.all import *
from datetime import datetime
import optparse, os

hidden = []
unhidden = []

#Showing time
def tt():
    t = datetime.now()
    h,m,s = t.hour, t.minute, t.second
    h,m,s = str(h), str(m), str(s)
    tt = h+"."+m+"."+s
    return tt
#File for captured devices info
def addf(fname, mac, ch):
    if ch == None:
        ch = None
        device = "[UsersDevice]"
    elif ch != None:
        device = "[AccessPoint]"
    content = "%s MAC: %s   Channel: %s     ESSID: %s\n"%(device,mac,ch,fname)
    f = open("stashbox","r")
    if content in f:
        pass
    elif content not in f:
        fl = open("stashbox","a")
        fl.write(content)
        fl.close()
    f.close()
#File for logs
def addlog(logs):
    content = logs+"\n"
    f = open("sniffer.log","a")
    f.close()
    f = open("sniffer.log","r")
    if content in f:
        pass
    elif content not in f:
        fl = open("sniffer.log","a")
        fl.write(content)
        fl.close()
    f.close()
#Decloaking hidden networks
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
#Beacon Frames
def beaconframe(pkt):
    ssid = pkt.getlayer(Dot11Beacon).info
    macaddr = pkt.getlayer(Dot11).addr2
    channel = ord(pkt[Dot11Elt:3].info)
    s = tt()
    log = ("%s [+] Detected Beacon Frame:   from MAC: %s  on Channel: %s\tAs ESSID: %s"%(s,macaddr,channel,ssid))
    print log
    addlog(log)
    if macaddr not in unhidden:
        unhidden.append(macaddr)
        addf(ssid,macaddr,channel)
#Probe Requests
def preq(pkt):
    name = pkt.getlayer(Dot11ProbeReq).info
    mac2 = pkt.getlayer(Dot11).addr2
    s = tt()
    if len(name) == 0:
        name = "unknown"
    log = ("%s [+] Detected Probe Request:  from MAC: %s\t\t\tTo ESSID: %s"%(s,mac2,name))
    print log
    addlog(log)
    if mac2 not in unhidden:
        unhidden.append(mac2)
        addf(name,mac2,None)
#Probe Responses
def presp(pkt):
    ssid = pkt.getlayer(Dot11ProbeResp).info
    mac2 = pkt.getlayer(Dot11).addr2
    mac1 = pkt.getlayer(Dot11).addr1
    s = tt()
    log = ("%s [+] Detected Probe Response: from MAC: %s\t\t\tTo Client MAC: %s\tAs ESSID: %s"%(s,mac2,mac1,ssid))
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
    elif p.haslayer(Dot11ProbeResp):
        presp(p)
    #Others to work on
    elif p.haslayer(Dot11AssoReq):
        print("[+] Detected Association request")
    elif p.haslayer(Dot11AssoResp):
        print("[+] Detected Association Response")
    elif p.haslayer(Dot11Disas):
        print("[+] Detected Disassociation")
    elif p.haslayer(Dot11Auth):
        print("[+] Detected Authentication")
    elif p.haslayer(Dot11Deauth):
        print("[+] Detected Deauthentication")
    elif p.haslayer(Dot11ProbeReq):
        print("[+] Detected Probe request")
    elif p.haslayer(Dot11ProbeResp):
        print("[+] Detected Probe Response")
    elif p.haslayer(Dot11Elt):
        print("[+] Detected 802.11 Rates INformation ELement")
    elif p.haslayer(Dot11QoS):
        print("[+] Detected QoS")
    elif p.haslayer(Dot11ReassoReq):
        print("[+] Detected Reassociation Request")
    elif p.haslayer("[+] Detected ReassoResp"):
        print("[+] Detected Reassociation Response")
    elif p.haslayer(Dot11WEP):
        print("[+] Detcted WEP packet")
    elif p.haslayer(TCP):
        print("[+] Detected a TCP Packet")
    elif p.haslayer(DNS):
        print("[+] Detected a DNS Packet")
    
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
    #print "\n Time\t\tDetection Type\t\tAP ESSID\t\tClient MAC\t\t\tAP MAC"
    if (options.interface != None):
        conf.iface = options.interface
        sniff(prn=main, store=0)
    elif (options.interface == None):
        interface = raw_input("\nInterface to use: ")
        print "\n"
        conf.iface = interface
        sniff(prn=main)
    else:
        print parser.usage
