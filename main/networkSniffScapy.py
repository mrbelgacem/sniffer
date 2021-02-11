
import scapy
from scapy import all
from scapy.utils import hexdump
import pygeoip
from IPy import IP as IPLIB
import socket
from datetime import datetime
import sys
from pathlib import Path
import logging


def createInitLogger(logLvl=logging.INFO, consol=False):
    # log level : DEBUG, INFO, WARNING, ERROR  
    if consol:
        # system consol out
        logging.basicConfig(stream=sys.stdout, 
                            format='%(asctime)s : %(levelname)s : %(message)s', 
                            datefmt='%Y/%m/%d %H:%M:%S', 
                            encoding='utf-8', 
                            level=logLvl)
        logging.info('logger ON - system consol out')
    else: 
        # log file out
        # create log directory if not exist
        Path(pathLogDir).mkdir(parents=True, exist_ok=True)    
        
        logging.basicConfig(filename=pathLogFile, 
                            format='%(asctime)s : %(levelname)s : %(message)s', 
                            datefmt='%Y/%m/%d %H:%M:%S', 
                            encoding='utf-8', 
                            level=logLvl)##stream=sys.stdout
        print('logger ON - file out : ' + pathLogFile )

def getInfoGeoIP(ipAddress):
    
    try:
        # try to resolve the IP address
        hostName = socket.gethostbyaddr(ipAddress)[0]
    except:
        # could not resolve the address
        hostName= ""         
    
    # convert the IP to a valid IP object
    ip =IPLIB(ipAddress)
    # do not proceed if the IP is private
    if(ip.iptype()=='PRIVATE'):
        return 'private IP, Host Name: ' + hostName 
        
    try:
        # initialize the GEOIP object
        geoip = pygeoip.GeoIP('GeoIP.dat', flags=pygeoip.const.STANDARD)
        # get the record info
        ipRecord = geoip.record_by_addr(ipAddress)
        # extract the country name
        country = ipRecord['country_name']
        #return the string results
        return 'Country: %s, Host: %s'% (country,hostName)
    except Exception:
        return "Can't  locate " + ipAddress + " Host:" + hostName

def printPacket(sourceIP,destinationIP):
    # assemble the message need to print/save
    return 'Source (%s): %s ---> Destination (%s): %s '% (sourceIP,getInfoGeoIP(sourceIP),destinationIP,getInfoGeoIP(destinationIP))
  

def startMonitoring(pkt):
    listPacket = pkt.layers()

    no_switch = False
    
    IPLayer = scapy.layers.inet.IP
    RawLayer = scapy.packet.Raw
    #print(type(IPName))

    try:      
        if pkt.haslayer(IPLayer):
            # get the source IP address
            sourceIP = pkt.getlayer(IPLayer).src
            # get the destination IP address
            destinationIP = pkt.getlayer(IPLayer).dst
                      
            if(destinationIP in exclude_ips):
                return;
            
            # generate a unique key to avoid duplication
            uniqueKey = sourceIP+'#'+destinationIP
            
            # already processed the packet --> don't proceed further
            if uniqueKey not in conversations:
                # store a new key in the dict to avoid duplication
                conversations[uniqueKey] = 1
                # call the print packet function
                logging.info('\r\n'+'=====Oo++oO=====Oo++oO=====')
                logging.info(printPacket(sourceIP, destinationIP))

                # test if packet contains RAW layer
                if pkt.haslayer(RawLayer):
                    #logging.debug(pkt.show())
                    logging.debug('Raw layer decode data to human readable')
                    logging.debug(hexdump(pkt.getlayer(RawLayer).load))
                #for subPkt in listPacket:
                    #logging.debug(subPkt)
            else:
                conversations[uniqueKey] = +1
        
    except Exception as ex:
        logging.error("Exception : " + str(ex))
        pass

def main():
    # log level / sys consol output (true)
    createInitLogger(logging.DEBUG, True)    
    # start sniffing by filtering only the IP packets without storing anything inside the memory.
    all.sniff(prn=startMonitoring,store=0,filter="ip")
    

if __name__ == '__main__':
    # packet processed
    conversations={}
    # Exclude local loop, .... etc '10.0.2.133'
    exclude_ips= ['127.0.0.1']
    # log properties
    dateTime = datetime.today().strftime('%Y%m%d %H:%M:%S')
    pathLogDir = './log/network_monitor_log/'
    pathLogFile = pathLogDir+dateTime + '.log'
    
    main()
    

##[+] Sub Packet (<class 'scapy.layers.l2.Ether'>)
##[+] Sub Packet (<class 'scapy.layers.inet.IP'>)
##[+] Sub Packet (<class 'scapy.layers.inet.UDP'>)
##[+] Sub Packet (<class 'scapy.layers.dns.DNS'>)
    
##[+] Sub Packet (<class 'scapy.layers.l2.Ether'>)
##[+] Sub Packet (<class 'scapy.layers.inet.IP'>)
##[+] Sub Packet (<class 'scapy.layers.inet.TCP'>)
##[+] Sub Packet (<class 'scapy.packet.Raw'>)
    
##[+] Sub Packet (<class 'scapy.layers.l2.Ether'>)
##[+] Sub Packet (<class 'scapy.layers.inet.IP'>)
##[+] Sub Packet (<class 'scapy.layers.inet.TCP'>)
    
##[+] Sub Packet (<class 'scapy.layers.l2.Ether'>)
##[+] Sub Packet (<class 'scapy.layers.inet.IP'>)
##[+] Sub Packet (<class 'scapy.layers.inet.UDP'>)
##[+] Sub Packet (<class 'scapy.layers.ntp.NTPHeader'>)

