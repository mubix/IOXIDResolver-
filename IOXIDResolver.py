#!/usr/bin/python

import sys, getopt
import ipaddress

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter
from impacket.dcerpc.v5.rpcrt import DCERPCException


def getIPs(subnetMask):
    ipList = []
    net = ipaddress.ip_network(subnetMask, strict=False)
    
    for ip in net.hosts():
        ipList.append(str(ip))
    
    return ipList

def getAdapterInfo(ipAddress):
    try:
        authLevel = RPC_C_AUTHN_LEVEL_NONE

        stringBinding = r'ncacn_ip_tcp:%s' % ipAddress
        rpctransport = transport.DCERPCTransportFactory(stringBinding)

        portmap = rpctransport.get_dce_rpc()
        portmap.set_auth_level(authLevel)
        portmap.connect()

        objExporter = IObjectExporter(portmap)
        bindings = objExporter.ServerAlive2()

        print ("[*] Retrieving network interface of " + ipAddress)

        #NetworkAddr = bindings[0]['aNetworkAddr']
        for binding in bindings:
            NetworkAddr = binding['aNetworkAddr']
            print("Address: " + NetworkAddr)
    except DCERPCException as e:
        print("[!] Error when attempting to connect to {0}: {1}".format(ipAddress, str(e)))

def main(argv):

    if not argv:
        print('IOXIDResolver.py -t <target>')
        sys.exit(2)

    try:
        opts, args = getopt.getopt(argv,"ht:",["target="])
    except getopt.GetoptError:
        print ('IOXIDResolver.py -t <target>')
        sys.exit(2)

    target_ip = "192.168.1.1"

    for opt, arg in opts:
        if opt == '-h':
            print ('IOXIDResolver.py -t <target>')
            sys.exit()
        elif opt in ("-t", "--target"):
            # target_ip = arg
            # Checking if argument contains subnet mask
            if "/" in arg:
                # Subnet mask specified
                print("Subnet mask specified: {0}".format(arg))
                ipList = getIPs(arg)
                target_ip = ipList
            else:
                print("Single host specified: {0}".format(arg))
                target_ip = arg
    

    if isinstance(target_ip, list):
        for i in target_ip:
            getAdapterInfo(i)
    else:
        getAdapterInfo(target_ip)


    

if __name__ == "__main__":
   main(sys.argv[1:])
