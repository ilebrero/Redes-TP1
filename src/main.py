from __future__ import division
import scapy

from scapy.all import rdpcap
from scapy.all import ARP
import argparse

############## Parse de argumentos #####################

parser = argparse.ArgumentParser(description='TP 1 de Redes')
parser.add_argument('--filename', metavar='filename', type=str,
                    help='.pcap File')

args = parser.parse_args()


########################################################


# Por ahora no se usan pero esta bueno saber que existen
#from scapy.all import sr1,IP,UDP,DNS,DNSQR,DNSRR,TCP

DEBUG = False
BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'

def protocolFilter(packages, protocol):
	filterd = list()
	for pkt in packages:
		if protocol in pkt:
			filterd.append(pkt)
	return filterd

def loadPackage(filename):
	return rdpcap(filename)

def relativeFrequency(packages):
	n = 0
	broadcasts = 0
	for pkt in packages:
		if(DEBUG):
			print("Destino: %s" %pkt.dst)
		if(pkt.dst == BROADCAST_ADDRESS):
			broadcasts += 1
		n += 1
		print("n: %d, p(Broadcast)=%f" % (n, broadcasts/n))

packages = loadPackage(args.filename)

arpPackages = protocolFilter(packages, ARP)

relativeFrequency(arpPackages)

