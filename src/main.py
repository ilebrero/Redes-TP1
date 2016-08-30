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
WHO_HAS = 1
IS_AT = 2

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

# Get seguro para tener default
def _getSafe(dictionary, key, defaul):
	if(key in dictionary):
		return dictionary[key]
	else:
		return defaul

def analizeSourceAndWhoHas(packages):
	nodes = {}
	for pkt in packages:
		if(pkt.op == WHO_HAS):
			ip = pkt.psrc # IP Origen
			nodeValue = _getSafe(nodes, ip, 0)
			nodes[ip] = nodeValue + 1
	return nodes

def analizeDestinyAndIsAt(packages):
	nodes = {}
	for pkt in packages:
		if(pkt.op == IS_AT):
			ip = pkt.pdst # IP Destino
			nodeValue = _getSafe(nodes, ip, 0)
			nodes[ip] = nodeValue + 1
	return nodes
 

#packages = loadPackage("./data/prueba.pcap")
packages = loadPackage(args.filename)

arpPackages = protocolFilter(packages, ARP)

print("Frecuencia Relativa")
relativeFrequency(arpPackages)


print("AnalizeSourceAndWhoHas:")
print(analizeSourceAndWhoHas(arpPackages))
print("AnalizeDestinyAndIsAt:")
print(analizeDestinyAndIsAt(arpPackages))

