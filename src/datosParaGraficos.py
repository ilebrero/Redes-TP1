from main import loadPackage
from main import protocolFilter
from main import analizeSourceDestinyWithOp
from main import obtenerDatos
from main import printDecimal

import scapy
from scapy.all import ARP, Dot11, Ether
import argparse
from math import log

############## Parse de argumentos #####################

parser = argparse.ArgumentParser(description='TP 1 de Redes')
parser.add_argument('--filename', metavar='filename', type=str, help='.pcap File')
parser.add_argument('--sources', metavar='sources', type=str, nargs='+', help='Use only a list of sources ie: s s1')
args = parser.parse_args()

########################################################

WHO_HAS = 1
IS_AT = 2

file   = args.filename
source = args.sources[0]

print source
print file

packages 	 = loadPackage(file)
arpPackages  = protocolFilter(packages, ARP)
rawData = 2

if (source == 'WHO_HAS'):
	rawData = analizeSourceDestinyWithOp(arpPackages,WHO_HAS)

if (source == 'IS_AT'):
	rawData = analizeSourceDestinyWithOp(arpPackages,IS_AT)

sourceEntrophy, sortedInformation, samples, ips = obtenerDatos(rawData)

print("entropia: ", sourceEntrophy)
#print("sortedInformation: ", sortedInformation)
print("sortedInformation:")
for e in sortedInformation:
	print("%s\t%s" %(e[0],printDecimal(e[1])))

print("samples: ", samples)
print("ips: ", ips)

