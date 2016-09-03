from __future__ import division
import scapy

from scapy.all import rdpcap
from scapy.all import ARP, Dot11, Ether
import argparse
from math import log

############## Parse de argumentos #####################

parser = argparse.ArgumentParser(description='TP 1 de Redes')
parser.add_argument('--filename', metavar='filename', type=str, help='.pcap File')
parser.add_argument('--sources', metavar='sources', type=str, nargs='+', help='Use only a list of sources ie: s s1')
args = parser.parse_args()


########################################################


# Por ahora no se usan pero esta bueno saber que existen
#from scapy.all import sr1,IP,UDP,DNS,DNSQR,DNSRR,TCP

DEBUG = False
BROADCAST_ADDRESS = 'ff:ff:ff:ff:ff:ff'
WHO_HAS = 1
IS_AT = 2

# Como hay un protocolo raro en la Facu hacemos estas funciones para levantar
# el destino y fuente de los distintos tipos de paquetes
def getDestiny(package):
	if(Ether in package):
		return package.dst
	elif (Dot11 in package):
		return package.addr1

def getSource(package):
	if(Ether in package):
		return package.dst
	elif (Dot11 in package):
		return package.addr3

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
		dst = getDestiny(pkt)
		if(dst == BROADCAST_ADDRESS):
			broadcasts += 1
		n += 1
		if(DEBUG):
			print("n: %d, p(Broadcast)=%f" % (n, broadcasts/n))
		else:
			print("%d\t%f" % (n, broadcasts/n))

# Get seguro para tener default, en python si
# no esta el valor pincha
def _safeGet(dictionary, key, defaul):
	if(key in dictionary):
		return dictionary[key]
	else:
		return defaul

def analizeSourceDestinyWithOp(packages, operation):
	source = {}
	for pkt in packages:
		if(pkt.op == operation):
			symbol = (pkt.psrc, pkt.pdst) # (IP Origen, IP Destino)
			symbolValue = _safeGet(source, symbol, 0)
			source[symbol] = symbolValue + 1
	return source

def getSymbolProbability(samples, symbol):
	samplesOcurrences = samples[symbol]
	samplesAmount = sum(samples.values())
	return samplesOcurrences / samplesAmount

def getInformation(samples, symbol):
	symbolProbability = getSymbolProbability(samples, symbol)
	return -1 * log(symbolProbability,2)

def getEntropy(samples):
	information = 0
	for symbol in samples.keys():
		information += getSymbolProbability(samples, symbol) * getInformation(samples, symbol)
	return information

#packages = loadPackage("./data/facu5.pcap")
packages = loadPackage(args.filename)

arpPackages = protocolFilter(packages, ARP)

if (not args.sources or 's' in args.sources):
	print("Frecuencia Relativa")
	relativeFrequency(arpPackages)

if (not args.sources or 's1' in args.sources):
	print("Analize (Source,Destiny,WhoHas):")
	print(analizeSourceDestinyWithOp(arpPackages,WHO_HAS))
	print("Analize (Source,Destiny,IsAt):")
	print(analizeSourceDestinyWithOp(arpPackages,IS_AT))
