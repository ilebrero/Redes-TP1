from __future__ import division
import scapy
import operator
import os

from scapy.all import rdpcap
from scapy.all import ARP, Dot11, Ether
import argparse
from math import log
from sets import Set

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

#######################################################

def protocolFilter(packages, protocol):
  filterd = list()
  totalPackets = 0
  for pkt in packages:
    totalPackets +=1
    if protocol in pkt:
      filterd.append(pkt)
  return (filterd, totalPackets, len(filterd))

def loadPackage(filename):
	return rdpcap(filename)

def BroadcastUnicastFrequency(packages):
  res = {'broadcast': 0, 'unicast': 0}
  for pkt in packages:
    if(pkt.fields['dst'] == BROADCAST_ADDRESS):
      res['broadcast'] += 1
    else:
      res['unicast'] += 1

  return res

def _safeGet(dictionary, key, defaul):
	if (key in dictionary):
		return dictionary[key]
	else:
		return defaul

def analizeDestinyWithOp(packages, operation):
	source = {}
	for pkt in packages:
		if (pkt.op == operation):
			symbol = pkt.pdst # (IP Destino)
			symbolValue = _safeGet(source, symbol, 0)
			source[symbol] = symbolValue + 1
	return source

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

#######################################################

# Loading packages
print ("Loading Packages")
packages = loadPackage(args.filename)
print ("Done!")
print ("")

# Keeping only the ones with ARP
print ("Filtering Packages")
(arpPackages, amountPackages, amountArpPackages) = protocolFilter(packages, ARP)
print ("Done!")
print ("")
print ("###########################################")

print ("ARP relative frequence in total packages:")
print ("")
print ("#Packages: %d, #ARPPackages= %d, p(ARP)= %f" % (amountPackages, amountArpPackages, amountArpPackages / amountPackages))
print ("")
print ("##########################################")

# Checking if there aren't parameters or if I'm asking for 'S' source
if (not args.sources or 's' in args.sources):
	#print("Broadcast and Unicast Frequency")
  # My symbols are Broadcast or Unicast
  s_source = BroadcastUnicastFrequency(packages)
  broadcasts = s_source['broadcast']
  unicasts = s_source['unicast']
  n = broadcasts + unicasts

  print ("S0 source data:")
  print ("")
  print ("#Packages: %d, p(Broadcast)=%f, p(Unicast)=%f" % (n, broadcasts/n, unicasts/n))
  print ("I(Broadcast)=%f, I(Unicast)=%f" % (-1 * log(broadcasts/n, 2), -1 * log(unicasts/n, 2)))
  print ("Entropy: %f" % getEntropy(s_source))
  print ("")
  print ("")

# Checking if there aren't parameters or if I'm asking for 'S1' source
if (not args.sources or 's1' in args.sources):
  # My symbol is destiny WhoHas: It return (IP_dest, #WHO_HAS)
  destinyWhoHas = analizeDestinyWithOp(arpPackages,WHO_HAS)

  # Getting filename
  filename = args.filename.split('/')[-1:][0].split('.')[0]

  directory = filename + '_data/'
  
  # Creating folder for new files
  if not os.path.exists(directory):
    os.mkdir(directory)

  # Saving to file "filename" this format per line: IP_dest,#WHO_HAS
  with open(directory + filename + '_whoHas', 'w') as whoHasResults:
    for info in destinyWhoHas:
      whoHasResults.write(info + ',' + str(destinyWhoHas[info]) + '\n')

  # Saving to file "filename" this format per line: IP_dest,Information
  with open(directory + filename + '_whoHasInformation', 'w') as whoHasResults:
    for info in destinyWhoHas:
      whoHasResults.write(info + ',' + str(getInformation(destinyWhoHas, info)) + '\n')

  with open(directory + filename + '_entropy', 'w') as whoHasResults:
    whoHasResults.write(str(getEntropy(destinyWhoHas)) + '\n')

  # This is just for making the graphs
  # Getting {(IP_source, IP_dest): WHO_HAS_connections)}
  sourceDestWhoHas = analizeSourceDestinyWithOp(arpPackages,WHO_HAS)
  # Saving to file with "filename" this format per line: IP_source, IP_dest, #WHO_HAS_connections
  with open(directory + filename + '_connections', 'w') as whoHasDestConnections:
    for info in sourceDestWhoHas:
      whoHasDestConnections.write(info[0] + ',' + info[1] + ',' + str(sourceDestWhoHas[info]) + '\n')
