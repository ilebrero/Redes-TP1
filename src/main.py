from __future__ import division

import sys
import scapy
import operator

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
IS_AT 	= 2
ORIGIN  = 3
DESTINY = 4

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

def printDecimal(f):
	return ("%f" % f).replace('.', ',')

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
			print("%d\t%s" % (n, printDecimal(broadcasts/n)))

def getSourceBroadcastUnicast(packages):
	source = {'unicast': 0, 'broadcast': 0}
	for pkt in packages:
		dst = getDestiny(pkt)
		if(dst == BROADCAST_ADDRESS):
			source['broadcast'] += 1
		else:
			source['unicast'] += 1
	return source

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
	return samplesOcurrences / float(samplesAmount)

def getInformation(samples, symbol):
	symbolProbability = getSymbolProbability(samples, symbol)
	return -1 * log(symbolProbability,2)		

def getEntropy(samples):
	information = 0
	for symbol in samples.keys():
		information += getSymbolProbability(samples, symbol) * getInformation(samples, symbol)
	return information

def getSymbolsInformation(samples):
	symbolsInformation = {}
	for symbol in samples.keys(): #saca la informacion de casa symbolo en la fuente
		symbolsInformation.update( {str(symbol) : getInformation(samples, symbol)} )
	#comparo la informacion con la entropia
	return symbolsInformation

#para tener todos los datos en una sola llamada
#Devulve: *Entropia de la fuente
#		  *Lista: <symbolo, informacion> 
#		  *Lista: <symbolo, frecuencia>
def obtenerDatos(samples):
	#obtengo informacion de los symbolos
	symbolsInformation = getSymbolsInformation(samples)
	#ordeno por valor de informacion
	sortedInformation = sorted(symbolsInformation.items(), key=operator.itemgetter(1))
	#obtengo la entropia
	sourceEntrophy = getEntropy(samples)
	#obtengo las ips y sus cantidades
	ips = obtenerIps(samples)
	return [sourceEntrophy, sortedInformation, samples, ips]

def obtenerDatosaGraficarDesdeArchivo(file, source):
	packages 	 = loadPackage(file)
	arpPackages  = protocolFilter(packages, ARP)
	whoHasData 	 = analizeSourceDestinyWithOp(arpPackages,WHO_HAS)
	isAtData 	 = analizeSourceDestinyWithOp(arpPackages,IS_AT)
	datosParaGraficar = obtenerDatos(whoHasData)
	datosParaGraficar = obtenerDatos(isAtData)
	return datosParaGraficar 

def obtenerIps(samples):
	ips = {}
	for sample in samples.keys():
		if sample[0] in ips:
			ips[sample[0]] = ips[sample[0]] + samples[sample]
		else:
			ips[sample[0]] = samples[sample]
		if sample[1] in ips:
			ips[sample[1]] = ips[sample[1]] + samples[sample]
		else:
			ips[sample[1]] = samples[sample]
	return ips

def obtenerIps(samples, option):
	ips = {}
	for sample in samples.keys():
		if (option == ORIGIN):
			if sample[0] in ips:
				ips[sample[0]] = ips[sample[0]] + samples[sample]
			else:
				ips[sample[0]] = samples[sample]
		if (option == DESTINY):
			if sample[1] in ips:
				ips[sample[1]] = ips[sample[1]] + samples[sample]
			else:
				ips[sample[1]] = samples[sample]
	return ips

def obtenerNodoMaxInfo(samples):
	maxInfo = 0
	result  = 0 
	for sample in samples:
		info = getInformation(samples, sample)
		if (info > maxInfo):
			result  = sample
			maxInfo = info
	return result

def obtenerNodoMinInfo(samples, maxInfo):
	minInfo = maxInfo
	result  = 0
	for sample in samples:
		info = getInformation(samples, sample)
		if (info < minInfo):
			result  = sample
			minInfo = info
	return result

def cantidad(samples):
	total = 0
	for sample in samples.keys():
		total = total + samples[sample]
	return total

def main():
	packages = loadPackage(args.filename)
	cantPacketes = 0
	arpPackages  = protocolFilter(packages, ARP)
	sourceWhoHas = analizeSourceDestinyWithOp(arpPackages,WHO_HAS)
	sourceDestiny = obtenerIps(sourceWhoHas, DESTINY)

	if (not args.sources or 's' in args.sources):
		S = getSourceBroadcastUnicast(packages)
		total = S.get('unicast') + S.get('broadcast')

		print("Cantidad de paquetes -> unicast: %s | broadcast: %s" %( S.get('unicast'), S.get('broadcast') ))
		print("Probabilidad unicast: %s" % printDecimal(S.get('unicast')/total))
		print("Probabilidad broadcast: %s" % printDecimal(S.get('broadcast')/total))
		print("Entropia: %s" % printDecimal(getEntropy(S)))
		print("SymbolsInformation: Unicast: %s, BroadCast: %s " %(printDecimal(getSymbolsInformation(S)['unicast']), printDecimal(getSymbolsInformation(S)['broadcast'])))
		print("Frecuencia Relativa")
		relativeFrequency(packages)

	if (not args.sources or 's1' in args.sources):
		print("Analize (Source,Destiny,WhoHas):")
		
		cantPacketes = cantidad(sourceDestiny)

		#muestro fuente y cantidad de packetes
        print("Cantidad de paquetes ")
        print(str(cantPacketes))

        #Calculo nodos con max y min informacion y muestro
        maxInfoNode = obtenerNodoMaxInfo(sourceDestiny)
        minInfoNode = obtenerNodoMinInfo(sourceDestiny, getInformation(sourceDestiny, maxInfoNode))
        print("el nodo con mas informacion fue: %s | informacion que provee: %s" %( maxInfoNode, getInformation(sourceDestiny, maxInfoNode) ))
        print("el nodo con menos informacion fue: %s | informacion que provee: %s" %( minInfoNode, getInformation(sourceDestiny, minInfoNode) ))

        with open(args.filename + '_whoHas', 'w') as whoHasResults:
            for info in sourceDestiny:
                whoHasResults.write(str(info[0]) + ',' + str(info[1]) + ',' + str(sourceDestiny[info]) + '\n')

		# print("Analize (Source,Destiny,IsAt):")
	 #        sourceIsAt = analizeSourceDestinyWithOp(arpPackages,IS_AT)
		# print(sourceIsAt)

if __name__ == "__main__":
    sys.exit(main())