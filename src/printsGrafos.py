from main import obtenerIps
from main import obtenerDatosaGraficarDesdeArchivo

from graphviz import Digraph

import argparse

WHO_HAS = 1
IS_AT = 2

parser = argparse.ArgumentParser(description='TP 1 de Redes')
parser.add_argument('--filename', metavar='filename', type=str, help='.pcap File')
args = parser.parse_args()

#Por ahora solo toma los datos {<ip1, ip2> : cantidad}
#Es lo que devuelve analizeSourceDestinyWithOp(--, --)
def createGraph(graphComment, data):
	dot = Digraph(comment=graphComment)
	ips = obtenerIps(data)
	for ip in ips.keys():
		size=str(ips[ip]/10) #ajustar mejor el valor, algunos valores muy chicos quedan afuera
		dot.node(ip, str(ips[ip]), width=size, height=size, fixedsize='true')
	for conexion in data.keys():
		dot.edge(conexion[0], conexion[1])
	return dot

def printGraph(dot):
	dot.render('test-output/round-table.gv', view=True)


#Con esto se puede graficar!

#WHO_HAS viendo las ips de destino
dataWhoDestiny = obtenerDatosaGraficarDesdeArchivo(args.filename, WHO_HAS, DESTINY)

#WHO_HAS viendo las ips de origen
#dataWhoOrigin = obtenerDatosaGraficarDesdeArchivo(args.filename, WHO_HAS)

#armo el grafo de conexiones
dotWhoOrigin  = createGraph("red con Who_has solo destino", dataWhoDestiny[3])

#printeo el grafio
printGraph(dotWhoOrigin)
printGraph(dotIs)