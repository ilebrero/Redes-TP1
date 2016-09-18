from graphviz import Digraph

#los argumentos estan en sys.argv
import sys

# python graficar_grafo.py <archivo ip,ip,#conexiones>

def organize_data(file, connections, ips):

  with open(sys.argv[1]) as info:
    for line in info:
      my_line = line.strip().split(',')
      print('la linea es' )
      print (my_line)
      connections[(my_line[0], my_line[1])] = my_line[2]
      ips.add(my_line[0])
      ips.add(my_line[1])

def rename_ips(ips, ips_renamed):
  i = 0
  for ip in ips:
    ips_renamed[ip] = str(i)
    i+=1

def rename_connections(ips_renamed, connections, connections_renamed):
  for connection in connections:
    connections_renamed[(str(ips_renamed[connection[0]]), str(ips_renamed[connection[1]]))] = connections[connection]
  
def create_graph(ips_renamed, connections_renamed):

  dot = Digraph(comment='unNombre')
  
  for ip in range(0, len(ips_renamed)): #Crea nodos del grafo
    dot.node(str(ip), str(ip), fixedsize='true')
  
  for connection in connections_renamed:
    dot.edge(connection[0], connection[1])
  
  return dot

def print_graph(graph):
  graph.render('prueba', view=True)

######################################

connections = {} #diccionario clave = (ip_origen, ip_destino) significado = cantidad de paquetes
ips = set()
organize_data(sys.argv[1], connections, ips)

ips_renamed = {}
rename_ips(ips, ips_renamed)
connections_renamed = {}
rename_connections(ips_renamed, connections, connections_renamed)

dot = create_graph(ips_renamed, connections_renamed)
print_graph(dot)

