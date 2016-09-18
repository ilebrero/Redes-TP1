from graphviz import Digraph

#los argumentos estan en sys.argv
import sys

# python graficar_grafo.py <archivo ip,ip,#conexiones>

def organize_data(file, connections, ips):

  with open(sys.argv[1]) as info:
    for line in info:
      my_line = line.strip().split(',')
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
  
def create_graph(ips, connections):

  dot = Digraph(comment='unNombre')
  
  for ip in ips: #Crea nodos del grafo
    dot.node(ip, ip, fixedsize='true')
  
  for connection in connections:
#if (int(connections[connection]) > 1):
    dot.edge(connection[0], connection[1])
  
  return dot

def appearances_as_dest(ip, connections_renamed, q):
  res = 0
  for connection in connections_renamed:
    if ip == connection[1]:
      res += 1  
  return res >= q

def appearances_as_org(ip, connections_renamed, q):
  res = 0
  for connection in connections_renamed:
    if ip == connection[0]:
      res += 1  
  return res >= q

def add_connection(ip, connections_renamed, final_connections):
  for connection in connections_renamed:
    if (connection[0] == ip or connection[1] == ip):
      if connections_renamed[connection] > 4:
        final_connections[connection] = connections_renamed[connection]

def filter_nodes(ips_renamed, connections_renamed, final_ips, final_connections, q1, q2):
  for ip in ips_renamed:
    aux = appearances_as_org(ips_renamed[ip], connections_renamed, q1) or appearances_as_dest(ips_renamed[ip], connections_renamed, q2)
    if (aux):
      add_connection(ips_renamed[ip], connections_renamed, final_connections)
  for connection in final_connections:
    final_ips.add(connection[0])
    final_ips.add(connection[1])
  print(final_ips)      
  print(final_connections)      

def print_graph(graph):
  graph.render(sys.argv[1] + '_grafo', view=True)

######################################
if (len(sys.argv) == 2):
  connections = {} #diccionario clave = (ip_origen, ip_destino) significado = cantidad de paquetes
  ips = set()
  organize_data(sys.argv[1], connections, ips)
  
  ips_renamed = {}
  rename_ips(ips, ips_renamed)
  connections_renamed = {}
  rename_connections(ips_renamed, connections, connections_renamed)
  final_ips = set() 
  final_connections = {}
  filter_nodes(ips_renamed, connections_renamed, final_ips, final_connections, 2, 2)
  dot = create_graph(final_ips, final_connections)
  print(len(final_ips))
  print_graph(dot)

else:
  sys.exit("falta un argumento")
