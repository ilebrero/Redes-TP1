from graphviz import Digraph

#Por ahora solo toma los datos {<ip1, ip2> : cantidad}
#Es lo que devuelve analizeSourceDestinyWithOp(--, --)
def createGraph(data):
	dot = Digraph()
	for pack in packages.keys():
		dot.node(pack[0], str(packages[pack]))
		dot.node(pack[1], str(packages[pack]))
		dot.edge(pack[0], pack[1])
	return dot

def printGraph(dot):
	dot.render('test-output/round-table.gv', view=True)