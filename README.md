# Redes-TP1

Para ejecutar las herramientas es necesario tener scapy y todas sus dependencias + python

###################################### main.py ######################################

Analisa los datos relevados de la red y devulve infomacion sobre las fuentes modeladas.

** Parametros **
1) "--filename" <- Recibe el directorio relativo el archivo ".pcap" con los datos tomados
2) "--source"   <- Recibe el tipo de fuente modelada, estas pueden ser "s", "s1" o no tener el parametro. En el ultimo caso, se devolvera la informacion de ambas fuentes

###################################### main2.py ######################################

Analisa los datos relevados de la red y devulve infomacion sobre las fuentes modeladas.
A diferencia del anterior, este guarda en los archivos: directory + filename + '_whoHas/_whoHasInformation/_entropy los datos correspondientes

** Parametros **
1) "--filename" <- Recibe el directorio relativo el archivo ".pcap" con los datos tomados
2) "--source"   <- Recibe el tipo de fuente modelada, estas pueden ser "s", "s1" o no tener el parametro. En el ultimo caso, se devolvera la informacion de ambas fuentes


###################################### printGrafos.py ######################################

Crea una imagen con el grafo explayado en el informe sobre las conexiones de las ips de la red dandole mayor tamaño a los mas imporrtantes.

** Parametros **
1) "--filename" <- Recibe el directorio relativo el archivo ".pcap" con los datos tomados

###################################### graficar_grafo.py ######################################

Crea una imagen con el grafo explayado en el informe sobre las conexiones de las ips de la red.
A diferencia del anterior, este elimina nodos redundantes.

** Parametros **
1) "--filename" <- Recibe el directorio relativo el archivo ".pcap" con los datos tomados
