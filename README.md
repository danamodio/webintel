# webintel
Attempt to identify common CMS and web applications with a single request.

Supports multi threading, and parsing targets from Nessus and Nmap output. 
You can also supply a single URL or file with a list of URLs.

For example:

```
$ python3 webintel.py -iL targets.txt
[200][73610] http://en.wikipedia.org | Mediawiki
[200][73610] http://en.wikipedia.org | Server: mw1327.eqiad.wmnet
[200][73610] http://en.wikipedia.org | X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1
[200][73610] http://en.wikipedia.org | Title: Wikipedia, the free encyclopedia
```

## Installation

``` 
$ pip3 install -r requirements.txt
```

Then it should be good to go!

## Usage

```
$ python3 webintel.py 
usage: webintel.py [-h] [--nmap NMAP] [--nessus NESSUS] [-iL LISTFILE]
                   [-u URL] [-o {default,csv,xml,json}] [-oJ OUTPUTJSON]
                   [--fqdn] [--debug] [-t THREADS] [--uri URI] [--dav]
                   [--cert] [--links]

Shakedown webservices for known CMS and technology stacks - @DanAmodio

optional arguments:
  -h, --help            show this help message and exit
  --nmap NMAP           nmap xml file.
  --nessus NESSUS       .nessus xml file.
  -iL LISTFILE, --listfile LISTFILE
                        straight file list containing fully qualified urls.
  -u URL, --url URL     profile a url.
  -o {default,csv,xml,json}, --output {default,csv,xml,json}
                        output type
  -oJ OUTPUTJSON, --outputjson OUTPUTJSON
                        JSON output file for raw responses and detections
  --fqdn                Use the fully qualified domain name from scanner
                        output (DNS). Pretty important if doing this over the
                        internet due to how some shared hosting services
                        route.
  --debug               Print the response data.
  -t THREADS, --threads THREADS
                        Number of concurrent request threads.
  --uri URI             get status code for a URI across all inputs. e.g.
                        /Trace.axd
  --dav                 finger WebDav with a PROPFIND request.
  --cert                Retrieve information from server certificate.
  --links               Extract links from HTTP response
```

Note that warning and error messages will still output to terminal as std.err. 
If you redirect output to a file, these messages should not populate into the file.

### Extract links

```
$ python3 webintel.py --url http://en.wikipedia.org --links
[200][73610] http://en.wikipedia.org | Mediawiki
[200][73610] http://en.wikipedia.org | Server: mw1327.eqiad.wmnet
[200][73610] http://en.wikipedia.org | X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1
[200][73610] http://en.wikipedia.org | Title: Wikipedia, the free encyclopedia
[200][73610] http://en.wikipedia.org | Link: #mw-head
[200][73610] http://en.wikipedia.org | Link: #p-search
[200][73610] http://en.wikipedia.org | Link: /wiki/Wikipedia
[200][73610] http://en.wikipedia.org | Link: /wiki/Free_content
[200][73610] http://en.wikipedia.org | Link: /wiki/Encyclopedia
[200][73610] http://en.wikipedia.org | Link: /wiki/Wikipedia:Introduction
[200][73610] http://en.wikipedia.org | Link: /wiki/Special:Statistics
[200][73610] http://en.wikipedia.org | Link: /wiki/English_language
[200][73610] http://en.wikipedia.org | Link: /wiki/Portal:Arts
[200][73610] http://en.wikipedia.org | Link: /wiki/Portal:Biography
[200][73610] http://en.wikipedia.org | Link: /wiki/Portal:Geography
***TRUNCATED***
```

### WebDAV 

Send a `PROPFIND` request to the web service. In my experience, this has been more reliable than relying on `OPTIONS` response, which a lot of the scripts seem to do.

```
$ python3 webintel.py --url http://en.wikipedia.org --dav
[405][1823] http://en.wikipedia.org | Server: Varnish
[405][1823] http://en.wikipedia.org | Title: Wikimedia Error
```

### Specific URI

Useful for trying to locate known services like Tomcat with `/manager/html`.

```
$ python3 webintel.py --url http://en.wikipedia.org --uri /manager/html
[404][1248] http://en.wikipedia.org/manager/html | Server: mw1246.eqiad.wmnet
[404][1248] http://en.wikipedia.org/manager/html | X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1
[404][1248] http://en.wikipedia.org/manager/html | Title: Not Found
```

The script does not accept a list of URIs similar to `dirbuster` at the moment, since this tool was meant to sweep for a single thing across a large infrastructure and not create multiple requests to a single host in any given run.

### Certificate Information

Extract SSL certificate details. Useful for identifying domain info from requests to IP addresses. I admit this feature is not pretty right now.

```
$ python3 webintel.py --url https://en.wikipedia.org --cert
[-] https://en.wikipedia.org | [(b'C', b'US'), (b'ST', b'California'), (b'L', b'San Francisco'), (b'O', b'Wikimedia Foundation, Inc.'), (b'CN', b'*.wikipedia.org')] | https://b'*.wikipedia.org':443
```

### JSON output

Terminal JSON output:
```
$ python3 webintel.py --url http://en.wikipedia.org --output json
{"status": 200, "length": 73610, "url": "http://en.wikipedia.org", "data": "Mediawiki"}
{"status": 200, "length": 73610, "url": "http://en.wikipedia.org", "data": "Server: mw1327.eqiad.wmnet"}
{"status": 200, "length": 73610, "url": "http://en.wikipedia.org", "data": "X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1"}
{"status": 200, "length": 73610, "url": "http://en.wikipedia.org", "data": "Title: Wikipedia, the free encyclopedia"}
```

JSON file output. This include raw HTTP response output, which is useful for chopping up with tools like `jq`, and feeding to other scripts / databases.
```
$ python3 webintel.py --url https://en.wikipedia.org -oJ wikipedia.json
```

### XML output

```
$ python3 webintel.py --url https://en.wikipedia.org --output xml
<item><status>200</status><length>73610</length><url>https://en.wikipedia.org</url><data>Mediawiki</data></item>
<item><status>200</status><length>73610</length><url>https://en.wikipedia.org</url><data>Server: mw1327.eqiad.wmnet</data></item>
<item><status>200</status><length>73610</length><url>https://en.wikipedia.org</url><data>X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1</data></item>
<item><status>200</status><length>73610</length><url>https://en.wikipedia.org</url><data>Title: Wikipedia, the free encyclopedia</data></item>
```

### Parse targets from NMAP output

```
$ nmap -n -r -Pn -p443 -oA nmap-wikipedia en.wikipedia.org
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-13 12:12 EST
Nmap scan report for en.wikipedia.org (208.80.154.224)
Host is up (0.0098s latency).

PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

By default, `webintel` will use the IP address found in `Nmap` and `Nessus` output. You must specify `--fqdn` do use the domain name, but this will only with if a domain was specifically provided to `Nmap` or `Nessus`.


```
$ python3 webintel.py --nmap nmap-wikipedia.xml 
[400][1805] https://208.80.154.224:443 | Server: Varnish
[400][1805] https://208.80.154.224:443 | Title: Wikimedia Error
```

```
$ python3 webintel.py --nmap nmap-wikipedia.xml --fqdn
[*][WARNING]:  Using DNS mode. Script will search for user provided hostnames in output.
[*][WARNING]:  If you did not manually specify hostnames in your scan input, this might fail.
[200][73610] https://en.wikipedia.org:443 | Mediawiki
[200][73610] https://en.wikipedia.org:443 | Server: mw1327.eqiad.wmnet
[200][73610] https://en.wikipedia.org:443 | X-Powered-By: PHP/7.2.26-1+0~20191218.33+debian9~1.gbpb5a340+wmf1
[200][73610] https://en.wikipedia.org:443 | Title: Wikipedia, the free encyclopedia
```


