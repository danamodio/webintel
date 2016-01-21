#!/usr/bin/python
#
# DanAmodio
#
# Profiles web enabled services 
#

from __future__ import print_function
import sys
import traceback
import argparse
import base64
import xml.etree.ElementTree as ET
import httplib2
import socket
import thread
import threading
import Queue
import time

reload(sys)  
sys.setdefaultencoding('utf8')

# GLOBALS
args = None
#threadLock = threading.Lock()
threads = []
exitFlag = False
qlock = threading.Lock()
qhosts = Queue.Queue()

def warn(*objs):
    print("[*] WARNING: ", *objs, file=sys.stderr)

def error(*objs):
    print("[!] ERROR: ", *objs, file=sys.stderr)

def debug(*objs):
    if args.debug:
        print("[*] DEBUG: ", *objs, file=sys.stderr)

def output(url, signature):
    if args.output == "default":
        print("[!] " + url + " : " + signature)
    elif args.output == "csv":
        print(url + ", " + signature)
    elif args.output == "xml":
        print("<item><url>" + url + "</url><match>" + signature + "</match></item>")

def getHttpLib():
    return httplib2.Http(".cache", disable_ssl_certificate_validation=True, timeout=5)

# Probing class
class Probe (threading.Thread):
    def __init__(self):
        self.url = None 
        self.resp = None
        self.respdata = None
        self.didFind = False
        self.urlFormat = False

    def inBody(self, test):
        return True if self.respdata.find(test)>-1 else False

    def inUrl(self, test):
        return True if self.resp.get('content-location','').find(test)>-1 else False

    def inHeader(self, header,test):
        if self.resp.get(header,'').find(test)>-1:
            return True
        return False

    def found(self, signature):
        self.didFind = True
        output(self.url, signature)

    # https://en.wikipedia.org/wiki/%3F:#Python
    def evalRules(s):
        s.found("Wordpress") if s.inBody("wp-content/") or s.inBody("wp-includes") else 0 
        s.found("Drupal") if s.inBody("drupal.min.js") or s.inBody("Drupal.settings") or s.inBody("http://drupal.org") or s.inBody("/node") else 0 
        s.found("Coldfusion") if s.inBody(".cfm") or s.inBody(".cfc") else 0
        s.found("Accellion SFT") if s.inBody("Secured by Accellion") else 0
        s.found("F5 BIG-IP") if (s.inBody("licensed from F5 Networks") and s.inUrl("my.policy")) or (s.inBody("BIG-IP logout page") and s.inUrl("my.logout.php")) else 0
        s.found("Confluence") if s.inBody("login to Confluence") or s.inBody("Log in to Confluence") or s.inBody("com-atlassian-confluence") else 0
        s.found("Lotus Domino") if s.inBody("homepage.nsf/homePage.gif?OpenImageResource") or (s.inBody("Notes Client") and s.inBody("Lotus")) else 0
        s.found("Citrix ShareFile Storage Server") if s.inBody("ShareFile Storage Server") else 0
        s.found("IIS7 Welcome Page") if s.inBody("welcome.png") and s.inBody("IIS7") else 0
        s.found("IIS8 Welcome Page") if s.inBody("Microsoft Internet Information Services 8.0") and s.inBody("ws8-brand.png") else 0
        s.found("Citrix") if s.inBody("Citrix Systems") and s.inBody("vpn/") else 0
        s.found("Citrix") if s.inBody("/Citrix/SecureGateway") else 0
        s.found("Citrix Web PN") if s.inHeader("server","Citrix Web PN") else 0
        s.found("Outlook Web App") if s.inBody("Outlook Web App") else 0
        s.found("MobileIron") if s.inBody("MobileIron") else 0
        s.found("VMware Horizon") if s.inBody("VMware Horizon") and s.inBody("connect to your desktop and applications") else 0
        s.found("Cisco VPN") if s.inBody("/+CSCOE+/logon.html") or s.inBody("SSL VPN Service") else 0
        s.found("Windows SBS") if s.inBody("Welcome to Windows Small Business Server") else 0
        s.found("Mediawiki") if s.inBody("wiki/Main_Page") or s.inBody("wiki/Special:") or s.inBody("wiki/File:") or s.inBody("poweredby_mediawiki") else 0
        s.found("Thycotic Secret Server") if s.inBody("Thycotic Secret Server") else 0
        s.found("Directory Listing") if s.inBody("Index of") or s.inBody("Parent Directory") else 0
        s.found("Junos Pulse") if s.inBody("dana-na") and s.inBody("Junos Pulse") else 0
        s.found("Default Tomcat Homepage") if s.inBody("this is the default Tomcat home page") else 0
        s.found("Quest Password Manager") if s.inBody("Quest Password Manager") else 0
        s.found("FogBugz") if s.inBody("FogBugz") and s.inBody("fogbugz.stackexchange.com") else 0
        s.found("WebSphere 6.1") if s.inBody("IBM HTTP Server") and s.inBody("infocenter/wasinfo/v6r1") else 0
        s.found("Tomcat / JBOSS") if s.inHeader("server","Apache-Coyote") else 0
        s.found("Default Glassfish Homepage") if s.inBody("GlassFish Server") and s.inBody("Your server is now running") else 0
        s.found("MobileGuard") if s.inBody("MobileGuard Compliance Home Page") else 0
        s.found("SAP Business Objects") if s.inUrl("BOE/BI") and s.inBody("servletBridgeIframe") else 0 # http://www.cvedetails.com/vulnerability-list/vendor_id-797/product_id-20077/SAP-Businessobjects.html
        s.found("Kentico") if s.inBody("CMSPages/GetResource.ashx") else 0
        s.found("vSphere") if s.inBody("client/VMware-viclient.exe") else 0
        s.found("ESXi") if s.inBody('content="VMware ESXi') else 0
        s.found("Juniper Web Device Manager") if s.inBody("Log In - Juniper Web Device Manager") else 0
        s.found("SNARE") if s.inBody("Intersect Alliance") and s.inBody("SNARE for") else 0
        s.found("HP System Management Homepage") if s.inBody("HP System Management Homepage") else 0
        s.found("Symantec Reporting") if s.inBody("log on to Symantec Reporting") else 0
        s.found("Silver Peak Appliance Management") if s.inBody("Silver Peak Systems") else 0
        s.found("EMC Unisphere") if s.inBody('src="engMessage.js"') and s.inBody("oemMessage.js") else 0
        s.found("Cisco Applications") if s.inBody("Installed Applications") and s.inBody("ciscologo.gif") else 0
        s.found("Cisco Prime Data Center Manager") if s.inBody("Cisco Prime") and s.inBody("Data Center Network Manager") else 0
        s.found("Axis Camera") if s.inBody("/view/index.shtml") else 0
        s.found("Apache Default") if s.inBody("This is the default web page for this server.") or s.inBody("Seeing this instead of the website you expected?") else 0
        s.found("Dell Remote Access Controller") if s.inBody("Dell Remote Access Controller") else 0
        s.found("Infoblox") if s.inBody('content="Infoblox WebUI Login Page') else 0
        s.found("Puppet Enterprise Console") if s.inBody("Puppet Enterprise Console") else 0
        s.found("Entrust") if s.inBody('content="Entrust SSM') else 0
        s.found("Under Construction") if s.inBody("does not currently have a default page") and s.inBody("Under Construction") else 0
        s.found("Barracuda Web Filter") if s.inBody("Barracuda Networks") and s.inBody("Web Filter") else 0
        s.found("Tripwire") if s.inBody("console/app.showApp.cmd") and s.inBody("Tripwire") else 0
        s.found("SolarWinds Orion") if s.inBody("SolarWinds Orion") or s.inBody("orionmaster.js.i18n.ashx") else 0
        s.found("Cisco ASDM") if s.inBody("Cisco ASDM") and s.inBody("startup.jnlp") else 0
        s.found("Red Hat Satellite") if s.inBody("Red Hat Satellite") and s.inBody("rhn-base.css") else 0
        s.found("DELL On Board Remote Management") if s.inBody("On Board Remote Management") and s.inBody("status.html") else 0
        s.found("Lansweeper") if s.inBody("Lansweeper") and s.inBody("lansweeper.js.aspx") else 0
        s.found("Raritan Dominion KX II (KVM)") if s.inBody("Raritan") and s.inBody("Dominion KX II") else 0
        s.found("HP iLO") if s.inBody("Hewlett-Packard") and s.inBody("iLO") else 0
        s.found("ArcSight Management Center") if s.inBody("<title>ArcSight Management Center</title>") else 0
        s.found("IIS Windows Server 8.5") if s.inBody("<title>IIS Windows Server</title>") and s.inBody("iis-85.png") else 0
        s.found("PowerEdge R420 iDRAC") if s.inBody("PowerEdge R420") and s.inBody("idrac") else 0
        s.found("Dell PowerVault TL4000 Tape Library") if s.inBody("<title>Dell PowerVault TL4000 Tape Library</title>") and s.inBody("RMULogin") else 0
        s.found("Codian ISDN") if s.inBody("<title>Codian ISDN") else 0
        s.found("BIG-IP Configuration Utility") if s.inBody("BIG-IP") and s.inBody("Configuration Utility") else 0
        s.found("iDRAC 8") if s.inBody("iDRAC8 - Login</title>") else 0
        s.found("Cisco Secure ACS") if s.inBody("<title>Cisco Secure ACS Login</title>") else 0
        s.found("Cisco Integrated Management Controller") if s.inBody("<title>Cisco Integrated Management Controller Login</title>") else 0
        s.found("Snap Server") if s.inUrl("/sadmin/GetLogin.event") else 0
        s.found("Palo Alto GlobalProtect Portal") if s.inBody("GlobalProtect Portal") else 0

    def probe(self,protocol,host,port):
        self.url = protocol+"://"+host+":"+port
        self.probeUrl()

    def probeUrl(self):
        #print "[*] Probing " + url
        # automatically follows 3xx
        # disable SSL validation
        h = getHttpLib()
        try:
            self.resp, self.respdata = h.request(self.url)
            if self.resp.status == 200:
                #print "[!] Got 200. profiling..."
                #profile(url,resp,content)
                #evalRules(url,resp,content)
                if args.debug:
                    print(self.resp)
                    print(self.respdata)
                self.evalRules()
                if self.didFind == False:
                    output(self.url, "No Signature Match")
                else:
                    self.didFind = False
            else:
                error("Got response code " + str(self.resp.status) + " from " + self.url)
        except httplib2.SSLHandshakeError as e:
            error("Could create SSL connection to " + self.url)
        except socket.error as e:
            error("Could not open socket to " + self.url)
        except httplib2.RelativeURIError as e:
            error("Only absolute URIs are allowed (" + self.url + ")") 
        except httplib2.RedirectLimit as e:
            error("Redirected more times than rediection_limit allows (" + self.url + ")")
        except:
            e = sys.exc_info()[0]
            error(str(e) + " (" + self.url + ")")
            if args.debug:
                traceback.print_tb(sys.exc_info()[2])

def parse():
    #loadRules(args)
    if args.output == "default":
        print("[*] Starting Web Intel scanner -- by Dan Amodio")
        print("[*] This script attempts to identify common CMS and web applications with a single request.")
        print("[*]")
    if args.fqdn:
        warn('Using DNS mode. Script will search for user provided hostnames in output.')
        warn('If you did not manually specify hostnames in your scan input, this might fail.')

    if(args.nmap):
        hosts = parseNmap()
        probeHosts(hosts, args.threads)
    elif(args.listfile):
        hosts = parseList()
        probeHosts(hosts, args.threads, True)
    elif(args.url):
        p = Probe()
        p.url = args.url
        p.probeUrl()
    elif(args.nessus):
        hosts = parseNessus()
        probeHosts(hosts, args.threads)

def probeHosts(hosts, numThreads=1, urlFormat=False):
    global qlock, qhosts, threads, exitFlag
    # add to queue
    # spawn workers
    for tid in range(1, numThreads+1):
        #thread = ProbeThread(tid, qhosts, urlFormat)
        debug("Starting Thread-{}".format(tid))
        thread = threading.Thread(target=process_requests, args=(tid, urlFormat,))
        thread.start()
        threads.append(thread)

    qlock.acquire()
    for h in hosts:
        qhosts.put(h)
    qlock.release()

    # wait
    while not qhosts.empty():
        pass

    debug("All hosts completed. Should exit now...")
    exitFlag = True #done

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # TODO -- uniq hosts
    # TODO -- threads
    # TODO probe.probeUrls(hosts)
    # TODO -- spider, dir bust, CVE checks, cache output

# Threading method
def process_requests(threadID, urlFormat):
    while not exitFlag:
        qlock.acquire()
        if not qhosts.empty():
            h = qhosts.get()
            qlock.release()
            debug( "Thread-{} : processing {}".format(threadID, h) )
            p = Probe()
            if urlFormat is True:
                p.url = h
                p.probeUrl()
            else:
                p.probe(h['method'],h['host'],h['port'])
        else:
            debug("Thread-{} : queue empty... exitFlag: {}".format(threadID, exitFlag))
            qlock.release()
        time.sleep(1)


def parseNessus():
    tree = ET.parse( args.nessus)
    root = tree.getroot().find('Report')
    hosts = []
    
    for host in root.findall('ReportHost'):
        fqdn = ""
        ipaddr = ""
        for tag in host.find('HostProperties').findall('tag'):
            if tag.get('name') == 'host-fqdn':
                fqdn = tag.text
            if tag.get('name') == 'host-ip':
                ipaddr = tag.text
        for item in host.findall('ReportItem'):
            if item.get('pluginName') == 'Service Detection':
                if item.get('svc_name') == 'www':
                    port = item.get('port')
                    thehost = None
                    if args.fqdn:
                        #print fqdn, item.get('port')
                        thehost = fqdn
                    else:
                        #print ipaddr, item.get('port')
                        thehost = ipaddr
                    if port == '80':
                        hosts.append({'method':'http', 'host':theHost, 'port':port})
                        #probe("http",thehost,port)
                    elif port == '443':
                        hosts.append({'method':'https', 'host':theHost, 'port':port})
                        #probe("https",thehost,port)
                    else:
                        hosts.append({'method':'http', 'host':theHost, 'port':port}) # WE HOPE!
                        #probe("http",thehost,port) # WE HOPE!
    return hosts

def parseNmap():
    tree = ET.parse( args.nmap )
    root = tree.getroot()
    hosts = []
    
    for host in root.findall('host'):
        addr = None
        if not args.fqdn:
            addr = host.find('address').get('addr')
        elif args.fqdn:
            for hostname in host.find('hostnames').findall('hostname'):
                if hostname.get('type') == 'user':
                    addr = hostname.get('name') 
        if host.find('ports') != None:
            for port in host.find('ports').findall('port'):
                portid = port.get('portid')
                if port.find('state').get('state') == 'open':
                    if port.find('service') != None:
                        if port.find('service').get('name') == 'http':
                            hosts.append({'method':'http', 'host':addr, 'port':portid})
                            #probe("http",addr,portid) 
                        if port.find('service').get('name') == 'https':
                            hosts.append({'method':'https', 'host':addr, 'port':portid})
                            #probe("https",addr,portid) 
    return hosts
        
# TODO --better parsing?
def parseList():
    urls = args.listfile.readlines()
    hosts = []
    for urln in urls:
        url = urln.rstrip()
        hosts.append(url)
        #probeUrl()
    return hosts



# may add some of this functionality back in for deeper probing (dir buster style)
# also used old rules lang
# 
# def profile(url,response,data):
#     bogus = bogusSuccess(url)
#     for rule in rules:
#         found = 0
#         for test in rules[rule]['body']:
#             if data.find(test)>-1:
#                 found = found+1
#         #if not args.nofollowup:
#         # do a quick test before running path rules.
#         if not bogus:
#             for path in rules[rule]['path']:
#                 try:
#                     resp, content = getHttpLib().request(url + path,redirections=0)
#                     if resp.status == 200:
#                         print "[!] FOUND: " + url + path
#                         found = found + 1
#                 except (IOError,httplib2.RedirectLimit) as err:
#                     #print "[!] ERROR:", str(err)
#                     pass
#         if found > 0:
#             print "[!] PROFILE: " +rule+ " (" + str(found) + "/" + str(countRules(rule)) + ")"
# 
# def bogusSuccess(url):
#     try:
#         resp, content = getHttpLib().request(url + "/asdfsa/asf/sdfwe/rr344433/s/egd/xbvvvvv/",redirections=0)
#         if resp.status == 200:
#             # we almost certainly cannot trust this server's response codes
#             print "[!] WARNING: This server is responding with bogus 200 status codes. Skipping some test cases."
#             return True
#     except httplib2.RedirectLimit as e:
#         pass
#     return False

def main(argv):
    filename = ""
    parser = argparse.ArgumentParser(description='Shakedown webservices for known CMS and technology stacks. ')
    parser.add_argument('--nmap', type=file, help='nmap xml file.')
    parser.add_argument('--nessus', type=file, help='.nessus xml file.')
    parser.add_argument('--listfile', type=file, help='straight file list containing fully qualified urls.')
    parser.add_argument('--url', type=str, required=False, help='profile a url.')
    parser.add_argument('--output', default="default", type=str, required=False, help='output type: csv, xml')
    #parser.add_argument('--subnet', type=str, required=False, help='subnet to scan.')
    #parser.add_argument('--ports', type=str, default='80,8080,8081,8000,9000,443,8443', required=False, help='the ports to scan for web services. e.g. 80,8080,443') # just use NMAP
    parser.add_argument('--fqdn', default=False, action="store_true", help='Use the fully qualified domain name from scanner output (DNS). Pretty important if doing this over the internet due to how some shared hosting services route.')
    parser.add_argument('--debug', default=False, action="store_true", help="Print the response data.")
    parser.add_argument('--threads', default=1, type=int, help='Number of concurrent request threads.')
    #parser.add_argument('--rules',default='rules',type=file,required=False,help='the rules file')
    #parser.add_argument('--nofollowup', default=False, action="store_true", help='disable sending followup requests to a host, like /wp-login.php.') # I want to avoid doing this at all with this script.

    if len(argv) == 0:
        parser.print_help()
        sys.exit(0)
    try:
        global args
        args = parser.parse_args() 
        parse( )
    except IOError as err: 
        error(str(type(err)) + " : " + str(err))
        parser.print_help()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
