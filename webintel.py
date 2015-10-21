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

reload(sys)  
sys.setdefaultencoding('utf8')

# did globals for easy rule language. kinda gross, but this is single thread.
args = None
url = None 
resp = None
respdata = None
didFind = False

def warn(*objs):
    print("[*] WARNING: ", *objs, file=sys.stderr)

def error(*objs):
    print("[!] ERROR: ", *objs, file=sys.stderr)

def inBody(test):
    return True if respdata.find(test)>-1 else False

def inUrl(test):
    return True if resp.get('content-location','').find(test)>-1 else False

def inHeader(header,test):
    if resp.get(header,'').find(test)>-1:
        return True
    return False

def output(url, signature):
    if args.output == "default":
        print("[!] " + url + " : " + signature)
    elif args.output == "csv":
        print(url + ", " + signature)
    elif args.output == "xml":
        print("<item><url>" + url + "</url><match>" + signature + "</match></item>")

def found(signature):
    global didFind
    didFind = True
    output(url, signature)

# https://en.wikipedia.org/wiki/%3F:#Python
def evalRules():
    found("Wordpress") if inBody("wp-content/") or inBody("wp-includes") else 0 
    found("Drupal") if inBody("drupal.min.js") or inBody("Drupal.settings") or inBody("http://drupal.org") or inBody("/node") else 0 
    found("Coldfusion") if inBody(".cfm") or inBody(".cfc") else 0
    found("Accellion SFT") if inBody("Secured by Accellion") else 0
    found("F5 BIG-IP") if (inBody("licensed from F5 Networks") and inUrl("my.policy")) or (inBody("BIG-IP logout page") and inUrl("my.logout.php")) else 0
    found("Confluence") if inBody("login to Confluence") or inBody("Log in to Confluence") or inBody("com-atlassian-confluence") else 0
    found("Lotus Domino") if inBody("homepage.nsf/homePage.gif?OpenImageResource") or (inBody("Notes Client") and inBody("Lotus")) else 0
    found("Citrix ShareFile Storage Server") if inBody("ShareFile Storage Server") else 0
    found("IIS7 Welcome Page") if inBody("welcome.png") and inBody("IIS7") else 0
    found("IIS8 Welcome Page") if inBody("Microsoft Internet Information Services 8.0") and inBody("ws8-brand.png") else 0
    found("Citrix") if inBody("Citrix Systems") and inBody("vpn/") else 0
    found("Citrix") if inBody("/Citrix/SecureGateway") else 0
    found("Outlook Web App") if inBody("Outlook Web App") else 0
    found("MobileIron") if inBody("MobileIron") else 0
    found("VMware Horizon") if inBody("VMware Horizon") and inBody("connect to your desktop and applications") else 0
    found("Cisco VPN") if inBody("/+CSCOE+/logon.html") or inBody("SSL VPN Service") else 0
    found("Windows SBS") if inBody("Welcome to Windows Small Business Server") else 0
    found("Mediawiki") if inBody("wiki/Main_Page") or inBody("wiki/Special:") or inBody("wiki/File:") or inBody("poweredby_mediawiki") else 0
    found("Thycotic Secret Server") if inBody("Thycotic Secret Server") else 0
    found("Directory Listing") if inBody("Index of") or inBody("Parent Directory") else 0
    found("Junos Pulse") if inBody("dana-na") and inBody("Junos Pulse") else 0
    found("Default Tomcat Homepage") if inBody("this is the default Tomcat home page") else 0
    found("Quest Password Manager") if inBody("Quest Password Manager") else 0
    found("FogBugz") if inBody("FogBugz") and inBody("fogbugz.stackexchange.com") else 0
    found("WebSphere 6.1") if inBody("IBM HTTP Server") and inBody("infocenter/wasinfo/v6r1") else 0
    found("Tomcat") if inHeader("server","Apache-Coyote") else 0
    found("Glassfish") if inBody("GlassFish Server") and inBody("Your server is now running") else 0
    found("MobileGuard") if inBody("MobileGuard Compliance Home Page") else 0
    found("SAP Business Objects") if inUrl("BOE/BI") and inBody("servletBridgeIframe") else 0 # http://www.cvedetails.com/vulnerability-list/vendor_id-797/product_id-20077/SAP-Businessobjects.html
    found("Kentico") if inBody("CMSPages/GetResource.ashx") else 0
    found("vSphere") if inBody("client/VMware-viclient.exe") else 0
    found("ESXi") if inBody('content="VMware ESXi is virtual infrastructure') else 0
    found("Juniper Web Device Manager") if inBody("Log In - Juniper Web Device Manager") else 0
    found("SNARE") if inBody("Intersect Alliance") and inBody("SNARE for") else 0
    found("HP System Management Homepage") if inBody("HP System Management Homepage") else 0

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
        parseNmap()
    elif(args.listfile):
        parseList()
    elif(args.url):
        global url
        url = args.url
        probeUrl()
    elif(args.nessus):
        parseNessus()

# TODO - Seem to get dups from this nessus parsing. Need to uniq the results.
def parseNessus():
    tree = ET.parse( args.nessus)
    root = tree.getroot().find('Report')
    
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
                        probe("http",thehost,port)
                    elif port == '443':
                        probe("https",thehost,port)
                    else:
                        probe("http",thehost,port) # WE HOPE!

def parseNmap():
    tree = ET.parse( args.nmap )
    root = tree.getroot()
    
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
                            probe("http",addr,portid) 
                        if port.find('service').get('name') == 'https':
                            probe("https",addr,portid) 
        
def parseList():
    global url
    urls = args.listfile.readlines()
    for urln in urls:
        url = urln.rstrip()
        probeUrl()

def getHttpLib():
    return httplib2.Http(".cache", disable_ssl_certificate_validation=True, timeout=5)

def probe(protocol,host,port):
    global url
    url = protocol+"://"+host+":"+port
    probeUrl()

def probeUrl():
    global url, resp, respdata, didFind
    #print "[*] Probing " + url
    # automatically follows 3xx
    # disable SSL validation
    h = getHttpLib()
    try:
        resp, respdata = h.request(url)
        if resp.status == 200:
            #print "[!] Got 200. profiling..."
            #profile(url,resp,content)
            #evalRules(url,resp,content)
            if args.debug:
                print(resp)
                print(respdata)
            evalRules()
            if didFind == False:
                output(url, "No Signature Match")
            else:
                didFind = False
        else:
            error("Got response code " + str(resp.status) + " from " + url)
    except httplib2.SSLHandshakeError as e:
        error("Could create SSL connection to " + url)
    except socket.error as e:
        error("Could not open socket to " + url)
    except httplib2.RelativeURIError as e:
        error("Only absolute URIs are allowed (" + url + ")") 
    except httplib2.RedirectLimit as e:
        error("Redirected more times than rediection_limit allows (" + url + ")")
    except:
        e = sys.exc_info()[0]
        error(str(e) + " (" + url + ")")
        if args.debug:
            traceback.print_tb(sys.exc_info()[2])

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
