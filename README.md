# webintel
Attempt to identify common CMS and web applications with a single request.

Supports output from Nessus and Nmap. Alternatively, you can supply a single URL or file with a list of URLs.

For example:

    $ python webintel.py --url http://www.wordpress.com
    [*] Starting Web Intel scanner -- by Dan Amodio
    [*] This script attempts to identify common CMS and web applications with a single request.
    [*]
    [!] http://www.wordpress.com : Wordpress


