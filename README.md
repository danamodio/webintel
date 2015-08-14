# webintel
Attempt to identify common CMS and web applications with a single request.

Supports output from Nessus and Nmap. 
You can also supply a single URL or file with a list of URLs.

For example:

    $ python webintel.py --url http://en.wikipedia.org
    [*] Starting Web Intel scanner -- by Dan Amodio
    [*] This script attempts to identify common CMS and web applications with a single request.
    [*]
    [!] http://en.wikipedia.org : Mediawiki

## Installation
I'm using httplib2, so you'll need that:

    $ pip install httplib2

Then it should be good to go!

## Usage

    $ python webintel.py
    usage: webintel.py [-h] [--nmap NMAP] [--nessus NESSUS] [--listfile LISTFILE]
                       [--url URL] [--fqdn] [--debug]

    Shakedown webservices for known CMS and technology stacks.

    optional arguments:
      -h, --help           show this help message and exit
      --nmap NMAP          nmap xml file.
      --nessus NESSUS      .nessus xml file.
      --listfile LISTFILE  straight file list containing fully qualified urls.
      --url URL            profile a url.
      --fqdn               Use the fully qualified domain name from scanner output
                           (DNS). Pretty important if doing this over the internet
                           due to how some shared hosting services route.
      --debug              Print the response data.

### Output types

    $ python webintel.py --url http://en.wikipedia.org --output csv
    http://en.wikipedia.org, Mediawiki

    $ python webintel.py --url http://en.wikipedia.org --output xml
    <item><url>http://en.wikipedia.org</url><match>Mediawiki</match></item>

Note that warning and error messages will still output to terminal as std.err. 
If you redirect output to a file, these messages should not populate into the file.

