#!/usr/bin/env python

from xml.etree import ElementTree
# output.txt is where your data is saved. input.xml is the nmap xml output file created by the scanner.
output = open("output.txt", "w")
tree = ElementTree.parse("input.xml")
root = tree.getroot()

# make quotes around text
quotize = lambda q: '' + q.replace('' , '') + '	'

# change None object to empty string and make quotes around it
prepare = lambda p: quotize(p if p else "")

# find all <host> items
for host in root.findall("host"):
    address = host.find("address").get("addr")
    hostname = host.find("./hostnames/hostname")
    
    if hostname is not None:
        hostname = hostname.get("name")

    ports = []

    # select all open ports
    for port in host.findall(".//state[@state='open'].."):
        service = port.find("service")
        product = None
        version = None

        if service is not None:
            product = service.get("product")
            version = service.get("version")
            service = service.get("name")

        if service == "unknown":
            service = None

        ports.append([port.get("portid"), port.get("protocol"), service, product, version])

    first_line = True

    if not hostname:
        hostname = ""

    for port in ports:
        if not first_line:
            address = ""
            hostname = ""
        else:
            first_line = False

        output.write("".join([
            prepare(address),
            prepare(hostname),
            "".join(map(prepare, port))
        ]))

        output.write("\n")

