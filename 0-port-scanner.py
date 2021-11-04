#! /usr/bin/python3
import sys
import argparse
import socket

# bash one liner to listen on some ports for testing
#   for j in 200{0..9}; do nc -klnvp $j & done


def main():
  
  if len(sys.argv) != 4:
      print(f'{sys.argv[0]} Scan a range of ports')
      print(f'Usage:  python3 {sys.argv[0]} <target IP> <start of range port> <end of port range>')
      print(f'Example:  python3 {sys.argv[0]} 127.0.0.1 2000 2010')
      sys.exit(1)

  # get IP of target from command line args
  targetIP = sys.argv[1]
  print(f'targetIP {targetIP}')

  # get start of range of ports from command line args
  rangeStart = int(sys.argv[2])
  print(f'rangeStart {rangeStart}')

  # get end of range of ports from command line args
  rangeEnd = int(sys.argv[3])
  print(f'rangeEnd {rangeEnd}')
  print("")
  print(f'Results: port, status')


  targetPorts = range(rangeStart, rangeEnd+1)

  # for each port on the target, try to connect, print the result
  for targetPort in targetPorts:
    result = tryConnect(targetIP,targetPort)
  #  print(f'Target socket:{targetIP}/{targetPort},Result:{result}')
    print(f'{targetPort},{result}')
    
  # next targetPort


def tryConnect(targetIP,targetPort):
    
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  try:
    s.connect((targetIP, targetPort))
  except:
    scanresult = 'closed'
  else:
    scanresult = 'open'
    s.shutdown(1)
  
  s.close()

  return scanresult



if __name__ == '__main__':
  main()

