0-spiking to find a vuln variable
  fuzz the executable to cause a crash
  
1-fuzzing.py
estimate the size of data required to crash the executable

2-offset.py
attempt to identify the exact number of bytes required to overwrite the EIP

3-eip.py
prove that we can control the EIP

4-badchars.py
identify any characters that we can't use in the payload

5-jmpesp.py
find a useful set of instructions and attempt to execute them (JMP ESP) with a breakpoint set

6-exploit.py
final working exploit - will generate a reverse shell to attacker's machine
