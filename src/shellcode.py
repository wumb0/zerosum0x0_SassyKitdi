import sys
import tempfile

import subprocess
process = subprocess.Popen(['objdump', '-M', 'intel', '-D', sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = process.communicate()
#print(out)

start = False
data = b""
hexs = b""

for line in out.split(b"\n"):
    if b"<malloc>:" in line:
        break

    if b"<_DllMainCRTStartup>:" in line:
        start = True
        continue

    if not start:
        continue

    try:
        bytestr = line.split(b":\t")[1].split(b"\t")[0].strip().replace(b" ", b"")
        data += bytes.fromhex(bytestr.decode())
        hexs += bytestr
        #print(data)
        #
    except:
        pass



temp = open("/tmp/wutup", "wb")
temp.write(data)
temp.close()
print(temp.name  + " \t\t" + str(len(data)))

count = 1
sys.stdout.write("\"")
for c in hexs.decode():
    if count % 2 == 1:
        sys.stdout.write("\\x")
    sys.stdout.write(c)

    if count % 80 == 0:
        sys.stdout.write("\"\n\"")

    count += 1

sys.stdout.write("\";")

#print(b'\\x'.join(hexs[i:i+2] for i in range(0, len(hexs), 2)).decode())


#process = subprocess.Popen(['objdump', '-b', 'binary' '-m', 'i386:x86-64', '-M', 'intel', '-D', temp.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#out, err = process.communicate()
#print(out)
#print(err)

import time
#time.sleep(2)
import os
##os.system("objdump -b binary -m i386:x86-64 -M intel -D /tmp/wutup")

