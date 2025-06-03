# Python安全专题

![objmodel_1.svg](https://marco-buttu.github.io/pycon_objmodel/pictures/objmodel_1.svg)

```python
os.system("ls")
os.popen("ls").read()

# python 2
commands.getstatusoutput("ls")
commands.getoutput("ls")
commands.getstatus("file/path")

# python 3
subprocess.call("ls", shell=True)
subprocess.Popen("ls", shell=True)

pty.spawn("ls")
pty.spawn("/bin/bash")
platform.os.system("ls")
pdb.os.system("ls")

#Import functions to execute commands
importlib.import_module("os").system("ls")
importlib.__import__("os").system("ls")
imp.load_source("os","/usr/lib/python3.8/os.py").system("ls")
imp.os.system("ls")
imp.sys.modules["os"].system("ls")
sys.modules["os"].system("ls")
__import__("os").system("ls")
import os
from os import *

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')

#In Python2.7
execfile('/usr/lib/python2.7/os.py')
system('ls')

```

## 沙箱逃逸

## Pickle 反序列化
