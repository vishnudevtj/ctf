#!/usr/bin/env python
import sys
from pwnlib import *


class Base:
    def __init__(self,path,host='',port=0):
        '''
        Create template for the exploit script for Heap
        based challenges .
        [K]eywords :
           def <name> <entry> : creates new function 
           arg <name> <input> : adds corresponding argument to the function
        '''
        self.path = path
        self.host = host
        self.port = port

        binary = elf.ELF(path)

        self.arch = binary.arch
        self.bits = binary.bits
        self.endian = binary.endian
        print(binary.checksec())

        #env = {'LD_PRELOAD':'/opt/preeny/x86_64-linux-gnu/dealarm.so'}
        # self.io = binary.process(env=env)
        self.io = binary.process()
        self.entries = []
    class Func:

        def __init__(self,name):
            self.name=name
            self.arg=[]
            self.members=[]

        def AddArg(self,arg):
            self.arg.append(arg)

        def AddMember(self,recv,send):
            if recv:
                self.members.append('io.recvuntil("{0}")'.format(recv))
            self.members.append('io.sendline(str({0}))'.format(send))


    def command(self,cmd,recv='',send=''):

        count = recv[:-1][::-1].find('\n') + 1
        recv = recv[-count:]

        if cmd[0] == 'def':
            self.define(cmd[1])
            if len(cmd) > 2:
                self.entries[-1].AddMember(recv,cmd[2])
                self.io.sendline(str(cmd[2]))
            return True
        elif cmd[0] == 'arg':
            self.entries[-1].AddArg(cmd[1])
            self.entries[-1].AddMember(recv,cmd[1])
            self.io.sendline(str(cmd[2]))
            return True
        else:
            inp = '"' + cmd[0] + '"'
            self.entries[-1].AddMember(recv,inp)
            self.io.sendline(str(cmd[0]))
            return False


    def define(self,name):
        self.entries.append(self.Func(name))

    def result(self):
        template = '''
from pwn import *

binary = ELF("{0}")
context.binary = binary

if False:
    io = remote ("{1}",{2})
else:
    # context.log_level = "debug"
    # context.terminal = ['tmux', 'splitw', '-h']
    io = binary.process()
    gdb.attach(io)

'''.format(self.path,self.host,self.port)
        for i in self.entries:
            arg = ','.join(i.arg)
            template +="def {0}({1}):".format(i.name,arg).encode('string-escape') + "\n"
            for j in i.members:
                template += "\t" + j.encode('string-escape') + "\n"

        template += "\n\nio.interactive()"
        return template



def promt():
    print(term.text.red('$')),
    cmd = raw_input()
    cmd = cmd.split(" ")

    if cmd[0] == "help" or cmd[0] == "?":
        print('''

Available Command :
help / ? : Print this help 
def <name> <input> : creates new function
arg <name> <input> : adds corresponding argument to the function

        ''')
    if cmd[0] == 'arg' and len(cmd) < 3:
        return False
    if cmd[0] == 'def' and len(cmd) >=2:
        return cmd
    if len(cmd)<3 and cmd[0] != 'end':
        return False
    return cmd

if __name__ == "__main__":
    HOST = "localhost"
    PORT = 1337

    if len(sys.argv) < 2:
        print("Usage {0} <binary> ".format(sys.argv[0]))
        exit(0)
    elif len(sys.argv) > 3:
        HOST = sys.argv[2]
        PORT = int(sys.argv[3])

    obj = Base(sys.argv[1],HOST,PORT)

    while(1):
        recv = obj.io.recv(2000,timeout=0.5)
        print(term.text.green(recv))
        while(1):
            cmd = promt()
            if not cmd:
                continue
            if cmd[0]=='end':
                break
            if obj.command(cmd,recv):
                break
        if cmd[0]=='end':
            break
    result = obj.result()
    print(result)
    if 'y' in  raw_input("Do you want to Create the exploit script ? ( Y/N ) : ").lower() :
        with open('exploit.py','w+') as f:
            for i in result:
                f.write(i)

        f.close()
        
            


