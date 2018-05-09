# pwnage

Creates a template exploit script for CTF based pwn challenges . Basically many of the pwn challenges are menu driven and we have to write a wrapper function to interact with each menu which the binary provide , offcource we will be using pwntools , process of copying the binary's output create those fuctions are tedious .

Mostly a specific input will trigger the menu entry, so first we will define new menu entry with

    def <function_name> <input>

Further these menu entry will require some input , so to define a argument

    arg <arg_name> inp

After a function defenition all the arg definition will assign argument to that fuction untill another fuction is defined .

And the end command will write the created script to file

    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
    -----------------------------------
                 DeathNote             
    -----------------------------------
     1. Add a name                     
     2. show a name on the note        
     3. delete a name int the note     
     4. Exit                           
    -----------------------------------
    Your choice :
    $ def add 1
    Index :
    $ arg idx 0
    Name :
    $ arg name AAAA
    Done !
    -----------------------------------
                 DeathNote             
    -----------------------------------
     1. Add a name                     
     2. show a name on the note        
     3. delete a name int the note     
     4. Exit                           
    -----------------------------------
    Your choice :
    $ end
    
    from pwn import *
    
    binary = ELF("death_note")
    context.binary = binary
    
    if False:
        io = remote ("localhost",1337)
    else:
        # context.log_level = "debug"
        # context.terminal = ['tmux', 'splitw', '-h']
        io = binary.process()
        gdb.attach(io)
    
    def add(idx,name):
    	io.recvuntil("Your choice :")
    	io.sendline(str(1))
    	io.recvuntil("Index :")
    	io.sendline(str(idx))
    	io.recvuntil("Name :")
    	io.sendline(str(name))
    
    
    io.interactive()
    Do you want to Create the exploit script ? ( Y/N ) : Y
