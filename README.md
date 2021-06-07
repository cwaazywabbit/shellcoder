# shellcoder
Generates shellcodes from a given assembly code and formats the output in a way that makes the shellcoder's life easier to eliminate bad-chars, enhance opcodes, etc.

The following is an exemplary output. On the left you have your opcodes next to each mnemonic (in the middle) so you know what they stand for, and on the far right you have your extra comments from the original assembly code.. everything is neatly formatted :)

Use `-c` to suppress empty lines for a compacter overview!

```
> python3 shellcoder.py 
sc = b""
sc += b""                                               
sc += b""                                               #;-------------------------------------------------------------------------------------------;
sc += b""                                               #; Author: Shadi Habbal (@Kerpanic)
sc += b""                                               #; Version: 1.0 (06 June 2021)
sc += b""                                               #;-------------------------------------------------------------------------------------------;
sc += b""                                               #; Characteristics: generates a shellcode based on a given assembly code using Keystone.
sc += b""                                               #; Takes care of an (as of time of writing) unresolved bug in Keystone when using "push word"
sc += b""                                               #; Allows you to write your assembly code in a clean way without having each line inside quotes
sc += b""                                               #; or having to end each line with a semicolon.
sc += b""                                               #; Use Python comments inside your assembly code for comments!
sc += b""                                               #; Use labels!
sc += b""                                               #; Don't worry about branching statements, they're taken care of and double checked at the end!
sc += b""                                               #; You can use CTypes at the end of the code to testrun your code in memory before moving into prod!
sc += b""                                               #;-------------------------------------------------------------------------------------------;
sc += b""                                               # fake_start:
sc += b""                                               #int3                       # bp for windbg, remove when not debugging
sc += b""                                               
sc += b""                                               # find_function:
sc += b"\x60"                                           # pushad                      # EBX has base_address of module to enumerate
sc += b"\x8b\x43\x3c"                                   # mov eax, [ebx+0x3c]         # offset to PE signature
sc += b"\x8b\x7c\x03\x78"                               # mov edi, [ebx+eax+0x78]     # Export Table Directory RVA
sc += b"\x01\xdf"                                       # add edi, ebx                # Export Table Directory VMA
sc += b"\x8b\x4f\x18"                                   # mov ecx, [edi+0x18]         # NumberOfNames
sc += b"\x8b\x47\x20"                                   # mov eax, [edi+0x20]         # AddressOfNames RVA
sc += b"\x01\xd8"                                       # add eax, ebx                # AddressOfNames VMA
sc += b"\x89\x45\xfc"                                   # mov [ebp-4], eax            # save AddressOfNames VMA for later use
...
...
sc += b""                                               
sc += b""                                               # call_exitprocess:
sc += b""                                               # expects uExitCode to store exit code, but we don't care so we use whatever on stack
sc += b"\x68\x7e\xd8\xe2\x73"                           # push 0x73e2d87e             # "ExitProcess" hash
sc += b""                                               # push 0x60e0ceef             # "ExitThread" hash
sc += b"\xff\xd7"                                       # call edi                    # call find_function
sc += b""                                               # 

Shellcode length is 223 bytes
Shellcode = ("\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\....")
```
