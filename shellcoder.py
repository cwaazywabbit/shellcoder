import binascii, ctypes, re, struct, sys, traceback
from keystone import *
from capstone import *

CODE = (
    """
    #;-------------------------------------------------------------------------------------------;
    #; Author: Shadi Habbal (@Kerpanic)
    #; Version: 1.0 (06 June 2021)
    #;-------------------------------------------------------------------------------------------;
    #; Characteristics: generates a shellcode based on a given assembly code using Keystone.
    #; Takes care of an (as of time of writing) unresolved bug in Keystone when using "push word"
    #; Allows you to write your assembly code in a clean way without having each line inside quotes
    #; or having to end each line with a semicolon.
    #; Use Python comments inside your assembly code for comments!
    #; Use labels!
    #; Don't worry about branching statements, they're taken care of and double checked at the end!
    #; You can use CTypes at the end of the code to testrun your code in memory before moving into prod!
    #;-------------------------------------------------------------------------------------------;
    fake_start:
      #int3                       # bp for windbg, remove when not debugging

    find_function:
      pushad                      # EBX has base_address of module to enumerate
      mov eax, [ebx+0x3c]         # offset to PE signature
      mov edi, [ebx+eax+0x78]     # Export Table Directory RVA
      add edi, ebx                # Export Table Directory VMA
      mov ecx, [edi+0x18]         # NumberOfNames
      mov eax, [edi+0x20]         # AddressOfNames RVA
      add eax, ebx                # AddressOfNames VMA
      mov [ebp-4], eax            # save AddressOfNames VMA for later use

    # YOUR ASSEMBLY CODE GOES INSIDE THIS MULTILINE STRING

    call_exitprocess:
                                  # expects uExitCode to store exit code, but we don't care so we use whatever on stack
      push 0x73e2d87e             # "ExitProcess" hash
      # push 0x60e0ceef             # "ExitThread" hash
      call edi                    # call find_function
    """
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
cs = Cs(CS_ARCH_X86, CS_MODE_32)

sh = b""
instructions = ""
try:
  complete_encoding, total_count = ks.asm(CODE)
except KsError:
  traceback.print_exc()
  sys.exit("Oops! looks like you entered an invalid or not supported instruction. Try harder!")
for e in complete_encoding:
  sh += struct.pack("B", e)
  instructions += "\\x{0:02x}".format(int(e)).rstrip("\n")
shellcode = bytearray(sh)

lines = list(iter(CODE.splitlines()))
branches_idxes = []
output = []
opcodes = []
own_count = 0
for l in lines:
  try :
    # test for `push word VAL`
    matches_word = re.search("^push word \\b((0x)?[0-9a-fA-F]+)\\b", l.strip(), re.IGNORECASE)
    if matches_word != None:
      if int(matches_word.group(1), 16 if matches_word.group(1).find("0x") == 0 else 10) > 65535:
        sys.exit("`push word` found, but the value is +2 bytes long. Check your sanity.")
      
      # let's first check how Ks assembles it
      encoding, count = ks.asm(l)
      ks_instructions = ""
      for e in encoding:
        ks_instructions += "\\x{0:02x}".format(int(e)).rstrip("\n")

      word = matches_word.group(1)
      word = bytearray.fromhex("{0:04x}".format(int(word, 16 if word.find("0x") == 0 else 10)))
      word.reverse() # little endian

      _instructions = "\\x66\\x68"
      # https://github.com/keystone-engine/keystone/blob/e1547852d9accb9460573eb156fc81645b8e1871/suite/regress/x86_issue10.py
      if int(word[1]) == 0:
        _instructions = "\\x66\\x6a"
        del(word[1]) # remove the null, it will be pushed automatically by the processor and saves us a byte

      own_count += 2 + len(word)

      for e in word:
        _instructions += "\\x{0:02x}".format(int(e)).rstrip("\n")

      instructions = instructions.replace(ks_instructions, _instructions) # replace in Ks output
      shellcode = shellcode.replace(bytearray(ks_instructions, encoding="latin-1"), bytearray(_instructions, encoding="latin-1")) # replace in Ks shellcode
    else:
      encoding, count = ks.asm(l)
      _instructions = ""
      for e in encoding:
        own_count += 1
        _instructions += "\\x{0:02x}".format(int(e)).rstrip("\n")

    output += ["{0:<50}".format("b\"" + _instructions + "\"") + "# %s" % l.strip()]
    opcodes += [_instructions]
  except TypeError:
    # empty line, but probably contains a comment so we print it ONLY if "-c" (collapse) is not present as argument
    if "-c" not in sys.argv:
      output += ["{0:<50}".format("b\"\"") + "%s" % l.strip()]
  except KsError:
    # offsets for calls/jmps to labels will not be calculated correctly when parsed line-per-line
    # so we mark them for manual extraction later
    branches_idxes += [len(output)]
    output += ["# %s" % l.strip()]

found_ops = []
dup_instructions = instructions
for op in opcodes:
  pos = dup_instructions.find(op)
  if pos == 0:
    # our partial shell does not start with a branch
    dup_instructions = dup_instructions[len(op):]
  else:
    # our partial shell starts with a branch
    found_op = dup_instructions[:pos]
    dup_instructions = dup_instructions[len(found_op):]
    dup_instructions = dup_instructions[len(op):]

    # example on how to disassemble: https://github.com/mbikovitsky/AssemblyBot/blob/master/assembly_bot.py
    decoded = "\n".join("%s %s" % (mnemonic, op_str)
                         for address, size, mnemonic, op_str
                         in cs.disasm_lite(binascii.unhexlify(found_op.replace(f"\\x","")), 0))
    decoded = decoded.split("\n")
    if len(decoded) == 1:
      found_ops += [found_op]
      own_count += len(found_op)/4
    else:
      for dec in decoded:
        enc, cnt = ks.asm(dec)
        o = ""
        for e in enc:
          own_count += 1
          o += "\\x{0:02x}".format(int(e)).rstrip("\n")
        found_ops += [o]

for idx, brch_idx in enumerate(branches_idxes):
  output[brch_idx] = "{0:<50}".format("b\"" + found_ops[idx] + "\"") + output[brch_idx]

print("sc = b\"\"")
for o in output:
  print("sc += %s" % o)

print("")
print("Shellcode length is %d bytes" % (len(instructions)/4))
if own_count != len(instructions)/4:
  print("Shellcode lengths do not match. PAY ATTENTION TO BRANCHES (NEAR, SHORT, FAR)\n"
  "Own shellcode length is %d bytes" % own_count)
print("Shellcode = (\"%s\")\n" % instructions)

# execute in memory for testing purposes - YOU NEED TO RUN IT ON WINDOWS

# allocate bytes for our sc on heap, with PAGE_EXECUTE_READWRITE
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
