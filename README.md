# psleigh

python bindings for ghidra's sleigh engine.

this library provides high level pythonic bindings for the sleigh engine, with a focus on ease of use and convenience.

instead of working with cumbersome ffi objects, this library provides pythonic dataclass objects that are much easier to work with.

## installation

```bash
pip install psleigh
```

## usage

here is a simple example of how to use this library to lift a single x86_64 instruction:

```python
from psleigh import Sleigh, SleighArch, BufMemReader

# mov rax, 0x1234567890abcdef
code = bytes.fromhex("48 b8 ef cd ab 90 78 56 34 12")

sleigh = Sleigh(SleighArch.x86_64(), BufMemReader(code, 0))

# lift the instruction at address 0
res = sleigh.lift_one(0)

# print the lifted p-code
print(res.fmt_insns(sleigh))
```

this will output the following:

```
COPY RAX, 0x1234567890abcdef:8
```

some instructions translate to multiple p-code operations. for example, a `push rax` instruction on x86_64 will first decrement the stack pointer and then store the value of `rax` at the new stack pointer location:

```python
from psleigh import Sleigh, SleighArch, BufMemReader

# push rax
code = bytes.fromhex("50")

sleigh = Sleigh(SleighArch.x86_64(), BufMemReader(code, 0))
res = sleigh.lift_one(0)

# print the lifted p-code
print(res.fmt_insns(sleigh))
```

this will output the following raw p-code. note that this is a direct, unsimplified representation of the instruction's operations. the exact addresses and unique ids may vary.

```
COPY unique[162944]:8, RAX
INT_SUB RSP, RSP, 0x8:8
STORE 0x1e68f670:8, RSP, unique[162944]:8
```

an example of lifting a mips instruction:

```python
from psleigh import Sleigh, SleighArch, BufMemReader, Opcode

# sw $ra, 0x10($sp)
code = bytes.fromhex("af bf 00 10")

sleigh = Sleigh(SleighArch.mips32be(), BufMemReader(code, 0))
res = sleigh.lift_one(0)

# print the lifted p-code
print(res.fmt_insns(sleigh))
```

this will output the following raw p-code. the exact addresses and unique ids may vary.

```
INT_ADD unique[256]:4, sp, 0x10:4
COPY unique[384]:4, 0x0:4
COPY unique[384]:4, unique[256]:4
STORE 0x20339f70:8, unique[384]:4, ra
```

you can also manually construct all of the pcode related objects, which makes it easier to work with them.
for example, you can construct an `Insn` object and compare it to the results of a lift operation:

```python
from psleigh import Sleigh, SleighArch, BufMemReader, Opcode, Insn, Vn, VnAddr, VnSpace

# li $v0, 1
code = bytes.fromhex("24 02 00 01")

reader = BufMemReader(code, 0)
sleigh = Sleigh(SleighArch.mips32be(), reader)
res = sleigh.lift_one(0)

# manually construct the expected Insn
expected_insn = Insn(
    opcode=Opcode.COPY,
    inputs=[Vn(addr=VnAddr(off=1, space=VnSpace.const()), size=4)],
    output=Vn(addr=VnAddr(off=8, space=VnSpace.register()), size=4),
)

# compare the lifted instruction to the expected one
assert res.insns[0] == expected_insn
```
