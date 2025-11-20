from __future__ import annotations
from .pysleigh_bindings import (
    BindingsSleigh,
    BindingsSimpleLoadImage,
    BindingsLiftRes,
    BindingsInsn,
    BindingsVarnodeData,
    BindingsAddrSpace,
)
from pathlib import Path
from abc import ABC, ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Self
from enum import IntEnum

PROCESSORS_DIR = Path(__file__).parent.joinpath("processors")


class MemReaderMeta(type(BindingsSimpleLoadImage), ABCMeta):
    pass


class MemReader(ABC, BindingsSimpleLoadImage, metaclass=MemReaderMeta):
    @abstractmethod
    def read(self, addr: int, amount: int) -> bytes:
        pass

    def loadSimple(self, addr: int, amount: int) -> bytes:
        return self.read(addr, amount)


class MyLoadImage(MemReader):
    def read(self, addr: int, amount: int) -> bytes:
        return b"\x00" * amount


SLA_RELATIVE_PATH_X86_64 = "x86/data/languages/x86-64.sla"


@dataclass
class VnSpace:
    shortcut: str

    # the register space.
    @classmethod
    def register(cls) -> Self:
        return cls("%")

    # the const space.
    @classmethod
    def const(cls) -> Self:
        return cls("#")

    # the ram space.
    @classmethod
    def ram(cls) -> Self:
        return cls("r")

    # the unique space.
    @classmethod
    def unique(cls) -> Self:
        return cls("u")

    @classmethod
    def from_bindings(cls, bindings_addr_space: BindingsAddrSpace) -> Self:
        return cls(bindings_addr_space.getShortcut())


@dataclass
class VnAddr:
    off: int
    space: VnSpace


@dataclass
class Vn:
    addr: VnAddr
    size: int

    @classmethod
    def from_bindings(cls, bindings_vn: BindingsVarnodeData) -> Self:
        addr = VnAddr(
            bindings_vn.getOffset(), VnSpace.from_bindings(bindings_vn.getSpace())
        )
        return cls(addr, bindings_vn.getSize())


class Opcode(IntEnum):
    # Copy one operand to another
    COPY = 1
    # Load from a pointer into a specified address space
    LOAD = 2
    # Store at a pointer into a specified address space
    STORE = 3
    # Always branch
    BRANCH = 4
    # Conditional branch
    CBRANCH = 5
    # Indirect branch (jumptable)
    BRANCHIND = 6
    # Call to an absolute address
    CALL = 7
    # Call through an indirect address
    CALLIND = 8
    # User-defined operation
    CALLOTHER = 9
    # Return from subroutine
    RETURN = 10
    # Integer comparison, equality (==)
    INT_EQUAL = 11
    # Integer comparison, in-equality (!=)
    INT_NOTEQUAL = 12
    # Integer comparison, signed less-than (<)
    INT_SLESS = 13
    # Integer comparison, signed less-than-or-equal (<=)
    INT_SLESSEQUAL = 14
    # Integer comparison, unsigned less-than (<). This also indicates a borrow on unsigned substraction.
    INT_LESS = 15
    # Integer comparison, unsigned less-than-or-equal (<=)
    INT_LESSEQUAL = 16
    # Zero extension
    INT_ZEXT = 17
    # Sign extension
    INT_SEXT = 18
    # Addition, signed or unsigned (+)
    INT_ADD = 19
    # Subtraction, signed or unsigned (-)
    INT_SUB = 20
    # Test for unsigned carry
    INT_CARRY = 21
    # Test for signed carry
    INT_SCARRY = 22
    # Test for signed borrow
    INT_SBORROW = 23
    # Twos complement
    INT_2COMP = 24
    # Logical/bitwise negation (~)
    INT_NEGATE = 25
    # Logical/bitwise exclusive-or (^)
    INT_XOR = 26
    # Logical/bitwise and (&)
    INT_AND = 27
    # Logical/bitwise or (|)
    INT_OR = 28
    # Left shift (<<)
    INT_LEFT = 29
    # Right shift, logical (>>)
    INT_RIGHT = 30
    # Right shift, arithmetic (>>)
    INT_SRIGHT = 31
    # Integer multiplication, signed and unsigned (*)
    INT_MULT = 32
    # Integer division, unsigned (/)
    INT_DIV = 33
    # Integer division, signed (/)
    INT_SDIV = 34
    # Remainder/modulo, unsigned (%)
    INT_REM = 35
    # Remainder/modulo, signed (%)
    INT_SREM = 36
    # Boolean negate (!)
    BOOL_NEGATE = 37
    # Boolean exclusive-or (^^)
    BOOL_XOR = 38
    # Boolean and (&&)
    BOOL_AND = 39
    # Boolean or (||)
    BOOL_OR = 40
    # Floating-point comparison, equality (==)
    FLOAT_EQUAL = 41
    # Floating-point comparison, in-equality (!=)
    FLOAT_NOTEQUAL = 42
    # Floating-point comparison, less-than (<)
    FLOAT_LESS = 43
    # Floating-point comparison, less-than-or-equal (<=)
    FLOAT_LESSEQUAL = 44
    # Not-a-number test (NaN)
    FLOAT_NAN = 46
    # Floating-point addition (+)
    FLOAT_ADD = 47
    # Floating-point division (/)
    FLOAT_DIV = 48
    # Floating-point multiplication (*)
    FLOAT_MULT = 49
    # Floating-point subtraction (-)
    FLOAT_SUB = 50
    # Floating-point negation (-)
    FLOAT_NEG = 51
    # Floating-point absolute value (abs)
    FLOAT_ABS = 52
    # Floating-point square root (sqrt)
    FLOAT_SQRT = 53
    # Convert an integer to a floating-point
    FLOAT_INT2FLOAT = 54
    # Convert between different floating-point sizes
    FLOAT_FLOAT2FLOAT = 55
    # Round towards zero
    FLOAT_TRUNC = 56
    # Round towards +infinity
    FLOAT_CEIL = 57
    # Round towards -infinity
    FLOAT_FLOOR = 58
    # Round towards nearest
    FLOAT_ROUND = 59
    # Phi-node operator
    MULTIEQUAL = 60
    # Copy with an indirect effect
    INDIRECT = 61
    # Concatenate
    PIECE = 62
    # Truncate
    SUBPIECE = 63
    # Cast from one data-type to another
    CAST = 64
    # Index into an array ([])
    PTRADD = 65
    # Drill down to a sub-field  (->)
    PTRSUB = 66
    # Look-up a \e segmented address
    SEGMENTOP = 67
    # Recover a value from the \e constant \e pool
    CPOOLREF = 68
    # Allocate a new object (new)
    NEW = 69
    # Insert a bit-range
    INSERT = 70
    # Extract a bit-range
    EXTRACT = 71
    # Count the 1-bits
    POPCOUNT = 72
    # Count the leading 0-bits
    LZCOUNT = 73
    # Value indicating the end of the op-code values
    MAX = 74


@dataclass
class Insn:
    opcode: Opcode
    inputs: List[Vn]
    output: Optional[Vn]

    @classmethod
    def from_bindings(cls, bindings_insn: BindingsInsn) -> Self:
        opcode = Opcode(bindings_insn.opcode())

        inputs_amount = bindings_insn.inVarsAmount()
        inputs = [
            Vn.from_bindings(bindings_insn.inVar(i)) for i in range(inputs_amount)
        ]

        bindings_output: Optional[BindingsVarnodeData] = bindings_insn.outVar()
        output = (
            Vn.from_bindings(bindings_output) if bindings_output is not None else None
        )

        return cls(opcode, inputs, output)


@dataclass
class LiftRes:
    machine_insn_len: int
    insns: List[Insn]

    @classmethod
    def from_bindings(cls, bindings_lift_res: BindingsLiftRes) -> Self:
        machine_insn_len = bindings_lift_res.machineInsnLen()

        insns_amount = bindings_lift_res.insnsAmount()
        insns = [
            Insn.from_bindings(bindings_lift_res.insn(i)) for i in range(insns_amount)
        ]

        return cls(machine_insn_len, insns)


class VnSpaceKind(IntEnum):
    CONSTANT = 0
    PROCESSOR = 1
    SPACEBASE = 2
    INTERNAL = 3
    FSPEC = 4
    IOP = 5
    JOIN = 6


@dataclass
class VnSpaceInfo:
    shortcut: str
    name: str
    kind: VnSpaceKind
    word_size: int
    addr_size: int

    def space(self) -> VnSpace:
        return VnSpace(self.shortcut)

@dataclass
class NoSuchRegErr(Exception):
    reg_name: str

class Sleigh:
    def __init__(self, sla_relative_path: str):
        sla_path = PROCESSORS_DIR.joinpath(sla_relative_path)
        self.bindings_sleigh = BindingsSleigh(str(sla_path), MyLoadImage())

    def lift_one(self, addr: int) -> LiftRes:
        bindings_lift_res = self.bindings_sleigh.liftOne(addr)
        return LiftRes.from_bindings(bindings_lift_res)

    def default_code_space(self) -> VnSpace:
        return VnSpace.from_bindings(self.bindings_sleigh.getDefaultCodeSpace())

    def space_info(self, space: VnSpace) -> VnSpaceInfo:
        bindings_space = self.bindings_sleigh.getSpaceByShortcut(space.shortcut)
        return VnSpaceInfo(
            bindings_space.getShortcut(),
            bindings_space.getName(),
            VnSpaceKind(bindings_space.getType()),
            bindings_space.getWordSize(),
            bindings_space.getAddrSize(),
        )

    def reg_by_name(self, name: str) -> Vn:
        bindings_vn: BindingsVarnodeData = self.bindings_sleigh.regByName(name)
        if bindings_vn is None:
            raise NoSuchRegErr(name)
        return Vn.from_bindings(bindings_vn)


sleigh = Sleigh(SLA_RELATIVE_PATH_X86_64)
res = sleigh.lift_one(0)
print(res)

print(sleigh.space_info(sleigh.default_code_space()))
print(sleigh.reg_by_name('RSP'))
