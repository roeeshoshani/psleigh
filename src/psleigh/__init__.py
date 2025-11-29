from __future__ import annotations
from .psleigh_bindings import (
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


@dataclass(frozen=True)
class MemReadReq:
    """
    a request to read memory from a memory reader.
    """

    # the address to read from
    addr: int

    # the maximum amount of contiguous bytes to read
    amount: int


class MemReaderMeta(type(BindingsSimpleLoadImage), ABCMeta):
    """
    a meta class which combines the pybind metaclass and the ABC metaclass so that we can create a class which inherits from
    both a pybind base class and the ABC base class.
    """
    pass


class MemReader(ABC, BindingsSimpleLoadImage, metaclass=MemReaderMeta):
    """
    a memory reader.

    this represents an abstraction over a memory map. it is used by the sleigh lifter to read the machine code bytes.

    the core (and only) abstract function of this base class is the `read` function.
    it takes in an address and an amount of bytes, and returns the value of these bytes in memory.

    this can represent many things, ranging from a simple buffer of contiguous memory, to a memory map which represents the data
    in an ELF file's section and program headers.
    """

    def __init__(self):
        super().__init__()

    @abstractmethod
    def read(self, req: MemReadReq) -> bytes:
        """
        read up to `req.amount` contiguous bytes from memory at address `req.addr`.

        if there is less than `req.amount` bytes of valid memory at address `req.addr`, this function should return as many bytes
        as possible, as long as they are contiguous.

        this is important since the sleigh engine will often issue reads of predefined sizes (e.g 16 bytes) even if instructions are
        smaller, and may thus try to read more bytes than are actually available.

        in such cases, we still want to return as many bytes as possible to the engine to properly decode the instructions, even if we
        don't have the requested amount of bytes.
        """
        pass

    def loadSimple(self, addr: int, amount: int) -> bytes:
        """
        this is the actual FFI function that we are overriding in the `BindingsSimpleLoadImage` class, and this is what will be called
        by the sleigh engine.

        this function is just a thin wrapper for the `read` function.
        """
        req = MemReadReq(addr, amount)

        res = self.read(req)

        # if there are no bytes available, raise a corresponding exception.
        if len(res) == 0:
            raise MemReaderDataUnavailErr(req)

        return res


@dataclass(frozen=True)
class MemReaderDataUnavailErr(Exception):
    """
    an error indicating that the memory reader doesn't have any bytes available at the requested address.
    """
    req: MemReadReq


@dataclass(frozen=True)
class EmptyMemReader(MemReader):
    def __post_init__(self):
        super().__init__()

    def read(self, req: MemReadReq) -> bytes:
        return b""


@dataclass
class BufMemReader(MemReader):
    buf: bytes
    buf_addr: int

    def __post_init__(self):
        super().__init__()

    def buf_end_addr(self) -> int:
        return self.buf_addr + len(self.buf)

    def read(self, req: MemReadReq) -> bytes:
        offset = req.addr - self.buf_addr
        end_offset = min(offset + req.amount, len(self.buf))
        return self.buf[offset:end_offset]


@dataclass(frozen=True)
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

    def __str__(self) -> str:
        return self.shortcut

    def info(self, sleigh: Sleigh) -> VnSpaceInfo:
        return sleigh.space_info(self)

    def fmt(self, sleigh: Sleigh) -> str:
        return self.info(sleigh).name


@dataclass(frozen=True)
class VnAddr:
    off: int
    space: VnSpace

    def __str__(self) -> str:
        if self.space == VnSpace.const():
            return hex(self.off)

        return f"{self.space}[{self.off}]"

    def fmt(self, sleigh: Sleigh) -> str:
        if self.space == VnSpace.const():
            return hex(self.off)

        return f"{self.space.fmt(sleigh)}[{self.off}]"


@dataclass(frozen=True)
class Vn:
    addr: VnAddr
    size: int

    @classmethod
    def from_bindings(cls, bindings_vn: BindingsVarnodeData) -> Self:
        addr = VnAddr(
            bindings_vn.getOffset(), VnSpace.from_bindings(bindings_vn.getSpace())
        )
        return cls(addr, bindings_vn.getSize())

    def __str__(self) -> str:
        return f"{self.addr}:{self.size}"

    def fmt(self, sleigh: Sleigh) -> str:
        name = sleigh.reg_to_name(self)
        if name is not None:
            return name

        return f"{self.addr.fmt(sleigh)}:{self.size}"


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

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return self.name


@dataclass(frozen=True)
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

    def all_vns(self) -> List[Vn]:
        if self.output is not None:
            return [self.output] + self.inputs
        else:
            return self.inputs.copy()

    def __str__(self) -> str:
        all_vns = self.all_vns()
        return str(self.opcode) + " " + ", ".join(str(vn) for vn in all_vns)

    def fmt(self, sleigh: Sleigh) -> str:
        all_vns = self.all_vns()
        return str(self.opcode) + " " + ", ".join(vn.fmt(sleigh) for vn in all_vns)


@dataclass(frozen=True)
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

    def fmt_insns(self, sleigh: Sleigh) -> str:
        return "\n".join(insn.fmt(sleigh) for insn in self.insns)


class VnSpaceKind(IntEnum):
    CONSTANT = 0
    PROCESSOR = 1
    SPACEBASE = 2
    INTERNAL = 3
    FSPEC = 4
    IOP = 5
    JOIN = 6


@dataclass(frozen=True)
class VnSpaceInfo:
    """
    extended information about a varnode address space.
    """

    shortcut: str
    name: str
    kind: VnSpaceKind

    # the size, in bytes, of a single word in this address space.
    # a word is the smallest addressable unit of memory.
    # this will usually be 1, indicating that the smallest addressable unit of memory in the address space is a single byte.
    word_size: int

    # specifies the number of bytes needed to address any byte within the space. for example, a 32-bit address space has size 4.
    addr_size: int

    def space(self) -> VnSpace:
        return VnSpace(self.shortcut)


@dataclass(frozen=True)
class NoSuchRegErr(Exception):
    reg_name: str


@dataclass(frozen=True)
class SleighArch:
    # the path of the sla file relative to the processors directory
    sla_relative_path: str

    # the path of the pspec file relative to the processors directory
    pspec_relative_path: str

    def sla_abs_path(self) -> str:
        return str(PROCESSORS_DIR.joinpath(self.sla_relative_path))

    def pspec_abs_path(self) -> str:
        return str(PROCESSORS_DIR.joinpath(self.pspec_relative_path))

    @classmethod
    def x86_64(cls) -> Self:
        return cls("x86/data/languages/x86-64.sla", "x86/data/languages/x86-64.pspec")

    @classmethod
    def x86(cls) -> Self:
        return cls("x86/data/languages/x86.sla", "x86/data/languages/x86.pspec")

    @classmethod
    def mips32le(cls) -> Self:
        return cls(
            "MIPS/data/languages/mips32le.sla", "MIPS/data/languages/mips32.pspec"
        )

    @classmethod
    def mips32be(cls) -> Self:
        return cls(
            "MIPS/data/languages/mips32be.sla", "MIPS/data/languages/mips32.pspec"
        )


@dataclass(frozen=True)
class PartiallyInitializedInsnErr(Exception):
    addr: int
    content: bytes
    desired_len: int


class Sleigh:
    arch: SleighArch
    mem_reader: MemReader
    bindings_sleigh: BindingsSleigh
    all_reg_names: List[str]

    def __init__(self, arch: SleighArch, mem_reader: MemReader):
        self.arch = arch
        self.mem_reader = mem_reader
        self.bindings_sleigh = BindingsSleigh(
            arch.sla_abs_path(), arch.pspec_abs_path(), mem_reader
        )
        self.all_reg_names = self._fetch_all_reg_names_from_bindings()

    def verify_insn_bytes_initialized(self, addr: int, machine_insn_len: int):
        content = self.mem_reader.read(MemReadReq(addr, machine_insn_len))

        # sanity
        assert len(content) <= machine_insn_len

        if len(content) < machine_insn_len:
            raise PartiallyInitializedInsnErr(addr, content, machine_insn_len)

    def lift_one(self, addr: int) -> LiftRes:
        bindings_lift_res = self.bindings_sleigh.liftOne(addr)

        # at this point we have successfully decoded the instruction, but i am adding an extra check here
        # to make sure that all of the instructions bytes are properly initialized.
        #
        # sleigh has a design problem where its "read memory" abstraction can only either return all of the
        # requested bytes, or fail entirely, but it can't return only a partial amount of bytes.
        #
        # when only part of the bytes are available, our ffi wrapper function just fills the rest of the buffer
        # with zeroes. this means that if we have a buffer with only the first few bytes of an instruction,
        # but not all, then the rest of the bytes will be treated as zeroes and the instruction will decode
        # successfully instead of returning an error.
        #
        # to fix this problem, we add a check here to make sure that all of the bytes that are reported by
        # sleigh to be used by the instruction are actually properly initialized.
        machine_insn_len = bindings_lift_res.machineInsnLen()
        self.verify_insn_bytes_initialized(addr, machine_insn_len)

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

    def reg_to_name(self, reg: Vn) -> Optional[str]:
        all_regs_amount = self.bindings_sleigh.allRegNamesAmount()

        bindings_space = self.bindings_sleigh.getSpaceByShortcut(
            reg.addr.space.shortcut
        )

        name_index = self.bindings_sleigh.regNameToIndex(
            bindings_space, reg.addr.off, reg.size
        )

        # the bindings returns the regs amount to indicate that the provided varnode is not a named register
        if name_index == all_regs_amount:
            return None

        return self.all_reg_names[name_index]

    def _fetch_all_reg_names_from_bindings(self) -> List[str]:
        all_regs_amount = self.bindings_sleigh.allRegNamesAmount()
        return [
            self.bindings_sleigh.allRegNamesGetByIndex(i)
            for i in range(all_regs_amount)
        ]

    def decode_space_from_vn(self, vn: Vn) -> VnSpace:
        """
        decodes the varnode address space encoded in the given varnode.

        the given vn must be the first input vn of a pcode LOAD or STORE operation, since this is the only case where vns are
        used to encode address spaces in pcode.

        WARNING: providing any other varnode will cause undefined behaviour, and may crash the program.
        """
        assert vn.addr.space == VnSpace.const()
        bindings_addr_space = self.bindings_sleigh.getSpaceFromConstVarnodeOffset(
            vn.addr.off
        )
        return VnSpace.from_bindings(bindings_addr_space)
