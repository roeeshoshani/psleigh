#include <iostream>
#include <memory>
#include <ostream>
#include <pybind11/buffer_info.h>
#include <pybind11/detail/common.h>
#include <pybind11/detail/using_smart_holder.h>
#include <pybind11/pybind11.h>

#include "./src/error.hh"
#include "./src/globalcontext.hh"
#include "./src/loadimage.hh"
#include "./src/marshal.hh"
#include "./src/opcodes.hh"
#include "./src/pcoderaw.hh"
#include "./src/sleigh.hh"
#include "./src/slghsymbol.hh"
#include "./src/space.hh"
#include "./src/translate.hh"
#include "./src/types.h"
#include "./src/xml.hh"
#include "src/interface.hh"
#include <cstdint>
#include <sstream>
#include <stdexcept>

#define STR(X) #X

namespace py = pybind11;
using namespace ghidra;

#define DEFINE_EXCEPTION_WRAPPER(EXCEPTION_NAME, ...)                                                                          \
    class Bindings##EXCEPTION_NAME : public std::runtime_error {                                                               \
      public:                                                                                                                  \
        Bindings##EXCEPTION_NAME(const EXCEPTION_NAME& inner)                                                                  \
            : std::runtime_error("sleigh" __VA_OPT__(" " __VA_ARGS__) " error: " + inner.explain) {}                           \
    }

DEFINE_EXCEPTION_WRAPPER(SleighError);
DEFINE_EXCEPTION_WRAPPER(UnimplError, "unimplemented");
DEFINE_EXCEPTION_WRAPPER(ParseError, "parse");
DEFINE_EXCEPTION_WRAPPER(DataUnavailError, "data unavailable");
DEFINE_EXCEPTION_WRAPPER(BadDataError, "bad data");
DEFINE_EXCEPTION_WRAPPER(DecoderError, "decoder");
DEFINE_EXCEPTION_WRAPPER(RecovError, "recoverable");
DEFINE_EXCEPTION_WRAPPER(EvaluationError, "evaluation");
DEFINE_EXCEPTION_WRAPPER(LowlevelError, "low level");

#define WRAP_EXCEPTION(EXCEPTION_NAME)                                                                                         \
    catch (const EXCEPTION_NAME& e) {                                                                                          \
        throw Bindings##EXCEPTION_NAME(e);                                                                                     \
    }

#define WRAP_EXCEPTIONS()                                                                                                      \
    WRAP_EXCEPTION(SleighError)                                                                                                \
    WRAP_EXCEPTION(UnimplError)                                                                                                \
    WRAP_EXCEPTION(ParseError)                                                                                                 \
    WRAP_EXCEPTION(DataUnavailError)                                                                                           \
    WRAP_EXCEPTION(BadDataError)                                                                                               \
    WRAP_EXCEPTION(DecoderError)                                                                                               \
    WRAP_EXCEPTION(RecovError)                                                                                                 \
    WRAP_EXCEPTION(EvaluationError)                                                                                            \
    WRAP_EXCEPTION(LowlevelError)

class SymbolIsNotARegisterError : public std::runtime_error{
  public:
    SymbolIsNotARegisterError(): std::runtime_error("symbol is not a register") {}
};

class SimpleLoadImage : public LoadImage {
  public:
    SimpleLoadImage() : LoadImage("[simple]") {}
    virtual string getArchType(void) const { return "[simple]"; }
    virtual void adjustVma(long adjust) {}

    virtual py::buffer loadSimple(uint64_t addr, int4 amount) = 0;
    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) {
        try {
            AddrSpace* space = addr.getSpace();
            if (space != space->getManager()->getDefaultCodeSpace()) {
                throw std::runtime_error(
                    "attempted to load data from a SimpleLoadImage instance using an address space other than "
                    "the default code space"
                );
            }
            py::buffer buf = this->loadSimple(addr.getOffset(), size);
            py::buffer_info info = buf.request();
            if (info.size > size) {
                throw std::runtime_error("load simple returned an unexpected number of bytes");
            }
            memcpy(ptr, info.ptr, info.size);
            memset(ptr + info.size, 0, size - info.size);
        }
        WRAP_EXCEPTIONS()
    }
};

class PySimpleLoadImage : public SimpleLoadImage, public py::trampoline_self_life_support {
  public:
    using SimpleLoadImage::SimpleLoadImage;

    virtual py::buffer loadSimple(uint64_t addr, int4 amount) {
        PYBIND11_OVERRIDE_PURE(py::buffer, SimpleLoadImage, loadSimple, addr, amount);
    }
};

class MemoryBuffer : public std::streambuf {
  public:
    MemoryBuffer(const uint1* data, size_t len) {
        setg((char*)const_cast<uint1*>(data), (char*)const_cast<uint1*>(data), (char*)const_cast<uint1*>(data) + len);
    }
};

struct BindingsInsn {
    OpCode m_opcode;

    bool m_has_out_var;
    VarnodeData m_out_var;

    std::vector<VarnodeData> m_in_vars;

    size_t m_machine_insn_len;

    int opcode() {
        try {
            return m_opcode;
        }
        WRAP_EXCEPTIONS()
    }

    VarnodeData* outVar() {
        try {
            if (!this->m_has_out_var) {
                return nullptr;
            }
            return &this->m_out_var;
        }
        WRAP_EXCEPTIONS()
    }

    size_t inVarsAmount() {
        try {
            return this->m_in_vars.size();
        }
        WRAP_EXCEPTIONS()
    }

    VarnodeData* inVar(size_t index) {
        try {
            if (index >= this->m_in_vars.size()) {
                throw py::index_error("input varnode index out of range");
            }
            return &this->m_in_vars[index];
        }
        WRAP_EXCEPTIONS()
    }
};

class LiftRes : public PcodeEmit {
  public:
    std::vector<BindingsInsn> m_insns;
    size_t m_machine_insn_len;

    LiftRes() : m_insns(), m_machine_insn_len() {}

    virtual void dump(const Address& addr, OpCode opc, VarnodeData* outvar, VarnodeData* vars, int4 isize) {
        BindingsInsn insn = {};

        insn.m_opcode = opc;

        if (outvar != nullptr) {
            insn.m_has_out_var = true;
            insn.m_out_var = *outvar;
        }

        for (int4 i = 0; i < isize; i++) {
            insn.m_in_vars.push_back(vars[i]);
        }

        m_insns.push_back(insn);
    }

    size_t machineInsnLen() {
        try {
            return this->m_machine_insn_len;
        }
        WRAP_EXCEPTIONS()
    }

    size_t insnsAmount() {
        try {
            return this->m_insns.size();
        }
        WRAP_EXCEPTIONS()
    }

    BindingsInsn* insn(size_t insn_index) {
        try {
            if (insn_index >= this->m_insns.size()) {
                throw py::index_error("insn index out of range");
            }
            return &this->m_insns[insn_index];
        }
        WRAP_EXCEPTIONS()
    }
};

class BindingsSleigh {
  public:
    std::unique_ptr<SimpleLoadImage> m_buf_load_image;

    ContextInternal m_ctx;

    std::unique_ptr<Sleigh> m_sleigh;

    std::vector<string> m_all_reg_names;

    BindingsSleigh(
        const std::string& sla_file_path, const std::string& pspec_file_path, std::unique_ptr<SimpleLoadImage> buf_load_image
    )
        : m_buf_load_image(std::move(buf_load_image)), m_ctx(), m_sleigh(nullptr), m_all_reg_names() {
        try {
            m_sleigh = std::make_unique<Sleigh>(m_buf_load_image.get(), &m_ctx);

            // poor man's xml quoting check
            if (sla_file_path.find('<') != std::string::npos || sla_file_path.find('>') != std::string::npos) {
                throw std::invalid_argument(
                    "the provided sla file path contains a '<' or a '>' character, which is not allowed: " + sla_file_path
                );
            }

            // decode the sla specification
            std::stringstream slaspecStrStream;
            slaspecStrStream << "<sleigh>" << sla_file_path << "</sleigh>";
            DocumentStorage slaspecDocStorage;
            Element* sleighRoot = slaspecDocStorage.parseDocument(slaspecStrStream)->getRoot();
            slaspecDocStorage.registerTag(sleighRoot);
            m_sleigh->initialize(slaspecDocStorage);

            // decode processor specification (pspec)
            DocumentStorage pspecDocStorage;
            Element* pspecRoot = pspecDocStorage.openDocument(pspec_file_path)->getRoot();
            pspecDocStorage.registerTag(pspecRoot);
            const Element* pspecElem = pspecDocStorage.getTag("processor_spec");
            if (pspecElem == (const Element*)0)
                throw LowlevelError("No processor configuration tag found");
            for (Element* curElem : pspecElem->getChildren()) {
                if (curElem->getName() == "context_data") {
                    XmlDecode pspecDecoder((AddrSpaceManager*)&*m_sleigh, curElem);
                    m_ctx.decodeFromSpec(pspecDecoder);
                }
            }

            // collect all register names
            map<VarnodeData, string> tmp_all_regs;
            m_sleigh->getAllRegisters(tmp_all_regs);
            for (const auto& entry : tmp_all_regs) {
                m_all_reg_names.push_back(entry.second);
            }
        }
        WRAP_EXCEPTIONS()
    }

    std::unique_ptr<LiftRes> liftOne(uint64_t addr) {
        try {
            std::unique_ptr<LiftRes> lift_res = std::make_unique<LiftRes>();
            Address sleigh_addr(m_sleigh->getDefaultCodeSpace(), addr);
            uint32_t machine_insn_len = m_sleigh->oneInstruction(*lift_res, sleigh_addr);
            lift_res->m_machine_insn_len = machine_insn_len;
            return lift_res;
        }
        WRAP_EXCEPTIONS()
    }

    void setVarDefault(const std::string& name, uint32_t value) {
        try {
            this->m_ctx.setVariableDefault(name, value);
        }
        WRAP_EXCEPTIONS()
    }

    AddrSpace* getDefaultCodeSpace() {
        try {
            return m_sleigh->getDefaultCodeSpace();
        }
        WRAP_EXCEPTIONS()
    }

    AddrSpace* getSpaceByShortcut(char sc) {
        try {
            return m_sleigh->getSpaceByShortcut(sc);
        }
        WRAP_EXCEPTIONS()
    }

    const VarnodeData* regByName(const std::string& reg_name) {
        try {
            VarnodeSymbol* sym = (VarnodeSymbol*)m_sleigh->findSymbol(reg_name);

            if (sym == (VarnodeSymbol*)0)
                return NULL;

            if (sym->getType() != SleighSymbol::varnode_symbol)
                throw SymbolIsNotARegisterError();

            const VarnodeData& vn = sym->getFixedVarnode();

            return &vn;
        }
        WRAP_EXCEPTIONS()
    }

    size_t regNameToIndex(AddrSpace* space, uint64_t off, int32_t size) {
        try {
            std::string name = m_sleigh->getRegisterName(space, off, size);
            std::vector<std::string>& names = this->m_all_reg_names;

            auto it = std::find(names.begin(), names.end(), name);
            if (it != names.end()) {
                // return the index of the name in the list
                return std::distance(names.begin(), it);
            } else {
                return allRegNamesAmount();
            }
        }
        WRAP_EXCEPTIONS()
    }

    size_t allRegNamesAmount() {
        try {
            return this->m_all_reg_names.size();
        }
        WRAP_EXCEPTIONS()
    }

    const std::string& allRegNamesGetByIndex(size_t index) {
        try {
            return this->m_all_reg_names[index];
        }
        WRAP_EXCEPTIONS()
    }
};

void sleighBindingsInitGlobals() {
    try {
        static std::atomic<bool> initialized = false;
        if (!initialized.exchange(true)) {
            AttributeId::initialize();
            ElementId::initialize();
        }
    }
    WRAP_EXCEPTIONS()
}

uint64_t varnodeGetOffset(const VarnodeData* v) {
    try {
        return v->offset;
    }
    WRAP_EXCEPTIONS()
}

uint32_t varnodeGetSize(const VarnodeData* v) {
    try {
        return v->size;
    }
    WRAP_EXCEPTIONS()
}

AddrSpace* varnodeGetSpace(const VarnodeData* v) {
    try {
        return v->space;
    }
    WRAP_EXCEPTIONS()
}

int addrSpaceGetType(const AddrSpace* space) {
    try {
        return (int)space->getType();
    }
    WRAP_EXCEPTIONS()
}

uint4 addrSpaceGetWordSize(const AddrSpace* space) {
    try {
        return space->getWordSize();
    }
    WRAP_EXCEPTIONS()
}

uint4 addrSpaceGetAddrSize(const AddrSpace* space) {
    try {
        return space->getAddrSize();
    }
    WRAP_EXCEPTIONS()
}

const std::string& addrSpaceGetName(const AddrSpace* space) {
    try {
        return space->getName();
    }
    WRAP_EXCEPTIONS()
}

char addrSpaceGetShortcut(const AddrSpace* space) {
    try {
        return space->getShortcut();
    }
    WRAP_EXCEPTIONS()
}

PYBIND11_MODULE(psleigh_bindings, m, py::mod_gil_not_used()) {
    sleighBindingsInitGlobals();

    py::class_<BindingsSleigh, py::smart_holder>(m, "BindingsSleigh")
        .def(py::init<const std::string&, const std::string&, std::unique_ptr<SimpleLoadImage>>())
        .def("liftOne", &BindingsSleigh::liftOne)
        .def("setVarDefault", &BindingsSleigh::setVarDefault)
        .def("getDefaultCodeSpace", &BindingsSleigh::getDefaultCodeSpace, py::return_value_policy::reference_internal)
        .def("getSpaceByShortcut", &BindingsSleigh::getSpaceByShortcut, py::return_value_policy::reference_internal)
        .def("regByName", &BindingsSleigh::regByName, py::return_value_policy::reference_internal)
        .def("regNameToIndex", &BindingsSleigh::regNameToIndex)
        .def("allRegNamesAmount", &BindingsSleigh::allRegNamesAmount)
        .def("allRegNamesGetByIndex", &BindingsSleigh::allRegNamesGetByIndex, py::return_value_policy::reference_internal);

    py::class_<LiftRes, py::smart_holder>(m, "BindingsLiftRes")
        .def("machineInsnLen", &LiftRes::machineInsnLen)
        .def("insnsAmount", &LiftRes::insnsAmount)
        .def("insn", &LiftRes::insn, py::return_value_policy::reference_internal);

    py::class_<BindingsInsn, py::smart_holder>(m, "BindingsInsn")
        .def("opcode", &BindingsInsn::opcode)
        .def("outVar", &BindingsInsn::outVar, py::return_value_policy::reference_internal)
        .def("inVarsAmount", &BindingsInsn::inVarsAmount)
        .def("inVar", &BindingsInsn::inVar, py::return_value_policy::reference_internal);

    py::class_<VarnodeData, py::smart_holder>(m, "BindingsVarnodeData")
        .def("getOffset", &varnodeGetOffset)
        .def("getSize", &varnodeGetSize)
        .def("getSpace", &varnodeGetSpace, py::return_value_policy::reference_internal);

    py::class_<AddrSpace, py::smart_holder>(m, "BindingsAddrSpace")
        .def("getName", &addrSpaceGetName, py::return_value_policy::reference_internal)
        .def("getShortcut", &addrSpaceGetShortcut)
        .def("getType", &addrSpaceGetType)
        .def("getWordSize", &addrSpaceGetWordSize)
        .def("getAddrSize", &addrSpaceGetAddrSize);

    py::class_<SimpleLoadImage, PySimpleLoadImage, py::smart_holder>(m, "BindingsSimpleLoadImage")
        .def(py::init<>())
        .def("loadSimple", &SimpleLoadImage::loadSimple);

#define DEF_EXCEPTION(EXCEPTION_NAME) py::exception<EXCEPTION_NAME>(m, STR(EXCEPTION_NAME))
#define DEF_BINDINGS_EXCEPTION(EXCEPTION_NAME) DEF_EXCEPTION(Bindings##EXCEPTION_NAME)
    DEF_BINDINGS_EXCEPTION(SleighError);
    DEF_BINDINGS_EXCEPTION(UnimplError);
    DEF_BINDINGS_EXCEPTION(ParseError);
    DEF_BINDINGS_EXCEPTION(DataUnavailError);
    DEF_BINDINGS_EXCEPTION(BadDataError);
    DEF_BINDINGS_EXCEPTION(DecoderError);
    DEF_BINDINGS_EXCEPTION(RecovError);
    DEF_BINDINGS_EXCEPTION(EvaluationError);
    DEF_BINDINGS_EXCEPTION(LowlevelError);
    DEF_EXCEPTION(SymbolIsNotARegisterError);
}
