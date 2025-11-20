#include <exception>
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

class SymbolIsNotARegisterError : public std::exception {};

class SimpleLoadImage : public LoadImage {
  public:
    SimpleLoadImage() : LoadImage("[simple]") {}
    virtual string getArchType(void) const { return "[simple]"; }
    virtual void adjustVma(long adjust) {}

    virtual py::buffer loadSimple(uint64_t addr, int4 amount) = 0;
    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) {
        AddrSpace* space = addr.getSpace();
        if (space != space->getManager()->getDefaultCodeSpace()) {
            throw std::runtime_error("attempted to load data from a SimpleLoadImage instance using an address space other than "
                                     "the default code space");
        }
        py::buffer buf = this->loadSimple(addr.getOffset(), size);
        py::buffer_info info = buf.request();
        if (info.size != size) {
            throw std::runtime_error("load simple returned an unexpected number of bytes");
        }
        memcpy(ptr, info.ptr, size);
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

    VarnodeData* outVar() {
        if (this->m_has_out_var) {
            return nullptr;
        }
        return &this->m_out_var;
    }

    size_t inVarsAmount() { return this->m_in_vars.size(); }

    VarnodeData* inVar(size_t index) {
        if (index >= this->m_in_vars.size()) {
            throw py::index_error("input varnode index out of range");
        }
        return &this->m_in_vars[index];
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

    size_t machineInsnLen() { return this->m_machine_insn_len; }

    size_t insnsAmount() { return this->m_insns.size(); }

    BindingsInsn* insn(size_t insn_index) {
        if (insn_index >= this->m_insns.size()) {
            throw py::index_error("insn index out of range");
        }
        return &this->m_insns[insn_index];
    }

};

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

class BindingsSleigh {
  public:
    std::unique_ptr<SimpleLoadImage> m_buf_load_image;

    ContextInternal m_ctx;

    std::unique_ptr<Sleigh> m_sleigh;

    std::vector<string> m_all_reg_names;

    BindingsSleigh(const std::string& sla_file_path, std::unique_ptr<SimpleLoadImage> buf_load_image)
        : m_buf_load_image(std::move(buf_load_image)), m_ctx(), m_sleigh(nullptr), m_all_reg_names() {

#define WRAP_EXCEPTION(EXCEPTION_NAME)                                                                                         \
    catch (const EXCEPTION_NAME& e) {                                                                                          \
        throw Bindings##EXCEPTION_NAME(e);                                                                                     \
    }

        try {
            m_sleigh = std::make_unique<Sleigh>(m_buf_load_image.get(), &m_ctx);

            // poor man's xml quoting check
            if (sla_file_path.find('<') != std::string::npos || sla_file_path.find('>') != std::string::npos) {
                throw std::invalid_argument(
                    "the provided sla file path contains a '<' or a '>' character, which is not allowed: " + sla_file_path
                );
            }

            // decode the sla specification
            DocumentStorage docstorage;
            std::stringstream strstream;
            strstream << "<sleigh>" << sla_file_path << "</sleigh>";
            Element* sleighroot = docstorage.parseDocument(strstream)->getRoot();
            docstorage.registerTag(sleighroot);
            m_sleigh->initialize(docstorage);

            // collect all register names
            map<VarnodeData, string> tmp_all_regs;
            m_sleigh->getAllRegisters(tmp_all_regs);
            for (const auto& entry : tmp_all_regs) {
                m_all_reg_names.push_back(entry.second);
            }
        }
        WRAP_EXCEPTION(SleighError)
        WRAP_EXCEPTION(UnimplError)
        WRAP_EXCEPTION(ParseError)
        WRAP_EXCEPTION(DataUnavailError)
        WRAP_EXCEPTION(BadDataError)
        WRAP_EXCEPTION(DecoderError)
        WRAP_EXCEPTION(RecovError)
        WRAP_EXCEPTION(EvaluationError)
        WRAP_EXCEPTION(LowlevelError)
    }

    std::unique_ptr<LiftRes> liftOne(uint64_t addr) {
        std::unique_ptr<LiftRes> lift_res = std::make_unique<LiftRes>();
        Address sleigh_addr(m_sleigh->getDefaultCodeSpace(), addr);
        uint32_t machine_insn_len = m_sleigh->oneInstruction(*lift_res, sleigh_addr);
        lift_res->m_machine_insn_len = machine_insn_len;
        return lift_res;
    }

    void setVarDefault(const std::string& name, uint32_t value) { this->m_ctx.setVariableDefault(name, value); }

    AddrSpace* getDefaultCodeSpace() { return m_sleigh->getDefaultCodeSpace(); }

    AddrSpace* getSpaceByShortcut(char sc) { return m_sleigh->getSpaceByShortcut(sc); }

    const VarnodeData* regByName(const std::string& reg_name) {
        VarnodeSymbol* sym = (VarnodeSymbol*)m_sleigh->findSymbol(reg_name);

        if (sym == (VarnodeSymbol*)0)
            return NULL;

        if (sym->getType() != SleighSymbol::varnode_symbol)
            throw SymbolIsNotARegisterError();

        const VarnodeData& vn = sym->getFixedVarnode();

        return &vn;
    }

    size_t regNameToIndex(AddrSpace* space, uint64_t off, int32_t size) {
        std::string name = m_sleigh->getRegisterName(space, off, size);
        std::vector<std::string>& names = this->m_all_reg_names;

        auto it = std::find(names.begin(), names.end(), name);
        if (it != names.end()) {
            // return the index of the name in the list
            return std::distance(names.begin(), it);
        } else {
            return SIZE_MAX;
        }
    }

    size_t allRegNamesAmount() { return this->m_all_reg_names.size(); }

    const std::string& allRegNamesGetByIndex(size_t index) { return this->m_all_reg_names[index]; }
};

void sleighBindingsInitGlobals() {
    static std::atomic<bool> initialized = false;
    if (!initialized.exchange(true)) {
        AttributeId::initialize();
        ElementId::initialize();
    }
}

uint64_t varnodeGetOffset(const VarnodeData* v) { return v->offset; }

uint32_t varnodeGetSize(const VarnodeData* v) { return v->size; }

AddrSpace* varnodeGetSpace(const VarnodeData* v) { return v->space; }

PYBIND11_MODULE(pysleigh_bindings, m, py::mod_gil_not_used()) {
    sleighBindingsInitGlobals();

    py::class_<BindingsSleigh, py::smart_holder>(m, "Sleigh")
        .def(py::init<const std::string&, std::unique_ptr<SimpleLoadImage>>())
        .def("liftOne", &BindingsSleigh::liftOne)
        .def("setVarDefault", &BindingsSleigh::setVarDefault)
        .def("getDefaultCodeSpace", &BindingsSleigh::getDefaultCodeSpace, py::return_value_policy::reference_internal)
        .def("getSpaceByShortcut", &BindingsSleigh::getSpaceByShortcut, py::return_value_policy::reference_internal)
        .def("regByName", &BindingsSleigh::regByName, py::return_value_policy::reference_internal)
        .def("regNameToIndex", &BindingsSleigh::regNameToIndex)
        .def("allRegNamesAmount", &BindingsSleigh::allRegNamesAmount)
        .def("allRegNamesGetByIndex", &BindingsSleigh::allRegNamesGetByIndex, py::return_value_policy::reference_internal);

    py::class_<LiftRes, py::smart_holder>(m, "LiftRes")
        .def("machineInsnLen", &LiftRes::machineInsnLen)
        .def("insnsAmount", &LiftRes::insnsAmount)
        .def("insn", &LiftRes::insn, py::return_value_policy::reference_internal);

    py::class_<BindingsInsn, py::smart_holder>(m, "Insn")
        .def("outVar", &BindingsInsn::outVar, py::return_value_policy::reference_internal)
        .def("inVarsAmount", &BindingsInsn::inVarsAmount)
        .def("inVar", &BindingsInsn::inVar, py::return_value_policy::reference_internal);

    py::class_<VarnodeData, py::smart_holder>(m, "VarnodeData")
        .def("getOffset", &varnodeGetOffset)
        .def("getSize", &varnodeGetSize)
        .def("getSpace", &varnodeGetSpace, py::return_value_policy::reference_internal);

    py::class_<AddrSpace, py::smart_holder>(m, "AddrSpace")
        .def("getName", &AddrSpace::getName, py::return_value_policy::reference_internal)
        .def("getShortcut", &AddrSpace::getShortcut)
        .def("getType", &AddrSpace::getType)
        .def("getWordSize", &AddrSpace::getWordSize)
        .def("getAddrSize", &AddrSpace::getAddrSize);

    py::class_<SimpleLoadImage, PySimpleLoadImage, py::smart_holder>(m, "SimpleLoadImage")
        .def(py::init<>())
        .def("loadSimple", &SimpleLoadImage::loadSimple);

#define DEF_EXCEPTION(EXCEPTION_NAME) py::exception<Bindings##EXCEPTION_NAME>(m, STR(Bindings##EXCEPTION_NAME))
    DEF_EXCEPTION(SleighError);
    DEF_EXCEPTION(UnimplError);
    DEF_EXCEPTION(ParseError);
    DEF_EXCEPTION(DataUnavailError);
    DEF_EXCEPTION(BadDataError);
    DEF_EXCEPTION(DecoderError);
    DEF_EXCEPTION(RecovError);
    DEF_EXCEPTION(EvaluationError);
    DEF_EXCEPTION(LowlevelError);
}
