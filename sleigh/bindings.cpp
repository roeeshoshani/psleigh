#include <pybind11/detail/common.h>
#include <pybind11/detail/using_smart_holder.h>
#include <pybind11/pybind11.h>

#include "./src/error.hh"
#include "./src/globalcontext.hh"
#include "./src/loadimage.hh"
#include "./src/marshal.hh"
#include "./src/opcodes.hh"
#include "./src/pcoderaw.hh"
#include "./src/slaformat.hh"
#include "./src/sleigh.hh"
#include "./src/slghsymbol.hh"
#include "./src/space.hh"
#include "./src/translate.hh"
#include "./src/types.h"
#include "./src/xml.hh"
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace py = pybind11;
using namespace ghidra;

class SymbolIsNotARegisterError : public std::exception {};

class PyLoadImage : public LoadImage, public py::trampoline_self_life_support {
  public:
    using LoadImage::LoadImage;

    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) {
        PYBIND11_OVERRIDE_PURE(void, LoadImage, loadFill, ptr, size, addr);
    }
    virtual string getArchType(void) const { return "[memory]"; }
    virtual void adjustVma(long adjust) {}
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

class BindingsPcodeEmitter : public PcodeEmit {
  public:
    std::vector<BindingsInsn> m_insns;

    BindingsPcodeEmitter() : m_insns() {}

    std::vector<BindingsInsn> takeInsns() { return m_insns; }

    void reset() { m_insns.clear(); }

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
};

class BindingsSleigh : public SleighBase {
  public:
    std::unique_ptr<LoadImage> m_buf_load_image;
    ContextInternal m_ctx;
    mutable PcodeCacher m_pcode_cache;
    std::unique_ptr<ContextCache> m_ctx_cache;
    std::unique_ptr<DisassemblyCache> m_dis_cache;

    std::vector<BindingsInsn> m_insns;
    size_t machine_insn_len;

    std::vector<string> m_all_reg_names;

    BindingsSleigh(std::vector<uint1> sla_content, std::unique_ptr<LoadImage> buf_load_image)
        : SleighBase(), m_buf_load_image(std::move(buf_load_image)), m_ctx(), m_pcode_cache(), m_ctx_cache(nullptr),
          m_dis_cache(nullptr), m_insns(), m_all_reg_names() {
        m_ctx_cache = std::make_unique<ContextCache>(&m_ctx);

        // convert the sla content buffer to an istream
        MemoryBuffer buf(sla_content.data(), sla_content.size());
        std::istream stream(&buf);

        // decode the sla specification
        sla::FormatDecode decoder(this);
        decoder.ingestStream(stream);
        decode(decoder);

        uint4 parser_cachesize = 2;
        uint4 parser_windowsize = 32;
        if ((maxdelayslotbytes > 1) || (unique_allocatemask != 0)) {
            parser_cachesize = 8;
            parser_windowsize = 256;
        }
        m_dis_cache = std::make_unique<DisassemblyCache>(
            this, m_ctx_cache.get(), getConstantSpace(), parser_cachesize, parser_windowsize
        );

        // collect all register names
        map<VarnodeData, string> tmp_all_regs;
        getAllRegisters(tmp_all_regs);
        for (const auto& entry : tmp_all_regs) {
            m_all_reg_names.push_back(entry.second);
        }
    }

    // implement all virtual functions to make compiler happy
    virtual void initialize(DocumentStorage& store) { throw std::runtime_error("not implemented by bindings sleigh instance"); }
    virtual int4 oneInstruction(PcodeEmit& emit, const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }
    virtual int4 instructionLength(const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }
    virtual int4 printAssembly(AssemblyEmit& emit, const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }

    void resolve(ParserContext& pos)

    {
        m_buf_load_image->loadFill(pos.getBuffer(), 16, pos.getAddr());
        ParserWalkerChange walker(&pos);
        pos.deallocateState(walker); // Clear the previous resolve and initialize the walker
        Constructor *ct, *subct;
        uint4 off;
        int4 oper, numoper;

        pos.setDelaySlot(0);
        walker.setOffset(0);        // Initial offset
        pos.clearCommits();         // Clear any old context commits
        pos.loadContext();          // Get context for current address
        ct = root->resolve(walker); // Base constructor
        walker.setConstructor(ct);
        ct->applyContext(walker);
        while (walker.isState()) {
            ct = walker.getConstructor();
            oper = walker.getOperand();
            numoper = ct->getNumOperands();
            while (oper < numoper) {
                OperandSymbol* sym = ct->getOperand(oper);
                off = walker.getOffset(sym->getOffsetBase()) + sym->getRelativeOffset();
                pos.allocateOperand(oper, walker); // Descend into new operand and reserve space
                walker.setOffset(off);
                TripleSymbol* tsym = sym->getDefiningSymbol();
                if (tsym != (TripleSymbol*)0) {
                    subct = tsym->resolve(walker);
                    if (subct != (Constructor*)0) {
                        walker.setConstructor(subct);
                        subct->applyContext(walker);
                        break;
                    }
                }
                walker.setCurrentLength(sym->getMinimumLength());
                walker.popOperand();
                oper += 1;
            }
            if (oper >= numoper) { // Finished processing constructor
                walker.calcCurrentLength(ct->getMinimumLength(), numoper);
                walker.popOperand();
                // Check for use of delayslot
                ConstructTpl* templ = ct->getTempl();
                if ((templ != (ConstructTpl*)0) && (templ->delaySlot() > 0))
                    pos.setDelaySlot(templ->delaySlot());
            }
        }
        pos.setNaddr(pos.getAddr() + pos.getLength()); // Update Naddr to pointer after instruction
        pos.setParserState(ParserContext::disassembly);
    }

    void resolveHandles(ParserContext& pos) const

    {
        TripleSymbol* triple;
        Constructor* ct;
        int4 oper, numoper;

        ParserWalker walker(&pos);
        walker.baseState();
        while (walker.isState()) {
            ct = walker.getConstructor();
            oper = walker.getOperand();
            numoper = ct->getNumOperands();
            while (oper < numoper) {
                OperandSymbol* sym = ct->getOperand(oper);
                walker.pushOperand(oper); // Descend into node
                triple = sym->getDefiningSymbol();
                if (triple != (TripleSymbol*)0) {
                    if (triple->getType() == SleighSymbol::subtable_symbol)
                        break;
                    else // Some other kind of symbol as an operand
                        triple->getFixedHandle(walker.getParentHandle(), walker);
                } else { // Must be an expression
                    PatternExpression* patexp = sym->getDefiningExpression();
                    intb res = patexp->getValue(walker);
                    FixedHandle& hand(walker.getParentHandle());
                    hand.space = pos.getConstSpace(); // Result of expression is a constant
                    hand.offset_space = (AddrSpace*)0;
                    hand.offset_offset = (uintb)res;
                    hand.size = 0; // This size should not get used
                }
                walker.popOperand();
                oper += 1;
            }
            if (oper >= numoper) { // Finished processing constructor
                ConstructTpl* templ = ct->getTempl();
                if (templ != (ConstructTpl*)0) {
                    HandleTpl* res = templ->getResult();
                    if (res != (HandleTpl*)0) // Pop up handle to containing operand
                        res->fix(walker.getParentHandle(), walker);
                    // If we need an indicator that the constructor exports nothing try
                    // else
                    //   walker.getParentHandle().setInvalid();
                }
                walker.popOperand();
            }
        }
        pos.setParserState(ParserContext::pcode);
    }

    ParserContext* obtainContext(const Address& addr, int4 state) {
        ParserContext* pos = m_dis_cache->getParserContext(addr);
        int4 curstate = pos->getParserState();
        if (curstate >= state)
            return pos;
        if (curstate == ParserContext::uninitialized) {
            resolve(*pos);
            if (state == ParserContext::disassembly)
                return pos;
        }
        // If we reach here,  state must be ParserContext::pcode
        resolveHandles(*pos);
        return pos;
    }

    int4 myOneInstruction(PcodeEmit& emit, uintb address) {
        Address baseaddr(getDefaultCodeSpace(), address);
        if (alignment != 1) {
            if ((baseaddr.getOffset() % alignment) != 0) {
                ostringstream s;
                s << "Instruction address not aligned: " << baseaddr;
                throw UnimplError(s.str(), 0);
            }
        }

        ParserContext* pos = obtainContext(baseaddr, ParserContext::pcode);
        pos->applyCommits();
        int4 fallOffset = pos->getLength();

        if (pos->getDelaySlot() > 0) {
            int4 bytecount = 0;
            do {
                // Do not pass pos->getNaddr() to obtainContext, as pos may have been previously cached and had naddr adjusted
                ParserContext* delaypos = obtainContext(pos->getAddr() + fallOffset, ParserContext::pcode);
                delaypos->applyCommits();
                int4 len = delaypos->getLength();
                fallOffset += len;
                bytecount += len;
            } while (bytecount < pos->getDelaySlot());
            pos->setNaddr(pos->getAddr() + fallOffset);
        }
        ParserWalker walker(pos);
        walker.baseState();
        m_pcode_cache.clear();
        SleighBuilder builder(
            &walker, m_dis_cache.get(), &m_pcode_cache, getConstantSpace(), getUniqueSpace(), unique_allocatemask
        );
        try {
            builder.build(walker.getConstructor()->getTempl(), -1);
            m_pcode_cache.resolveRelatives();
            m_pcode_cache.emit(baseaddr, &emit);
        } catch (UnimplError& err) {
            ostringstream s;
            s << "Instruction not implemented in pcode:\n ";
            ParserWalker* cur = builder.getCurrentWalker();
            cur->baseState();
            Constructor* ct = cur->getConstructor();
            cur->getAddr().printRaw(s);
            s << ": ";
            ct->printMnemonic(s, *cur);
            s << "  ";
            ct->printBody(s, *cur);
            err.explain = s.str();
            err.instruction_length = fallOffset;
            throw err;
        }
        return fallOffset;
    }

    virtual void registerContext(const string& name, int4 sbit, int4 ebit) { m_ctx.registerVariable(name, sbit, ebit); }

    virtual void setContextDefault(const string& name, uintm val) { m_ctx.setVariableDefault(name, val); }

    virtual void allowContextSet(bool val) const { m_ctx_cache.get()->allowSet(val); }

    void liftOne(uint64_t addr) {
        BindingsPcodeEmitter emitter;
        uint32_t machine_insn_len = this->myOneInstruction(emitter, addr);
        this->m_insns = emitter.takeInsns();
        this->machine_insn_len = machine_insn_len;
    }

    void setVarDefault(const std::string& name, uint32_t value) { this->m_ctx.setVariableDefault(name, value); }

    size_t machineInsnLen() { return this->machine_insn_len; }

    size_t insnsAmount() { return this->m_insns.size(); }

    BindingsInsn* insn(size_t insn_index) {
        if (insn_index >= this->m_insns.size()) {
            throw py::index_error("insn index out of range");
        }
        return &this->m_insns[insn_index];
    }

    const VarnodeData* regByName(const std::string& reg_name) {
        VarnodeSymbol* sym = (VarnodeSymbol*)this->findSymbol(reg_name);

        if (sym == (VarnodeSymbol*)0)
            return NULL;

        if (sym->getType() != SleighSymbol::varnode_symbol)
            throw SymbolIsNotARegisterError();

        const VarnodeData& vn = sym->getFixedVarnode();

        return &vn;
    }

    size_t regNameToIndex(AddrSpace* space, uint64_t off, int32_t size) {
        std::string name = this->getRegisterName(space, off, size);
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
        .def(py::init<std::vector<uint1>, std::unique_ptr<LoadImage>>())
        .def("liftOne", &BindingsSleigh::liftOne)
        .def("setVarDefault", &BindingsSleigh::setVarDefault)
        .def("getDefaultCodeSpace", &BindingsSleigh::getDefaultCodeSpace, py::return_value_policy::reference_internal)
        .def("machineInsnLen", &BindingsSleigh::machineInsnLen)
        .def("insnsAmount", &BindingsSleigh::insnsAmount)
        .def("insn", &BindingsSleigh::insn, py::return_value_policy::reference_internal)
        .def("getSpaceByShortcut", &BindingsSleigh::getSpaceByShortcut, py::return_value_policy::reference_internal)
        .def("regByName", &BindingsSleigh::regByName, py::return_value_policy::reference_internal)
        .def("regNameToIndex", &BindingsSleigh::regNameToIndex)
        .def("allRegNamesAmount", &BindingsSleigh::allRegNamesAmount)
        .def("allRegNamesGetByIndex", &BindingsSleigh::allRegNamesGetByIndex, py::return_value_policy::reference_internal);

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
}
