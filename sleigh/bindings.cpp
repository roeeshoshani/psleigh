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
#include <pybind11/pybind11.h>
#include <stdexcept>

using namespace ghidra;

enum class BindingsError {
    Success = 0,

    AddrWraparound = 1,
    AddrOutOfBufferBounds = 2,
    OutOfMem = 3,
    ParseErr = 4,
    Unknown = 5,
    CallbackError = 6,
    NoSuchRegister = 7,
    SymbolIsNotARegister = 8,
    LowLevelErr = 9,
};

class BindingsException : public std::exception {
  public:
    BindingsException(BindingsError error) : m_error(error) {}
    BindingsError m_error;
};

typedef uint8_t (*BindingsLoadImageCallback)(void* ctx, uint1* ptr, int4 size, const AddrSpace* addr_space, uintb addr_offset);

class BindingsLoadImage : public LoadImage {
  public:
    BindingsLoadImageCallback m_read_callback;
    void* m_read_callback_ctx;

    BindingsLoadImage(BindingsLoadImageCallback read_callback, void* read_callback_ctx)
        : LoadImage("[memory]"), m_read_callback(read_callback), m_read_callback_ctx(read_callback_ctx) {}

    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) {
        uint8_t res = m_read_callback(m_read_callback_ctx, ptr, size, addr.getSpace(), addr.getOffset());
        if (!res) {
            throw BindingsException(BindingsError::CallbackError);
        }
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
};

class BindingsSleigh : public SleighBase {
  public:
    BindingsLoadImage m_buf_load_image;
    ContextInternal m_ctx;
    mutable PcodeCacher m_pcode_cache;
    std::unique_ptr<ContextCache> m_ctx_cache;
    std::unique_ptr<DisassemblyCache> m_dis_cache;

    std::vector<BindingsInsn> m_insns;
    size_t machine_insn_len;

    std::vector<string> m_all_reg_names;

    BindingsSleigh(
        const uint1* sla_content, size_t sla_content_len, BindingsLoadImageCallback read_callback, void* read_callback_ctx
    )
        : SleighBase(), m_buf_load_image(read_callback, read_callback_ctx), m_ctx(), m_pcode_cache(), m_ctx_cache(nullptr),
          m_dis_cache(nullptr), m_insns(), m_all_reg_names() {
        m_ctx_cache = std::make_unique<ContextCache>(&m_ctx);

        // convert the sla content buffer to an istream
        MemoryBuffer buf(sla_content, sla_content_len);
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
        m_buf_load_image.loadFill(pos.getBuffer(), 16, pos.getAddr());
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

void sleigh_bindings_init_globals() {
    AttributeId::initialize();
    ElementId::initialize();
}

int sleigh_bindings_ctx_init(
    const uint8_t* sla_content, size_t sla_content_len, BindingsLoadImageCallback read_callback, void* read_callback_ctx,
    void** ctx
) {
    BindingsSleigh* s = new BindingsSleigh(sla_content, sla_content_len, read_callback, read_callback_ctx);
    if (s == nullptr) {
        return (int)BindingsError::OutOfMem;
    }
    *ctx = s;
    return (int)BindingsError::Success;
}

int sleigh_bindings_ctx_set_var_default(void* ctx, const char* name, size_t name_len, uint32_t value) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;

    // `name` is a rust string and not a cstring, so we need to specify its lenghth explicitly.
    std::string name_string(name, name_len);

    s->m_ctx.setVariableDefault(name_string, value);

    return (int)BindingsError::Success;
}

void* sleigh_bindings_ctx_default_code_space(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->getDefaultCodeSpace();
}

int sleigh_bindings_ctx_lift_one(void* ctx, uint64_t addr) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    BindingsPcodeEmitter emitter;
    uint32_t machine_insn_len = s->myOneInstruction(emitter, addr);
    s->m_insns = emitter.takeInsns();
    s->machine_insn_len = machine_insn_len;
    return (int)BindingsError::Success;
}

size_t sleigh_bindings_ctx_machine_insn_len(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->machine_insn_len;
}

size_t sleigh_bindings_ctx_insns_amount(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_insns.size();
}

int sleigh_bindings_ctx_insn_opcode(void* ctx, size_t insn_index) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_insns[insn_index].m_opcode;
}

void* sleigh_bindings_ctx_insn_out_var(void* ctx, size_t insn_index) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    if (!s->m_insns[insn_index].m_has_out_var) {
        return nullptr;
    }
    return &s->m_insns[insn_index].m_out_var;
}

size_t sleigh_bindings_ctx_insn_in_vars_amount(void* ctx, size_t insn_index) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_insns[insn_index].m_in_vars.size();
}

void* sleigh_bindings_ctx_insn_in_var(void* ctx, size_t insn_index, size_t in_var_index) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    if (in_var_index >= s->m_insns[insn_index].m_in_vars.size()) {
        return nullptr;
    }
    return &s->m_insns[insn_index].m_in_vars[in_var_index];
}

void* sleigh_bindings_ctx_space_by_shortcut(void* ctx, char shortcut) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->getSpaceByShortcut(shortcut);
}

int sleigh_bindings_ctx_reg_by_name(void* ctx, const char* reg_name, size_t reg_name_len, void** out_vn_ptr) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;

    // `reg_name` is a rust string and not a cstring, so we need to specify its lenghth explicitly.
    std::string reg_name_string(reg_name, reg_name_len);

    VarnodeSymbol* sym = (VarnodeSymbol*)s->findSymbol(reg_name_string);

    if (sym == (VarnodeSymbol*)0)
        return (int)BindingsError::NoSuchRegister;

    if (sym->getType() != SleighSymbol::varnode_symbol)
        return (int)BindingsError::SymbolIsNotARegister;

    const VarnodeData& vn = sym->getFixedVarnode();
    const VarnodeData* vn_ptr = (const VarnodeData*)&vn;
    *out_vn_ptr = (void*)vn_ptr;

    return (int)BindingsError::Success;
}

size_t sleigh_bindings_ctx_reg_to_name_index(void* ctx, void* space, uint64_t off, int32_t size) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;

    std::string name = s->getRegisterName((AddrSpace*)space, off, size);
    std::vector<std::string>& names = s->m_all_reg_names;

    auto it = std::find(names.begin(), names.end(), name);
    if (it != names.end()) {
        // return the index of the name in the list
        return std::distance(names.begin(), it);
    } else {
        return SIZE_MAX;
    }
}

size_t sleigh_bindings_ctx_all_reg_names_amount(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_all_reg_names.size();
}

const char* sleigh_bindings_ctx_all_reg_names_get_by_index(void* ctx, size_t index, size_t* out_name_len) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    const string& name = s->m_all_reg_names[index];
    *out_name_len = name.size();
    return name.data();
}

uint64_t sleigh_bindings_varnode_offset(void* varnode) {
    const VarnodeData* v = (VarnodeData*)varnode;
    return v->offset;
}

uint32_t sleigh_bindings_varnode_size(void* varnode) {
    const VarnodeData* v = (VarnodeData*)varnode;
    return v->size;
}

void* sleigh_bindings_varnode_space(void* varnode) {
    const VarnodeData* v = (VarnodeData*)varnode;
    return v->space;
}

const char* sleigh_bindings_space_name(void* space, size_t* out_name_len) {
    AddrSpace* s = (AddrSpace*)space;
    *out_name_len = s->getName().size();
    return s->getName().data();
}

char sleigh_bindings_space_shortcut(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getShortcut();
}

int sleigh_bindings_space_type(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getType();
}

uint32_t sleigh_bindings_space_word_size(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getWordSize();
}

uint32_t sleigh_bindings_space_addr_size(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getAddrSize();
}

void sleigh_bindings_ctx_destroy(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    delete s;
}

PYBIND11_MODULE(pysleigh_bindings, m) {
#define DEF_FN(FN) m.def(#FN, FN)

    DEF_FN(sleigh_bindings_init_globals);
    DEF_FN(sleigh_bindings_ctx_init);
    DEF_FN(sleigh_bindings_ctx_set_var_default);
    DEF_FN(sleigh_bindings_ctx_default_code_space);
    DEF_FN(sleigh_bindings_ctx_lift_one);
    DEF_FN(sleigh_bindings_ctx_machine_insn_len);
    DEF_FN(sleigh_bindings_ctx_insns_amount);
    DEF_FN(sleigh_bindings_ctx_insn_opcode);
    DEF_FN(sleigh_bindings_ctx_insn_out_var);
    DEF_FN(sleigh_bindings_ctx_insn_in_vars_amount);
    DEF_FN(sleigh_bindings_ctx_insn_in_var);
    DEF_FN(sleigh_bindings_ctx_space_by_shortcut);
    DEF_FN(sleigh_bindings_ctx_reg_by_name);
    DEF_FN(sleigh_bindings_ctx_reg_to_name_index);
    DEF_FN(sleigh_bindings_ctx_all_reg_names_amount);
    DEF_FN(sleigh_bindings_ctx_all_reg_names_get_by_index);
    DEF_FN(sleigh_bindings_varnode_offset);
    DEF_FN(sleigh_bindings_varnode_size);
    DEF_FN(sleigh_bindings_varnode_space);
    DEF_FN(sleigh_bindings_space_name);
    DEF_FN(sleigh_bindings_space_shortcut);
    DEF_FN(sleigh_bindings_space_type);
    DEF_FN(sleigh_bindings_space_word_size);
    DEF_FN(sleigh_bindings_space_addr_size);
    DEF_FN(sleigh_bindings_ctx_destroy);
}
