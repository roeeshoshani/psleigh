BUILD_DIR ?= build
DIST_DIR ?= $(BUILD_DIR)/dist

SRC_NAMES := xml slghsymbol grammar pcodeparse slghparse slghscan ruleparse slghpatexpress slghpattern slaformat marshal opcodes translate space pcoderaw address float compression crc32 context semantics globalcontext pcodecompile type database variable cover varnode jumptable emulateutil emulate opbehavior memstate override fspec modelrules cpool architecture prefersplit funcdata_op op heritage rangeutil block funcdata merge funcdata_varnode unionresolve dynamic userop pcodeinject typeop varmap stringmanage flow funcdata_block action transform coreaction constseq subflow double condexe blockaction ruleaction multiprecision options printc ifacedecomp interface capability testfunction callgraph graph paramid printlanguage prettyprint comment loadimage cast sleighbase sleigh filemanage

OBJS := $(SRC_NAMES:%=$(BUILD_DIR)/%.o)
OBJS += $(BUILD_DIR)/bindings.o

SLGH_COMPILE_BIN := $(BUILD_DIR)/slgh_compile.elf

DIST_PROCESSORS_DIR := $(DIST_DIR)/processors
COPIED_PROCESSORS_DIR_MARKER := $(DIST_PROCESSORS_DIR)/.marker

SLASPEC_FILES := $(shell find processors/ -name "*.slaspec")
SLA_FILES := $(SLASPEC_FILES:processors/%.slaspec=$(DIST_PROCESSORS_DIR)/%.sla)

CXX := clang++

CXXFLAGS :=
LDFLAGS :=

CXXFLAGS += $(shell python3-config --cflags)

# sleigh depends on zlib
LDFLAGS += -lz

CXXFLAGS += -O3

CXXFLAGS += -fPIC

# enable lto
CXXFLAGS += -flto=thin -ffat-lto-objects
LDFLAGS += -fuse-ld=lld

YACC := bison

.phony: all
all: $(DIST_DIR)/libsla.so $(SLA_FILES)

$(COPIED_PROCESSORS_DIR_MARKER):
	rm -rf $(DIST_PROCESSORS_DIR)/*
	mkdir -p $(DIST_PROCESSORS_DIR)/
	cp -r processors/* $(DIST_PROCESSORS_DIR)/
	touch $@

$(DIST_PROCESSORS_DIR)/%.sla: processors/%.slaspec $(SLGH_COMPILE_BIN) $(COPIED_PROCESSORS_DIR_MARKER)
	@mkdir -p $(@D)
	$(SLGH_COMPILE_BIN) $< $@

$(DIST_DIR)/libsla.so: $(OBJS)
	$(CXX) -shared $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(SLGH_COMPILE_BIN): $(BUILD_DIR)/slgh_compile.o $(OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: src/%.cc
	@mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(BUILD_DIR)/bindings.o: bindings.cpp
	@mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

src/grammar.cc: src/grammar.y
	$(YACC) -l -o $@ $<
src/xml.cc: src/xml.y
	$(YACC) -l -o $@ $<
src/pcodeparse.cc: src/pcodeparse.y
	$(YACC) -l -o $@ $<
src/slghparse.cc: src/slghparse.y
	$(YACC) -l -d -o $@ $<
src/slghscan.cc: src/slghscan.l
	$(LEX) -L -o$@ $<
src/ruleparse.cc: src/ruleparse.y
	$(YACC) -p ruleparse -d -o $@ $<

src/slghparse.hh: src/slghparse.y src/slghparse.cc
src/slghscan.cc: src/slghparse.hh src/slgh_compile.hh
src/ruleparse.hh: src/ruleparse.y src/ruleparse.cc

.phony: clean
clean:
	rm -rf build
