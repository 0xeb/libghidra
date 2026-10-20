// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// Host core data-types for the offline decompiler.
//
// The live host starts its decompiler with a <coretypes> element built by
// PcodeDataTypeManager.generateCoreTypes: Ghidra's own names (`int`, `uint`,
// `undefined4`, `longlong`, `wchar_t` ...) sized by the program's data
// organization. The standalone SleighArchitecture, given no such element,
// falls back to a fixed dialect (`int4`, `uint4`, `xunknown4`, `int8` ...),
// which is what every inferred local and temporary printed offline. The
// sizes come from the compiler spec, which is only parsed during init(), so
// the list is built in an overridden buildCoreTypes() rather than handed in.

#include "core_types.h"
#include "program_listing.h"

#include <map>
#include <sstream>

#include "libdecomp.hh"
#include "raw_arch.hh"

using namespace ghidra;

namespace ghidra_standalone {

std::vector<CoreTypeSpec> hostCoreTypes(const DataOrganizationSizes& org) {
  std::vector<CoreTypeSpec> out;
  out.push_back({"void", 0, "void"});
  for (int size = 1; size <= 8; ++size)
    out.push_back({"undefined" + std::to_string(size), size, "unknown"});

  // AbstractIntegerDataType.getSigned/UnsignedDataTypes: the fixed-size types
  // by size (index = size - 1, plus the 16-byte one), with the C names put in
  // their size slots in the order long long, long, short, int.
  std::vector<std::string> sgn = {"sbyte", "sword", "int3", "sdword", "int5", "int6", "int7", "sqword"};
  std::vector<std::string> uns = {"byte", "word", "uint3", "dword", "uint5", "uint6", "uint7", "qword"};
  auto put = [](std::vector<std::string>& names, int size, const char* name) {
    if (size >= 1 && size <= 8) names[size - 1] = name;
  };
  put(sgn, org.long_long_size, "longlong");
  put(uns, org.long_long_size, "ulonglong");
  put(sgn, org.long_size, "long");
  put(uns, org.long_size, "ulong");
  put(sgn, org.short_size, "short");
  put(uns, org.short_size, "ushort");
  put(sgn, org.int_size, "int");
  put(uns, org.int_size, "uint");
  for (int i = 0; i < 8; ++i) out.push_back({sgn[i], i + 1, "int"});
  out.push_back({"int16", 16, "int"});
  for (int i = 0; i < 8; ++i) out.push_back({uns[i], i + 1, "uint"});
  out.push_back({"uint16", 16, "uint"});

  // AbstractFloatDataType.getFloatDataTypes: float, double and long double at
  // their sizes, then the generic floatN types for every size still free.
  std::map<int, std::string> floats;
  floats.emplace(org.float_size, "float");
  floats.emplace(org.double_size, "double");
  floats.emplace(org.long_double_size, "longdouble");
  for (int size : {2, 4, 8, 10, 16}) floats.emplace(size, "float" + std::to_string(size));
  for (const auto& [size, name] : floats) out.push_back({name, size, "float"});

  out.push_back({"code", 1, "code"});
  CoreTypeSpec ch{"char", org.char_size, org.signed_char ? "int" : "uint"};
  (org.char_size == 1 ? ch.is_char : ch.is_utf) = true;
  out.push_back(ch);
  out.push_back({"wchar_t", org.wchar_size, "int", false, true});
  if (org.wchar_size != 2) out.push_back({"wchar16", 2, "int", false, true});
  if (org.wchar_size != 4) out.push_back({"wchar32", 4, "int", false, true});
  out.push_back({"bool", 1, "bool"});
  return out;
}

namespace {

// Datatype::hashName (protected there): the id TypeFactory::getBase(size,
// meta, name) gives a named base type, and so the id a program's built-in
// `int` gets when project_types loads it. Void and code need an explicit id.
uint8 nameHash(const std::string& name) {
  uint8 res = 123;
  for (char c : name) {
    res = (res << 8) | (res >> 56);
    res += static_cast<uint8>(c);  // sign-extends like (uint8)nm[i] there
    if ((res & 1) == 0) res ^= 0xfeabfeab;
  }
  return res | 0xC000000000000000ULL;
}

// DataOrganizationImpl.restoreXml over the compiler spec's element.
DataOrganizationSizes readDataOrganization(DocumentStorage& store) {
  DataOrganizationSizes org;
  const Element* cspec = store.getTag("compiler_spec");
  if (cspec == nullptr) return org;
  for (const Element* el : cspec->getChildren()) {
    if (el->getName() != "data_organization") continue;
    for (const Element* item : el->getChildren()) {
      const std::string& name = item->getName();
      for (int4 i = 0; i < item->getNumAttributes(); ++i) {
        const std::string& attr = item->getAttributeName(i);
        const std::string& value = item->getAttributeValue(i);
        if (name == "char_type" && attr == "signed") {
          org.signed_char = value == "true" || value == "1" || value == "yes";
          continue;
        }
        if (attr != "value") continue;
        int v = 0;
        std::istringstream(value) >> v;
        if (name == "char_size") org.char_size = v;
        else if (name == "wchar_size") org.wchar_size = v;
        else if (name == "short_size") org.short_size = v;
        else if (name == "integer_size") org.int_size = v;
        else if (name == "long_size") org.long_size = v;
        else if (name == "long_long_size") org.long_long_size = v;
        else if (name == "float_size") org.float_size = v;
        else if (name == "double_size") org.double_size = v;
        else if (name == "long_double_size") org.long_double_size = v;
      }
    }
  }
  return org;
}

class HostCoreTypesArchitecture : public RawBinaryArchitecture {
 public:
  using RawBinaryArchitecture::RawBinaryArchitecture;

 protected:
  // The global scope answers what the host's scope answers lazily (code
  // labels inside functions, undefined read-only constants).
  Scope* buildDatabase(DocumentStorage& store) override {
    symboltab = new Database(this, true);
    Scope* globscope = newListingScope(this);
    symboltab->attachScope(globscope, nullptr);
    return globscope;
  }

  void buildCoreTypes(DocumentStorage& store) override {
    if (store.getTag("coretypes") != nullptr) {  // an explicit list wins
      SleighArchitecture::buildCoreTypes(store);
      return;
    }
    // Encode the list and decode it through decodeCoreTypes: the host's path.
    std::ostringstream os;
    {
      PackedEncode enc(os);
      enc.openElement(ELEM_CORETYPES);
      for (const CoreTypeSpec& t : hostCoreTypes(readDataOrganization(store))) {
        enc.openElement(ELEM_TYPE);
        enc.writeString(ATTRIB_NAME, t.name);
        enc.writeSignedInteger(ATTRIB_SIZE, t.size);
        enc.writeString(ATTRIB_METATYPE, t.metatype);
        if (t.is_char) enc.writeBool(ATTRIB_CHAR, true);
        if (t.is_utf) enc.writeBool(ATTRIB_UTF, true);
        enc.writeUnsignedInteger(ATTRIB_ID, nameHash(t.name));
        enc.closeElement(ELEM_TYPE);
      }
      enc.closeElement(ELEM_CORETYPES);
    }
    std::istringstream is(os.str());
    PackedDecode dec(this);
    dec.ingestStream(is);
    types->decodeCoreTypes(dec);  // clear() is harmless here: nothing is built yet
  }
};

}  // namespace

Architecture* buildRawArchitecture(const std::string& filename, const std::string& target,
                                   std::ostream* errors) {
  return new HostCoreTypesArchitecture(filename, target, errors);
}

void registerTypeNameAliases(Architecture* arch) {
  TypeFactory* tf = arch->types;
  // The host core type of a size and kind: typecache lookups prefer `char`
  // for a one-byte int, so pick by name from the core list instead.
  auto core = [&](const char* name) { return tf->findByName(name); };
  auto wide = [&](int size) -> Datatype* {
    try {
      return tf->getTypeChar(size);
    } catch (LowlevelError&) {
      return nullptr;  // no core character type of that size
    }
  };
  auto sized = [&](int size, type_metatype meta) -> Datatype* {
    Datatype* found = nullptr;
    // Host names first; the standalone dialect last, for an architecture that
    // kept it (an XML image's architecture builds its own core types).
    const char* sgn[] = {"sbyte", "short", "int", "long", "longlong", "sword", "sdword", "sqword",
                         "int3", "int5", "int6", "int7", "int16",
                         "int1", "int2", "int4", "int8"};
    const char* uns[] = {"byte", "ushort", "uint", "ulong", "ulonglong", "word", "dword", "qword",
                         "uint3", "uint5", "uint6", "uint7", "uint16",
                         "uint1", "uint2", "uint4", "uint8"};
    for (const char* n : meta == TYPE_INT ? sgn : uns) {
      Datatype* dt = tf->findByName(n);
      if (dt != nullptr && dt->getSize() == size && dt->isCoreType()) {
        found = dt;
        break;
      }
    }
    return found;
  };
  struct Alias {
    const char* name;
    Datatype* target;
  };
  const Alias aliases[] = {
      // The standalone dialect.
      {"int1", sized(1, TYPE_INT)},
      {"int2", sized(2, TYPE_INT)},
      {"int4", sized(4, TYPE_INT)},
      {"int8", sized(8, TYPE_INT)},
      {"uint1", sized(1, TYPE_UINT)},
      {"uint2", sized(2, TYPE_UINT)},
      {"uint4", sized(4, TYPE_UINT)},
      {"uint8", sized(8, TYPE_UINT)},
      {"float4", tf->getBase(4, TYPE_FLOAT)},
      {"float8", tf->getBase(8, TYPE_FLOAT)},
      {"xunknown1", core("undefined1")},
      {"xunknown2", core("undefined2")},
      {"xunknown4", core("undefined4")},
      {"xunknown8", core("undefined8")},
      {"wchar2", wide(2)},
      {"wchar4", wide(4)},
      // C spellings, sized by the data organization.
      {"int", sized(tf->getSizeOfInt(), TYPE_INT)},
      {"short", sized(2, TYPE_INT)},
      {"unsigned int", sized(tf->getSizeOfInt(), TYPE_UINT)},
      {"unsigned short", sized(2, TYPE_UINT)},
      {"long", sized(tf->getSizeOfLong(), TYPE_INT)},
      {"unsigned long", sized(tf->getSizeOfLong(), TYPE_UINT)},
      {"long long", sized(8, TYPE_INT)},
      {"unsigned long long", sized(8, TYPE_UINT)},
      {"signed char", sized(1, TYPE_INT)},
      {"unsigned char", sized(1, TYPE_UINT)},
  };
  for (const Alias& a : aliases) {
    if (a.target != nullptr && tf->findByName(a.name) == nullptr)
      tf->getTypedef(a.target, a.name, 0, 0);
  }
}

}  // namespace ghidra_standalone
