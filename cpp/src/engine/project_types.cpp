// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// Saved function signatures for the offline backend.
//
// A Ghidra project stores each function's signature in its program db, and the
// live host hands it to the decompiler as a locked prototype built from the
// program's own data types. Offline, loadProject used to apply nothing but the
// function names, so every function read back as `void f()` and decompiled
// with guessed parameters. This file does what the host's decompiler interface
// does: it materialises the program's data types in the decompiler's
// TypeFactory (with the Ghidra data type id as the decompiler id) and installs
// every saved prototype.
//
// TypeFactory's direct setters (setFields, getTypeUnicode, getTypeCode(name))
// are private to its friends; the public door is decodeType(), which reads the
// same <type> stream the Java host sends. Composites, enums, function
// definitions and wide chars are therefore encoded and decoded.

#include "project_types.h"
#include "ghidra_project.h"
#include "libdecomp.hh"
#include "function_state.h"

#include <algorithm>
#include <functional>
#include <cstdio>
#include <set>
#include <sstream>
#include <vector>

using namespace ghidra;

namespace ghidra_standalone {
namespace {

using ghidra_db::DataTypeEntry;
using ghidra_db::DataTypeKind;

class TypeLoader {
 public:
  TypeLoader(Architecture* arch, const ghidra_db::ProgramTypes& db, TypeCategories& categories)
      : arch_(arch), tf_(arch->types), db_(db), categories_(categories) {}

  std::size_t made() const { return made_.size(); }

  // Undefined.isUndefined: DEFAULT, an UndefinedN built-in, or an array of them.
  bool isUndefined(int64_t id) const {
    for (int depth = 0; depth < 16; ++depth) {
      if (id == ghidra_db::DEFAULT_DATATYPE_ID || id == ghidra_db::NULL_DATATYPE_ID) return true;
      auto it = db_.types.find(id);
      if (it == db_.types.end()) return false;
      const DataTypeEntry& t = it->second;
      if (t.kind == DataTypeKind::ARRAY) {
        id = t.target;
        continue;
      }
      if (t.kind != DataTypeKind::BUILT_IN) return false;
      const std::string cls = t.class_name.substr(t.class_name.rfind('.') + 1);
      return cls.rfind("Undefined", 0) == 0 && cls.size() > 9 && cls[9] >= '1' && cls[9] <= '8';
    }
    return false;
  }
  std::size_t failures() const { return failures_; }

  // DataType.getLength() < 0 for a type that is not a FunctionDefinition: a
  // typedef (of a typedef ...) of a function definition.
  bool hasNoLength(int64_t id) const {
    bool through_typedef = false;
    for (int depth = 0; depth < 16; ++depth) {
      auto it = db_.types.find(id);
      if (it == db_.types.end()) return false;
      if (it->second.kind == DataTypeKind::FUNCTION_DEF) return through_typedef;
      if (it->second.kind != DataTypeKind::TYPEDEF) return false;
      through_typedef = true;
      id = it->second.target;
    }
    return false;
  }

  // The type of a defined data item (PcodeDataTypeManager.encodeType with the
  // item's length): a string is an array of characters, any other data-only
  // built-in an opaque type of its length. nullptr when it has no length.
  Datatype* dataItem(const ghidra_db::DataEntry& d) {
    auto it = db_.types.find(d.type_id);
    if (it != db_.types.end() && it->second.kind == DataTypeKind::BUILT_IN) {
      const DataTypeEntry& t = it->second;
      const std::string cls = t.class_name.substr(t.class_name.rfind('.') + 1);
      const int len = d.length;
      auto chars = [&](int unit) -> Datatype* {
        if (len < unit) return nullptr;
        return tf_->getTypeArray(len / unit, tf_->getTypeChar(unit));
      };
      if (cls == "StringDataType" || cls == "TerminatedStringDataType" ||
          cls == "StringUTF8DataType" || cls == "PascalStringDataType" ||
          cls == "PascalString255DataType")
        return chars(1);
      if (cls == "UnicodeDataType" || cls == "TerminatedUnicodeDataType" ||
          cls == "PascalUnicodeDataType")
        return chars(2);
      if (cls == "Unicode32DataType" || cls == "TerminatedUnicode32DataType") return chars(4);
      Datatype* known = get(d.type_id);
      if (known != undefined() || cls.rfind("Undefined", 0) == 0 || cls == "DefaultDataType")
        return known;
      // encodeOpaqueDataType: its own name, "unknown" below 16 bytes, an empty
      // struct from 16 on.
      if (len <= 0) return nullptr;
      const bool var_length = d.length > 0;
      if (len < 16 && !var_length) return tf_->getBase(len, TYPE_UNKNOWN, t.name);
      return decode([&](Encoder& e) {
        openType(e, t.name, d.type_id, len, len < 16 ? "unknown" : "struct");
        if (var_length) e.writeBool(ATTRIB_VARLENGTH, true);
        e.closeElement(ELEM_TYPE);
      });
    }
    if (d.type_id == ghidra_db::DEFAULT_DATATYPE_ID) return undefined();
    return get(d.type_id);
  }

  Datatype* get(int64_t id) {
    if (id == ghidra_db::DEFAULT_DATATYPE_ID || id == ghidra_db::NULL_DATATYPE_ID)
      return undefined();
    auto done = made_.find(id);
    if (done != made_.end()) return done->second != nullptr ? done->second : undefined();
    auto it = db_.types.find(id);
    if (it == db_.types.end()) {
      ++failures_;
      return undefined();
    }
    const DataTypeEntry& t = it->second;
    Datatype* dt = nullptr;
    try {
      switch (t.kind) {
        case DataTypeKind::BUILT_IN:
          dt = builtin(t);
          break;
        case DataTypeKind::POINTER: {
          const int size = t.length > 0 ? t.length : tf_->getSizeOfPointer();
          const uint4 ws = arch_->getDefaultDataSpace()->getWordSize();
          made_[id] = nullptr;  // cycle guard; composites break real cycles
          if (t.target == ghidra_db::NULL_DATATYPE_ID)
            dt = tf_->getTypePointer(size, undefined(), ws, "pointer");
          else if (hasNoLength(t.target))
            // PcodeDataTypeManager.encodePointer: a target with no length that is
            // not itself a function definition (a typedef of one) points at
            // undefined1, so a PEXCEPTION_ROUTINE variable is named puVar.
            dt = tf_->getTypePointer(size, tf_->getBase(1, TYPE_UNKNOWN), ws);
          else
            dt = tf_->getTypePointer(size, get(t.target), ws);
          break;
        }
        case DataTypeKind::TYPEDEF: {
          made_[id] = nullptr;
          Datatype* target = get(t.target);
          dt = tf_->getTypedef(target, t.name, static_cast<uint8>(id), 0);
          categories_[dt->getUnsizedId()] = db_.categoryPath(t.category);
          break;
        }
        case DataTypeKind::ARRAY: {
          Datatype* elem = get(t.target);
          dt = t.count > 0 ? static_cast<Datatype*>(tf_->getTypeArray(t.count, elem)) : elem;
          break;
        }
        case DataTypeKind::COMPOSITE:
          dt = composite(id, t);
          break;
        case DataTypeKind::FUNCTION_DEF:
          dt = functionDefinition(id, t);
          categories_[dt->getUnsizedId()] = db_.categoryPath(t.category);
          break;
        case DataTypeKind::ENUM:
          dt = enumeration(id, t);
          break;
        default:
          break;
      }
    } catch (LowlevelError& err) {
      std::fprintf(stderr, "[libghidra] project type '%s': %s\n", t.name.c_str(),
                   err.explain.c_str());
      dt = nullptr;
    } catch (DecoderError& err) {
      std::fprintf(stderr, "[libghidra] project type '%s': %s\n", t.name.c_str(),
                   err.explain.c_str());
      dt = nullptr;
    }
    if (dt == nullptr) {
      ++failures_;
      dt = undefined();
    }
    made_[id] = dt;
    return dt;
  }

 private:
  Architecture* arch_;
  TypeFactory* tf_;
  const ghidra_db::ProgramTypes& db_;
  TypeCategories& categories_;
  std::map<int64_t, Datatype*> made_;
  std::size_t failures_ = 0;

  // Ghidra's DataType.DEFAULT.
  Datatype* undefined() { return tf_->getBase(1, TYPE_UNKNOWN, "undefined"); }

  // Built-in types are identified by their Java class; sizes that depend on the
  // compiler come from the cspec's data organization, as they do in Ghidra.
  Datatype* builtin(const DataTypeEntry& t) {
    const std::string cls = t.class_name.substr(t.class_name.rfind('.') + 1);
    enum : int { kInt = -1, kLong = -2, kPtr = -3 };
    struct Prim {
      const char* cls;
      int size;
      type_metatype meta;
    };
    static const Prim kPrims[] = {
        {"IntegerDataType", kInt, TYPE_INT},
        {"UnsignedIntegerDataType", kInt, TYPE_UINT},
        {"LongDataType", kLong, TYPE_INT},
        {"UnsignedLongDataType", kLong, TYPE_UINT},
        {"ShortDataType", 2, TYPE_INT},
        {"UnsignedShortDataType", 2, TYPE_UINT},
        {"LongLongDataType", 8, TYPE_INT},
        {"UnsignedLongLongDataType", 8, TYPE_UINT},
        {"SignedCharDataType", 1, TYPE_INT},
        {"UnsignedCharDataType", 1, TYPE_UINT},
        {"ByteDataType", 1, TYPE_UINT},
        {"WordDataType", 2, TYPE_UINT},
        {"DWordDataType", 4, TYPE_UINT},
        {"QWordDataType", 8, TYPE_UINT},
        {"SignedByteDataType", 1, TYPE_INT},
        {"SignedWordDataType", 2, TYPE_INT},
        {"SignedDWordDataType", 4, TYPE_INT},
        {"SignedQWordDataType", 8, TYPE_INT},
        {"FloatDataType", 4, TYPE_FLOAT},
        {"DoubleDataType", 8, TYPE_FLOAT},
        {"Undefined1DataType", 1, TYPE_UNKNOWN},
        {"Undefined2DataType", 2, TYPE_UNKNOWN},
        {"Undefined3DataType", 3, TYPE_UNKNOWN},
        {"Undefined4DataType", 4, TYPE_UNKNOWN},
        {"Undefined5DataType", 5, TYPE_UNKNOWN},
        {"Undefined6DataType", 6, TYPE_UNKNOWN},
        {"Undefined7DataType", 7, TYPE_UNKNOWN},
        {"Undefined8DataType", 8, TYPE_UNKNOWN},
        {"UnsignedPointerSizedIntegerDataType", kPtr, TYPE_UINT},
        {"PointerSizedIntegerDataType", kPtr, TYPE_INT},
        {"Int8TDataType", 1, TYPE_INT},
        {"Int16TDataType", 2, TYPE_INT},
        {"Int32TDataType", 4, TYPE_INT},
        {"Int64TDataType", 8, TYPE_INT},
        {"UInt8TDataType", 1, TYPE_UINT},
        {"UInt16TDataType", 2, TYPE_UINT},
        {"UInt32TDataType", 4, TYPE_UINT},
        {"UInt64TDataType", 8, TYPE_UINT},
        {"GuidDataType", 16, TYPE_UNKNOWN},
    };
    if (cls == "VoidDataType") return tf_->getTypeVoid();
    if (cls == "CharDataType") return tf_->getTypeChar(tf_->getSizeOfChar());
    if (cls == "BooleanDataType") return tf_->getBase(1, TYPE_BOOL);
    if (cls == "WideCharDataType") return unicode(t.name, tf_->getSizeOfWChar());
    if (cls == "WideChar16DataType") return unicode(t.name, 2);
    if (cls == "WideChar32DataType") return unicode(t.name, 4);
    // An image-base-relative offset is a pointer typedef with settings the
    // decompiler does not model, so PcodeDataTypeManager.encodeTypeDef sends it
    // as a typedef of undefinedN: the decompiler casts it where it is used as a
    // number, as the host prints (ulonglong)(uint)hdr->VirtualAddress.
    if (cls == "IBO32DataType" || cls == "IBO64DataType")
      return tf_->getTypedef(tf_->getBase(cls == "IBO32DataType" ? 4 : 8, TYPE_UNKNOWN), t.name, 0, 0);
    if (cls == "PointerDataType")
      return tf_->getTypePointer(tf_->getSizeOfPointer(), undefined(),
                                 arch_->getDefaultDataSpace()->getWordSize(), t.name);
    for (const Prim& p : kPrims) {
      if (cls != p.cls) continue;
      const int size = p.size == kInt    ? tf_->getSizeOfInt()
                       : p.size == kLong ? tf_->getSizeOfLong()
                       : p.size == kPtr  ? tf_->getSizeOfPointer()
                                         : p.size;
      return tf_->getBase(size, p.meta, t.name);
    }
    // Data-only built-ins (strings, PE structures) never appear in a
    // signature; they stand in as "undefined".
    return nullptr;
  }

  template <class Write>
  Datatype* decode(Write&& write) {
    std::ostringstream os;
    {
      PackedEncode enc(os);
      write(enc);
    }
    std::istringstream is(os.str());
    PackedDecode dec(arch_);
    dec.ingestStream(is);
    return tf_->decodeType(dec);
  }

  static void openType(Encoder& e, const std::string& name, int64_t id, int size,
                       const char* meta) {
    e.openElement(ELEM_TYPE);
    e.writeString(ATTRIB_NAME, name);
    e.writeUnsignedInteger(ATTRIB_ID, static_cast<uint8>(id));
    e.writeSignedInteger(ATTRIB_SIZE, size);
    e.writeString(ATTRIB_METATYPE, meta);
  }

  Datatype* unicode(const std::string& name, int size) {
    return decode([&](Encoder& e) {
      e.openElement(ELEM_TYPE);
      e.writeString(ATTRIB_NAME, name);
      e.writeSignedInteger(ATTRIB_SIZE, size);
      e.writeString(ATTRIB_METATYPE, "int");
      e.writeBool(ATTRIB_UTF, true);
      e.closeElement(ELEM_TYPE);
    });
  }

  // PcodeDataTypeManager.encodeFunctionDefinition: a code type carrying the
  // definition's prototype (FunctionPrototype(FunctionSignature) with
  // voidInputIsVarargs), so a call through a pointer to it is typed and the
  // decompiler casts an argument of another function-pointer type.
  Datatype* functionDefinition(int64_t id, const DataTypeEntry& t) {
    made_[id] = nullptr;  // cycle guard: a parameter pointing back at this type
    FunctionDefinitionSpec spec;
    spec.name = t.name;
    spec.id = static_cast<uint8>(id);
    spec.output = t.return_type == ghidra_db::DEFAULT_DATATYPE_ID ? undefined() : get(t.return_type);
    auto it = db_.funcdef_params.find(id);
    if (it != db_.funcdef_params.end())
      for (const ghidra_db::FuncDefParam& p : it->second)
        spec.params.emplace_back(p.name, get(p.type_id));
    spec.calling_convention = t.calling_convention;
    spec.has_var_args = t.has_var_args;
    spec.no_return = t.no_return;
    return makeFunctionDefinition(arch_, spec);
  }

  Datatype* enumeration(int64_t id, const DataTypeEntry& t) {
    auto values = db_.enum_values.find(id);
    std::vector<std::pair<std::string, int64_t>> list;
    if (values != db_.enum_values.end()) list = values->second;
    Datatype* dt = makeEnumType(arch_, t.name, static_cast<uint8>(id), t.length, list);
    categories_[dt->getUnsizedId()] = db_.categoryPath(t.category);
    return dt;
  }

  // DataTypeComponent.getDefaultFieldName.
  static std::string defaultFieldName(const ghidra_db::ComponentEntry& c, bool is_union) {
    char buf[32];
    if (is_union)
      std::snprintf(buf, sizeof buf, "field%d", c.ordinal);
    else
      std::snprintf(buf, sizeof buf, "field_0x%x", c.offset);
    return buf;
  }

  // A bitfield component's data type id (BitFieldDBDataType.getId): bits 0-7
  // the declared size, 8-15 the bit offset within the component's storage,
  // 21-22 how the base type is named (1 typedef, 2 enum, 3 integer built-in,
  // 0 none: int), 24-55 the base type's index in its table. The effective
  // size is clamped to the base type (BitFieldDataType.getEffectiveBitSize).
  bool bitfield(const ghidra_db::ComponentEntry& c, Datatype*& base, int& first_bit, int& bits) {
    const uint64_t id = static_cast<uint64_t>(c.type_id);
    const int declared = static_cast<int>(id & 0xff);
    first_bit = static_cast<int>((id >> 8) & 0xff);
    const int kind = static_cast<int>((id >> 21) & 0x3);
    const uint64_t index = (id >> 24) & 0xffffffffULL;
    int64_t base_id = ghidra_db::NULL_DATATYPE_ID;
    if (index != 0xffffffffULL) {
      if (kind == 1) base_id = static_cast<int64_t>((uint64_t(DataTypeKind::TYPEDEF) << 56) | index);
      else if (kind == 2) base_id = static_cast<int64_t>((uint64_t(DataTypeKind::ENUM) << 56) | index);
      else if (kind == 3) base_id = static_cast<int64_t>(index);
    }
    base = base_id == ghidra_db::NULL_DATATYPE_ID ? nullptr : get(base_id);
    if (base == nullptr || base->getMetatype() == TYPE_UNKNOWN)
      base = tf_->getBase(tf_->getSizeOfInt(), TYPE_INT);  // IntegerDataType on failure
    bits = std::min(declared, 8 * base->getSize());
    return bits > 0;
  }

  Datatype* composite(int64_t id, const DataTypeEntry& t) {
    const char* meta = t.is_union ? "union" : "struct";
    // Stub first (size 0 = incomplete), so a field pointing back at this
    // composite resolves to it -- the same recursion rule the host relies on.
    Datatype* stub = decode([&](Encoder& e) {
      openType(e, t.name, id, 0, meta);
      e.closeElement(ELEM_TYPE);
    });
    made_[id] = stub;
    categories_[stub->getUnsizedId()] = db_.categoryPath(t.category);

    const int4 size = std::max(t.length, 1);
    struct Field {
      std::string name;
      int offset;
      Datatype* type;
      int ordinal;
      int first_bit = -1;  // a bitfield: least significant bit within `offset`
      int bits = 0;        // a bitfield: effective size in bits
    };
    std::vector<Field> fields;
    int4 align = 1;
    auto comps = db_.components.find(id);
    if (comps != db_.components.end()) {
      for (const ghidra_db::ComponentEntry& c : comps->second) {
        if (c.size <= 0) continue;  // flexible array members have no size
        if (ghidra_db::dataTypeKind(c.type_id) == DataTypeKind::BITFIELD) {
          // PcodeDataTypeManager.encodeStructure sends a struct's bitfields as
          // <bitfield>s; a union's are left out here.
          if (t.is_union) continue;
          Field f;
          if (!bitfield(c, f.type, f.first_bit, f.bits)) continue;
          f.name = c.name.empty() ? defaultFieldName(c, false) : c.name;
          f.offset = c.offset;
          f.ordinal = c.ordinal;
          fields.push_back(f);
          continue;
        }
        Datatype* ft = get(c.type_id);
        if (ft->getSize() == 0 || ft->getMetatype() == TYPE_VOID) continue;
        if (!t.is_union && c.offset + ft->getSize() > size) continue;
        const std::string name = c.name.empty() ? defaultFieldName(c, t.is_union) : c.name;
        fields.push_back({name, t.is_union ? 0 : c.offset, ft, c.ordinal});
        int4 a = ft->getAlignment();
        if (t.pack > 0) a = std::min(a, t.pack);  // explicit packing caps the alignment
        align = std::max(align, a);
      }
    }
    // Composite.getAlignment(): a composite without packing is byte aligned.
    if (t.pack < 0) align = 1;
    return decode([&](Encoder& e) {
      openType(e, t.name, id, size, meta);
      e.writeSignedInteger(ATTRIB_ALIGNMENT, align);
      for (const Field& f : fields) {
        if (f.first_bit >= 0) {
          e.openElement(ELEM_BITFIELD);
          e.writeString(ATTRIB_NAME, f.name);
          e.writeSignedInteger(ATTRIB_ID, f.ordinal);
          e.writeSignedInteger(ATTRIB_OFFSET, f.offset);
          e.writeSignedInteger(ATTRIB_FIRST, f.first_bit);
          e.writeSignedInteger(ATTRIB_SIZE, f.bits);
          f.type->encodeRef(e);
          e.closeElement(ELEM_BITFIELD);
          continue;
        }
        e.openElement(ELEM_FIELD);
        e.writeString(ATTRIB_NAME, f.name);
        e.writeSignedInteger(ATTRIB_OFFSET, f.offset);
        if (t.is_union) e.writeSignedInteger(ATTRIB_ID, f.ordinal);
        f.type->encodeRef(e);
        e.closeElement(ELEM_FIELD);
      }
      e.closeElement(ELEM_TYPE);
    });
  }
};

// The decompiler model for a Ghidra calling convention name. "unknown" (and
// any name this cspec lacks) becomes an UnknownProtoModel that behaves like the
// default model and keeps the name -- what the host's decompiler does.
ProtoModel* modelFor(Architecture* arch, const std::string& name) {
  if (name == "default") return arch->defaultfp;
  ProtoModel* model = arch->getModel(name);
  return model != nullptr ? model : arch->createUnknownModel(name);
}

// The decompiler address of one saved storage piece: the stack space for a
// stack offset (wrapped into the space), else the space of that name.
bool storageAddress(Architecture* arch, const ghidra_db::VarnodeEntry& v, Address& out) {
  if (v.space == "stack") {
    AddrSpace* stack = arch->getStackSpace();
    if (stack == nullptr) return false;
    out = Address(stack, stack->wrapOffset(static_cast<uintb>(v.offset)));
    return true;
  }
  AddrSpace* spc = arch->getSpaceByName(v.space);
  if (spc == nullptr) return false;
  out = Address(spc, static_cast<uintb>(v.offset));
  return true;
}

}  // namespace

namespace {

Datatype* decodeType(Architecture* arch, const std::function<void(Encoder&)>& write) {
  std::ostringstream os;
  {
    PackedEncode enc(os);
    write(enc);
  }
  std::istringstream is(os.str());
  PackedDecode dec(arch);
  dec.ingestStream(is);
  return arch->types->decodeType(dec);
}

}  // namespace

Datatype* makeFunctionDefinition(Architecture* arch, const FunctionDefinitionSpec& spec) {
  ProtoModel* model = spec.calling_convention == "default" || spec.calling_convention.empty()
                          ? arch->defaultfp
                          : arch->getModel(spec.calling_convention);
  if (model == nullptr) model = arch->defaultfp;  // CompilerSpec.matchConvention
  const bool void_input = spec.params.empty();
  Datatype* out = spec.output != nullptr ? spec.output : arch->types->getTypeVoid();
  return decodeType(arch, [&](Encoder& e) {
    e.openElement(ELEM_TYPE);
    e.writeString(ATTRIB_NAME, spec.name);
    if (spec.id != 0) e.writeUnsignedInteger(ATTRIB_ID, spec.id);  // else derived from the name
    e.writeSignedInteger(ATTRIB_SIZE, 1);
    e.writeString(ATTRIB_METATYPE, "code");
    e.openElement(ELEM_PROTOTYPE);
    if (model->getExtraPop() == ProtoModel::extrapop_unknown)
      e.writeString(ATTRIB_EXTRAPOP, "unknown");
    else
      e.writeSignedInteger(ATTRIB_EXTRAPOP, model->getExtraPop());
    e.writeString(ATTRIB_MODEL, spec.calling_convention.empty() ? "unknown" : spec.calling_convention);
    e.writeBool(ATTRIB_MODELLOCK, true);
    if (spec.has_var_args || void_input) e.writeBool(ATTRIB_DOTDOTDOT, true);
    if (void_input) e.writeBool(ATTRIB_VOIDLOCK, true);
    if (spec.no_return) e.writeBool(ATTRIB_NORETURN, true);
    e.openElement(ELEM_RETURNSYM);
    e.writeBool(ATTRIB_TYPELOCK, true);
    e.openElement(ELEM_ADDR);
    e.closeElement(ELEM_ADDR);
    out->encodeRef(e);
    e.closeElement(ELEM_RETURNSYM);
    e.openElement(ELEM_INTERNALLIST);
    for (const auto& [name, type] : spec.params) {
      e.openElement(ELEM_PARAM);
      if (!name.empty()) e.writeString(ATTRIB_NAME, name);
      e.writeBool(ATTRIB_TYPELOCK, true);
      e.writeBool(ATTRIB_NAMELOCK, !name.empty());
      e.openElement(ELEM_ADDR);
      e.closeElement(ELEM_ADDR);
      type->encodeRef(e);
      e.closeElement(ELEM_PARAM);
    }
    e.closeElement(ELEM_INTERNALLIST);
    e.closeElement(ELEM_PROTOTYPE);
    e.closeElement(ELEM_TYPE);
  });
}

Datatype* makeEnumType(Architecture* arch, const std::string& name, std::uint64_t id, int size,
                       const std::vector<std::pair<std::string, std::int64_t>>& values) {
  bool is_signed = false;
  for (const auto& nv : values)
    if (nv.second < 0) is_signed = true;
  return decodeType(arch, [&](Encoder& e) {
    e.openElement(ELEM_TYPE);
    e.writeString(ATTRIB_NAME, name);
    if (id != 0) e.writeUnsignedInteger(ATTRIB_ID, id);  // else derived from the name
    e.writeSignedInteger(ATTRIB_SIZE, size);
    e.writeString(ATTRIB_METATYPE, is_signed ? "enum_int" : "enum_uint");
    for (const auto& [member, value] : values) {
      e.openElement(ELEM_VAL);
      e.writeString(ATTRIB_NAME, member);
      e.writeSignedInteger(ATTRIB_VALUE, value);
      e.closeElement(ELEM_VAL);
    }
    e.closeElement(ELEM_TYPE);
  });
}

int enumLengthFor(const std::vector<std::pair<std::string, std::int64_t>>& values, int initial) {
  if (values.empty()) return std::max(1, initial);
  std::int64_t lo = values.front().second, hi = values.front().second;
  for (const auto& nv : values) {
    lo = std::min(lo, nv.second);
    hi = std::max(hi, nv.second);
  }
  const bool negative = lo < 0;
  int min_len = 8;
  for (int size = 1; size < 8; size *= 2) {
    const int bits = size * 8 - (negative ? 1 : 0);
    const std::int64_t max_possible = (std::int64_t(1) << bits) - 1;
    const std::int64_t min_possible = negative ? -(std::int64_t(1) << bits) : 0;
    if (lo >= min_possible && hi <= max_possible) {
      min_len = size;
      break;
    }
  }
  return std::max(min_len, initial);
}

ProjectSignatureStats applyProjectSignatures(Architecture* arch,
                                             const ghidra_db::ProjectData& data,
                                             TypeCategories& categories,
                                             ProjectFunctionState& state,
                                             std::map<std::uint64_t, Datatype*>* data_types) {
  ProjectSignatureStats stats;
  TypeLoader loader(arch, data.types, categories);
  for (const auto& entry : data.types.types) loader.get(entry.first);
  if (data_types != nullptr) {
    for (const ghidra_db::DataEntry& d : data.data) {
      try {
        if (Datatype* t = loader.dataItem(d)) (*data_types)[d.address] = t;
      } catch (LowlevelError& err) {
        std::fprintf(stderr, "[libghidra] data item at 0x%llx left untyped: %s\n",
                     static_cast<unsigned long long>(d.address), err.explain.c_str());
      }
    }
  }

  Scope* global = arch->symboltab->getGlobalScope();
  AddrSpace* code = arch->getDefaultCodeSpace();
  std::vector<const ghidra_db::SignatureEntry*> all;
  for (const ghidra_db::SignatureEntry& sig : data.signatures) all.push_back(&sig);
  for (const ghidra_db::ExternalRefEntry& ext : data.external_refs) all.push_back(&ext.signature);
  for (const ghidra_db::SignatureEntry* sigp : all) {
    const ghidra_db::SignatureEntry& sig = *sigp;
    Funcdata* fd = global->queryFunction(Address(code, sig.address));
    if (fd == nullptr) continue;
    FuncProto& proto = fd->getFuncProto();
    try {
      if (!sig.locked) {
        // DEFAULT signature: Ghidra lets the decompiler recover parameters,
        // under the function's own calling convention, locked unless it is
        // "unknown" (FunctionPrototype.grabFromFunction). Locking an unknown
        // model printed "WARNING: Unknown calling convention" in 25 thunks the
        // host prints without it.
        ProtoModel* model = modelFor(arch, sig.calling_convention);
        proto.setModel(model);
        proto.setModelLock(!model->isUnknown());
        state.default_models[sig.address] = model;
        if (sig.no_return) proto.setNoReturn(true);
        if (sig.is_inline) proto.setInline(true);
        ++stats.unlocked;
        continue;
      }
      SavedPrototype saved;
      PrototypePieces& pieces = saved.pieces;
      pieces.model = modelFor(arch, sig.calling_convention);
      pieces.name = fd->getName();
      pieces.outtype = loader.get(sig.return_type);
      for (const ghidra_db::ParameterEntry& p : sig.parameters) {
        pieces.intypes.push_back(loader.get(p.type_id));
        pieces.innames.push_back(p.name);
      }
      pieces.firstVarArgSlot = sig.has_var_args ? static_cast<int4>(sig.parameters.size()) : -1;
      // FunctionPrototype.grabFromFunction: a DEFAULT ("undefined") return type
      // is not locked, so the decompiler recovers it (e.g. as void).
      saved.output_locked = sig.return_type != ghidra_db::DEFAULT_DATATYPE_ID;
      // Custom storage: every piece must place, or the prototype falls back
      // to the calling convention's storage.
      if (sig.custom_storage) {
        saved.custom = true;
        for (const ghidra_db::ParameterEntry& p : sig.parameters) {
          Address a;
          if (p.storage.size() != 1 || !storageAddress(arch, p.storage[0], a)) {
            saved.custom = false;
            break;
          }
          saved.input_storage.push_back(a);
        }
        if (saved.custom && sig.return_storage.size() == 1 &&
            !storageAddress(arch, sig.return_storage[0], saved.output_storage))
          saved.custom = false;
        if (!saved.custom) {
          saved.input_storage.clear();
          std::fprintf(stderr, "[libghidra] custom storage of '%s' not placed; using its calling convention\n",
                       sig.name.c_str());
        }
      }
      if (sig.no_return) proto.setNoReturn(true);
      if (sig.is_inline) proto.setInline(true);
      installSavedPrototype(fd, saved);
      state.prototypes[sig.address] = std::move(saved);
      ++stats.locked;
    } catch (LowlevelError& err) {
      std::fprintf(stderr, "[libghidra] saved signature of '%s' not applied: %s\n",
                   sig.name.c_str(), err.explain.c_str());
    }
  }

  // Saved locals, resolved once: LocalSymbolMap.grabFromFunction locks every
  // name and every type that is not undefined.
  for (const ghidra_db::FunctionEntry& fn : data.functions) {
    for (const ghidra_db::LocalVariableEntry& local : fn.locals) {
      Address addr;
      if (local.storage.size() != 1 || !storageAddress(arch, local.storage[0], addr)) {
        ++state.skipped_locals;  // unassigned, joined or unknown-space storage
        continue;
      }
      SavedLocal saved;
      saved.name = local.name;
      saved.addr = addr;
      saved.type = local.type_id == ghidra_db::NULL_DATATYPE_ID
                       ? arch->types->getBase(local.storage[0].size, TYPE_UNKNOWN)
                       : loader.get(local.type_id);
      saved.type_locked = !loader.isUndefined(local.type_id);
      state.locals[fn.address].push_back(std::move(saved));
    }
  }
  stats.types = loader.made();
  stats.type_failures = loader.failures();
  return stats;
}

// The host sends every type-locked symbol with merge="false" (HighSymbol.isIsolated
// is "typelocked"), so the decompiler never speculatively merges another value into
// it: a locked parameter keeps its own variable when the function reuses its
// register for a result.
static void isolateTypeLockedParams(FuncProto& proto) {
  for (int4 i = 0; i < proto.numParams(); ++i) {
    ProtoParameter* param = proto.getParam(i);
    if (!param->isTypeLocked()) continue;
    try {
      if (Symbol* sym = param->getSymbol()) sym->setIsolated(true);
    } catch (LowlevelError&) {
      // an internal (symbol-less) parameter list: nothing to isolate
    }
  }
}

void installSavedPrototype(Funcdata* fd, const SavedPrototype& saved) {
  FuncProto& proto = fd->getFuncProto();
  if (!saved.custom) {
    PrototypePieces pieces = saved.pieces;
    pieces.name = fd->getName();
    proto.setPieces(pieces);
    if (!saved.output_locked) proto.setOutputLock(false);
    isolateTypeLockedParams(proto);
    return;
  }
  // The <prototype> the host sends for a custom-storage function: the model,
  // custom="true", and the return value at its own storage. FuncProto::decode
  // starts from clear flags, so carry no-return, inline and a call fixup over.
  Architecture* arch = fd->getArch();
  const int4 inject = proto.getInjectId();
  const bool no_return = proto.isNoReturn();
  const bool is_inline = proto.isInline() && inject < 0;
  std::ostringstream os;
  {
    PackedEncode e(os);
    e.openElement(ELEM_PROTOTYPE);
    e.writeString(ATTRIB_MODEL,
                  saved.pieces.model != nullptr ? saved.pieces.model->getName() : "default");
    e.writeBool(ATTRIB_MODELLOCK, true);
    if (saved.pieces.firstVarArgSlot >= 0) e.writeBool(ATTRIB_DOTDOTDOT, true);
    if (no_return) e.writeBool(ATTRIB_NORETURN, true);
    if (is_inline) e.writeBool(ATTRIB_INLINE, true);
    e.writeBool(ATTRIB_CUSTOM, true);
    e.openElement(ELEM_RETURNSYM);
    e.writeBool(ATTRIB_TYPELOCK, saved.output_locked);
    saved.output_storage.encode(e, saved.pieces.outtype->getSize());
    saved.pieces.outtype->encodeRef(e);
    e.closeElement(ELEM_RETURNSYM);
    e.closeElement(ELEM_PROTOTYPE);
  }
  std::istringstream is(os.str());
  PackedDecode dec(arch);
  dec.ingestStream(is);
  proto.decode(dec, arch);
  if (inject >= 0) proto.setInjectId(inject);

  // The parameters are the function scope's parameter symbols
  // (ProtoStoreSymbol::setInput), each at its own storage.
  proto.clearInput();
  ScopeLocal* scope = fd->getScopeLocal();
  for (size_t i = 0; i < saved.input_storage.size() && i < saved.pieces.intypes.size(); ++i) {
    const Address& addr = saved.input_storage[i];
    const Address usepoint =
        addr.getSpace() == arch->getStackSpace() ? Address() : fd->getAddress() + (-1);
    const std::string& name = i < saved.pieces.innames.size() ? saved.pieces.innames[i] : "";
    Symbol* sym = scope->addSymbol(name, saved.pieces.intypes[i], addr, usepoint)->getSymbol();
    scope->setCategory(sym, Symbol::function_parameter, static_cast<int4>(i));
    scope->setAttribute(sym, Varnode::typelock | Varnode::namelock);
    sym->setIsolated(true);
  }
  proto.setInputLock(true);
}

void prepareSavedFunction(Funcdata* fd, const ProjectFunctionState& state) {
  const uint64_t entry = fd->getAddress().getOffset();
  auto proto = state.prototypes.find(entry);
  if (proto != state.prototypes.end()) {
    installSavedPrototype(fd, proto->second);
  } else {
    auto model = state.default_models.find(entry);
    if (model != state.default_models.end() && !fd->getFuncProto().isInputLocked()) {
      fd->getFuncProto().setModel(model->second);
      fd->getFuncProto().setModelLock(!model->second->isUnknown());
    }
  }
  auto locals = state.locals.find(entry);
  ScopeLocal* scope = fd->getScopeLocal();
  if (locals == state.locals.end() || scope == nullptr) return;
  bool name_only = false;
  for (const SavedLocal& local : locals->second) {
    // A type-locked local survives clearAnalysis; only re-add what it dropped.
    if (scope->findAddr(local.addr, Address()) != nullptr) continue;
    Symbol* sym = scope->addSymbol(local.name, local.type, local.addr, Address())->getSymbol();
    scope->setAttribute(sym, local.type_locked ? (Varnode::namelock | Varnode::typelock)
                                               : Varnode::namelock);
    if (local.type_locked) sym->setIsolated(true);
    name_only = name_only || !local.type_locked;
  }
  if (!name_only) return;
  // A name-locked, type-unlocked local is only a name for whatever variable
  // the decompiler finds there: ScopeLocal::decode turns such symbols into
  // name recommendations (collectNameRecs), which is how the host's <localdb>
  // lands. Without it startProcessing's clearUnlocked drops them unnamed.
  // Decoding an empty symbol list runs exactly that step.
  std::ostringstream os;
  {
    PackedEncode enc(os);
    enc.openElement(ELEM_SYMBOLLIST);
    enc.closeElement(ELEM_SYMBOLLIST);
  }
  std::istringstream is(os.str());
  PackedDecode dec(fd->getArch());
  dec.ingestStream(is);
  scope->decode(dec);
}

std::string ghidraTypeName(Datatype* type, int pointer_size) {
  if (type->getMetatype() == TYPE_PTR && type->getName().empty()) {
    auto* ptr = static_cast<TypePointer*>(type);
    std::string name = ghidraTypeName(ptr->getPtrTo(), pointer_size) + " *";
    if (ptr->getSize() != pointer_size) name += std::to_string(ptr->getSize() * 8);
    return name;
  }
  if (type->getMetatype() == TYPE_ARRAY && type->getName().empty()) {
    auto* arr = static_cast<TypeArray*>(type);
    std::string elem = ghidraTypeName(arr->getBase(), pointer_size);
    const std::string dim = "[" + std::to_string(arr->numElements()) + "]";
    const size_t bracket = elem.find('[');
    if (arr->getBase()->getMetatype() == TYPE_ARRAY && bracket != std::string::npos)
      return elem.substr(0, bracket) + dim + elem.substr(bracket);  // outer dimension first
    return elem + dim;
  }
  return type->getName();
}

std::string ghidraTypePath(Datatype* type, int pointer_size, const TypeCategories* categories) {
  Datatype* base = type;
  while (base->getName().empty()) {
    if (base->getMetatype() == TYPE_PTR)
      base = static_cast<TypePointer*>(base)->getPtrTo();
    else if (base->getMetatype() == TYPE_ARRAY)
      base = static_cast<TypeArray*>(base)->getBase();
    else
      break;
  }
  std::string category = "/";
  if (categories != nullptr) {
    auto it = categories->find(base->getUnsizedId());
    if (it != categories->end()) category = it->second;
  }
  return (category == "/" ? "/" : category + "/") + ghidraTypeName(type, pointer_size);
}

}  // namespace ghidra_standalone
