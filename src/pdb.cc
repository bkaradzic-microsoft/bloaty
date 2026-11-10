// Copyright 2026 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Support for reading Microsoft Program Database (PDB) files, which hold the
// debug information for PE binaries produced by MSVC, clang-cl and lld-link.
//
// A PDB is never analyzed on its own; it is used as the debug file for a PE
// binary (matched by GUID and age, see GetBuildId()), and provides the
// "symbols" and "compileunits" data sources for it.

#include "PDB.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include "PDB_CoalescedMSFStream.h"
#include "PDB_DBIStream.h"
#include "PDB_GlobalSymbolStream.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_InfoStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleSymbolStream.h"
#include "PDB_PublicSymbolStream.h"
#include "PDB_RawFile.h"
#include "PDB_SectionContributionStream.h"
#include "bloaty.h"
#include "util.h"

using std::string_view;

namespace bloaty {
namespace pdb {

// The MSF 7.00 superblock magic: "Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0".
constexpr char kMagic[] =
    "Microsoft C/C++ MSF 7.00\r\n\x1a"
    "DS\0\0";
constexpr size_t kMagicSize = sizeof(kMagic);  // Includes the implicit NUL.
static_assert(kMagicSize == 32, "PDB magic must be 32 bytes");

bool IsPdb(string_view data) {
  return data.size() >= kMagicSize &&
         memcmp(data.data(), kMagic, kMagicSize) == 0;
}

// Owns the raw PDB view and the streams shared by all of the readers below.
class PdbFile {
 public:
  explicit PdbFile(string_view data)
      : raw_(Open(data)),
        dbi_(PDB::CreateDBIStream(raw_)),
        sections_(CreateImageSectionStream()) {}

  const PDB::RawFile& raw() const { return raw_; }
  const PDB::DBIStream& dbi() const { return dbi_; }

  // Converts a one-based section index + offset to an RVA.  Returns 0 if the
  // location does not map into the image.
  uint32_t ToRva(uint16_t section, uint32_t offset) const {
    return sections_.ConvertSectionOffsetToRVA(section, offset);
  }

  // Returns the end RVA of the image section containing |rva|, or 0.
  uint32_t SectionEnd(uint32_t rva) const {
    for (const auto& section : sections_.GetImageSections()) {
      uint32_t begin = section.VirtualAddress;
      uint32_t size =
          std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
      if (rva >= begin && rva - begin < size) {
        return begin + size;
      }
    }
    return 0;
  }

 private:
  static PDB::RawFile Open(string_view data) {
    if (PDB::ValidateFile(data.data(), data.size()) !=
        PDB::ErrorCode::Success) {
      THROW("invalid or corrupt PDB file");
    }
    PDB::RawFile raw = PDB::CreateRawFile(data.data());
    if (PDB::HasValidDBIStream(raw) != PDB::ErrorCode::Success) {
      THROW("PDB file has no valid DBI stream");
    }
    return raw;
  }

  PDB::ImageSectionStream CreateImageSectionStream() const {
    if (dbi_.HasValidImageSectionStream(raw_) != PDB::ErrorCode::Success) {
      THROW("PDB file has no valid image section stream");
    }
    return dbi_.CreateImageSectionStream(raw_);
  }

  PDB::RawFile raw_;
  PDB::DBIStream dbi_;
  PDB::ImageSectionStream sections_;
};

std::string GetBuildId(string_view data) {
  // Matches the CodeView (RSDS) record in the PE debug directory: the 16-byte
  // GUID followed by the 32-bit age.  The age recorded in the DBI stream is the
  // one that the linker writes to the image; the PDB info stream age may be
  // bumped by later tools without relinking.
  PDB::RawFile raw = PDB::CreateRawFile(data.data());
  const PDB::InfoStream info(raw);
  uint32_t age = info.GetHeader()->age;
  if (PDB::HasValidDBIStream(raw) == PDB::ErrorCode::Success) {
    age = PDB::CreateDBIStream(raw).GetHeader().age;
  }

  std::string build_id(sizeof(PDB::GUID) + sizeof(age), '\0');
  memcpy(&build_id[0], &info.GetHeader()->guid, sizeof(PDB::GUID));
  memcpy(&build_id[sizeof(PDB::GUID)], &age, sizeof(age));
  return build_id;
}

struct Contribution {
  uint32_t rva;
  uint32_t size;
  uint16_t module;
};

// Section contributions, sorted by RVA.  Each one is a range of the image that
// the linker took from a single object file (one COMDAT, or one section of a
// .obj), so they are a natural upper bound for symbols with unknown sizes.
std::vector<Contribution> ReadContributions(const PdbFile& pdb) {
  std::vector<Contribution> ret;
  if (pdb.dbi().HasValidSectionContributionStream(pdb.raw()) !=
      PDB::ErrorCode::Success) {
    return ret;
  }
  const PDB::SectionContributionStream stream =
      pdb.dbi().CreateSectionContributionStream(pdb.raw());
  for (const auto& contribution : stream.GetContributions()) {
    if (contribution.size == 0) continue;
    uint32_t rva = pdb.ToRva(contribution.section, contribution.offset);
    if (rva == 0) continue;
    ret.push_back({rva, contribution.size, contribution.moduleIndex});
  }
  std::sort(ret.begin(), ret.end(),
            [](const Contribution& a, const Contribution& b) {
              return a.rva < b.rva;
            });
  return ret;
}

const Contribution* FindContribution(
    const std::vector<Contribution>& contributions, uint32_t rva) {
  auto it = std::upper_bound(
      contributions.begin(), contributions.end(), rva,
      [](uint32_t rva, const Contribution& c) { return rva < c.rva; });
  if (it == contributions.begin()) return nullptr;
  --it;
  return rva - it->rva < it->size ? &*it : nullptr;
}

std::string ModuleName(const PDB::ModuleInfoStream::Module& module) {
  // For object files that were pulled out of a static library this is the
  // name of the member; the library itself is GetObjectName().
  return std::string(module.GetName().Decay());
}

// Symbol name candidates, in order of preference when several symbols share
// the same address (e.g. after identical COMDAT folding).
enum class NameRank {
  kMangledPublic = 0,  // "?foo@@YAXH@Z": demangles to the full signature.
  kProcedure = 1,      // "foo" from S_GPROC32/S_LPROC32, has an exact size.
  kData = 2,           // S_GDATA32/S_LDATA32/S_GTHREAD32/S_LTHREAD32.
  kPublic = 3,         // Undecorated public, e.g. "_foo" on x86.
  kThunk = 4,
};

struct Symbol {
  std::string name;
  NameRank rank;
  uint32_t size;  // 0 if unknown.
};

class SymbolCollector {
 public:
  void Add(uint32_t rva, const char* name, NameRank rank, uint32_t size = 0) {
    if (rva == 0 || name == nullptr || name[0] == '\0') return;
    auto [it, inserted] = symbols_.try_emplace(rva, Symbol{name, rank, size});
    if (inserted) return;
    Symbol& existing = it->second;
    existing.size = std::max(existing.size, size);
    if (rank < existing.rank ||
        (rank == existing.rank && existing.name.compare(name) > 0)) {
      existing.name = name;
      existing.rank = rank;
    }
  }

  const std::map<uint32_t, Symbol>& symbols() const { return symbols_; }

 private:
  std::map<uint32_t, Symbol> symbols_;
};

void AddSymbolRecord(const PdbFile& pdb, const PDB::CodeView::DBI::Record* rec,
                     SymbolCollector* out) {
  using PDB::CodeView::DBI::SymbolRecordKind;
  const auto& d = rec->data;
  switch (rec->header.kind) {
    case SymbolRecordKind::S_PUB32: {
      const char* name = d.S_PUB32.name;
      out->Add(pdb.ToRva(d.S_PUB32.section, d.S_PUB32.offset), name,
               name[0] == '?' ? NameRank::kMangledPublic : NameRank::kPublic);
      break;
    }
    case SymbolRecordKind::S_GPROC32:
    case SymbolRecordKind::S_LPROC32:
    case SymbolRecordKind::S_GPROC32_ID:
    case SymbolRecordKind::S_LPROC32_ID:
      out->Add(pdb.ToRva(d.S_GPROC32.section, d.S_GPROC32.offset),
               d.S_GPROC32.name, NameRank::kProcedure, d.S_GPROC32.codeSize);
      break;
    case SymbolRecordKind::S_GDATA32:
    case SymbolRecordKind::S_LDATA32:
    case SymbolRecordKind::S_GTHREAD32:
    case SymbolRecordKind::S_LTHREAD32:
      out->Add(pdb.ToRva(d.S_GDATA32.section, d.S_GDATA32.offset),
               d.S_GDATA32.name, NameRank::kData);
      break;
    case SymbolRecordKind::S_THUNK32:
      out->Add(pdb.ToRva(d.S_THUNK32.section, d.S_THUNK32.offset),
               d.S_THUNK32.name, NameRank::kThunk, d.S_THUNK32.length);
      break;
    case SymbolRecordKind::S_TRAMPOLINE:
      out->Add(
          pdb.ToRva(d.S_TRAMPOLINE.thunkSection, d.S_TRAMPOLINE.thunkOffset),
          "[Incremental Linking Thunk]", NameRank::kThunk, d.S_TRAMPOLINE.size);
      break;
    default:
      break;
  }
}

void ReadSymbols(string_view data, RangeSink* sink) {
  PdbFile pdb(data);
  SymbolCollector collector;

  if (pdb.dbi().HasValidSymbolRecordStream(pdb.raw()) ==
      PDB::ErrorCode::Success) {
    const PDB::CoalescedMSFStream records =
        pdb.dbi().CreateSymbolRecordStream(pdb.raw());

    if (pdb.dbi().HasValidPublicSymbolStream(pdb.raw()) ==
        PDB::ErrorCode::Success) {
      const PDB::PublicSymbolStream publics =
          pdb.dbi().CreatePublicSymbolStream(pdb.raw());
      for (const auto& hash_record : publics.GetRecords()) {
        AddSymbolRecord(pdb, publics.GetRecord(records, hash_record),
                        &collector);
      }
    }

    if (pdb.dbi().HasValidGlobalSymbolStream(pdb.raw()) ==
        PDB::ErrorCode::Success) {
      const PDB::GlobalSymbolStream globals =
          pdb.dbi().CreateGlobalSymbolStream(pdb.raw());
      for (const auto& hash_record : globals.GetRecords()) {
        AddSymbolRecord(pdb, globals.GetRecord(records, hash_record),
                        &collector);
      }
    }
  }

  // Module symbol streams hold the procedure records (with exact code sizes)
  // and file-static data that does not appear in the global streams.
  const PDB::ModuleInfoStream modules =
      pdb.dbi().CreateModuleInfoStream(pdb.raw());
  for (const auto& module : modules.GetModules()) {
    if (!module.HasSymbolStream()) continue;
    const PDB::ModuleSymbolStream stream = module.CreateSymbolStream(pdb.raw());
    stream.ForEachSymbol([&](const PDB::CodeView::DBI::Record* rec) {
      AddSymbolRecord(pdb, rec, &collector);
    });
  }

  const std::vector<Contribution> contributions = ReadContributions(pdb);
  const auto& symbols = collector.symbols();
  for (auto it = symbols.begin(); it != symbols.end(); ++it) {
    uint32_t rva = it->first;
    const Symbol& symbol = it->second;
    uint64_t size = symbol.size;

    if (size == 0) {
      // Data and public symbols carry no size.  Extend the symbol up to the
      // next symbol, without crossing the end of the object file
      // contribution (or, failing that, the section) that it lives in.
      uint64_t end = std::numeric_limits<uint64_t>::max();
      auto next = std::next(it);
      if (next != symbols.end()) end = next->first;
      if (const Contribution* c = FindContribution(contributions, rva)) {
        end = std::min<uint64_t>(end, uint64_t{c->rva} + c->size);
      } else if (uint32_t section_end = pdb.SectionEnd(rva)) {
        end = std::min<uint64_t>(end, section_end);
      }
      if (end == std::numeric_limits<uint64_t>::max() || end <= rva) continue;
      size = end - rva;
    }

    sink->AddVMRangeAllowAlias(
        "pdb_symbols", rva, size,
        ItaniumDemangle(symbol.name, sink->data_source()));
  }
}

void ReadCompileUnits(string_view data, RangeSink* sink) {
  PdbFile pdb(data);
  const PDB::ModuleInfoStream modules =
      pdb.dbi().CreateModuleInfoStream(pdb.raw());
  const auto module_list = modules.GetModules();

  std::vector<std::string> names;
  names.reserve(module_list.GetLength());
  for (const auto& module : module_list) {
    names.push_back(ModuleName(module));
  }

  for (const Contribution& c : ReadContributions(pdb)) {
    if (c.module >= names.size()) continue;
    sink->AddVMRangeIgnoreDuplicate("pdb_contributions", c.rva, c.size,
                                    names[c.module]);
  }
}

class PdbObjectFile : public ObjectFile {
 public:
  PdbObjectFile(std::unique_ptr<InputFile> file, std::string build_id)
      : ObjectFile(std::move(file)), build_id_(std::move(build_id)) {}

  std::string GetBuildId() const override { return build_id_; }

  void ProcessFile(const std::vector<RangeSink*>&) const override {
    THROW(
        "PDB files cannot be analyzed directly; pass the PE binary and use "
        "--debug-file=<file.pdb>");
  }

  bool GetDisassemblyInfo(string_view, DataSource,
                          DisassemblyInfo*) const override {
    return false;
  }

 private:
  std::string build_id_;
};

}  // namespace pdb

bool IsPDBFile(string_view data) { return pdb::IsPdb(data); }

void ReadPDBSymbols(string_view pdb_data, RangeSink* sink) {
  pdb::ReadSymbols(pdb_data, sink);
}

void ReadPDBCompileUnits(string_view pdb_data, RangeSink* sink) {
  pdb::ReadCompileUnits(pdb_data, sink);
}

std::unique_ptr<ObjectFile> TryOpenPDBFile(std::unique_ptr<InputFile>& file) {
  string_view data = file->data();
  if (!pdb::IsPdb(data) ||
      PDB::ValidateFile(data.data(), data.size()) != PDB::ErrorCode::Success) {
    return nullptr;
  }
  std::string build_id = pdb::GetBuildId(data);
  return std::make_unique<pdb::PdbObjectFile>(std::move(file),
                                              std::move(build_id));
}

}  // namespace bloaty
