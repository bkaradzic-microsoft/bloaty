// Copyright 2021 Google Inc. All Rights Reserved.
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

#include "absl/strings/substitute.h"
#include "bloaty.h"
#include "util.h"

using std::string;
using std::string_view;

namespace bloaty {
namespace pe {
constexpr uint16_t dos_magic = 0x5A4D;  // MZ

// From LIEF/include/LIEF/PE/Structures.hpp.in
//! Sizes in bytes of various things in the COFF format.
[[maybe_unused]] constexpr size_t kHeader16Size = 20;
[[maybe_unused]] constexpr size_t kHeader32Size = 56;
constexpr size_t kNameSize = 8;
constexpr size_t kSymbol16Size = 18;
[[maybe_unused]] constexpr size_t kSymbol32Size = 20;
constexpr size_t kSectionSize = 40;
constexpr size_t kRelocationSize = 10;
constexpr size_t kBaseRelocationBlockSize = 8;
constexpr size_t kImportDirectoryTableEntrySize = 20;
constexpr size_t kResourceDirectoryTableSize = 16;
constexpr size_t kResourceDirectoryEntriesSize = 8;
constexpr size_t kResourceDataEntrySize = 16;

#include "third_party/lief_pe/pe_enums.h"
#include "third_party/lief_pe/pe_structures.h"

static_assert(kSectionSize == sizeof(pe_section),
              "Compiler options broke LIEF struct layout");
static_assert(kRelocationSize == sizeof(pe_relocation),
              "Compiler options broke LIEF struct layout");
static_assert(kBaseRelocationBlockSize == sizeof(pe_base_relocation_block),
              "Compiler options broke LIEF struct layout");
static_assert(kImportDirectoryTableEntrySize == sizeof(pe_import),
              "Compiler options broke LIEF struct layout");
static_assert(kResourceDirectoryTableSize ==
                  sizeof(pe_resource_directory_table),
              "Compiler options broke LIEF struct layout");
static_assert(kResourceDirectoryEntriesSize ==
                  sizeof(pe_resource_directory_entries),
              "Compiler options broke LIEF struct layout");
static_assert(kResourceDataEntrySize == sizeof(pe_resource_data_entry),
              "Compiler options broke LIEF struct layout");
static_assert(kSymbol16Size == sizeof(pe_symbol),
              "Compiler options broke LIEF struct layout");

static_assert(sizeof(PE_TYPE) == sizeof(uint16_t),
              "Compiler options broke PE_TYPE size");

class PeFile {
 public:
  PeFile(string_view data) : data_(data) { ok_ = Initialize(); }

  bool IsOpen() const { return ok_; }

  string_view entire_file() const { return data_; }
  string_view pe_headers() const { return pe_headers_; }
  string_view section_headers() const { return section_headers_; }

  uint32_t section_count() const { return section_count_; }
  string_view section_header(size_t n) const {
    return StrictSubstr(section_headers_, n * sizeof(pe_section),
                        sizeof(pe_section));
  }

  // CodeView (RSDS) debug info: identifies the matching PDB file.
  bool has_codeview() const { return has_codeview_; }
  const uint8_t* codeview_guid() const { return codeview_guid_; }
  uint32_t codeview_age() const { return codeview_age_; }
  const std::string& pdb_path() const { return pdb_path_; }

 private:
  bool Initialize();
  void ReadCodeView(uint32_t optional_header_offset);
  string_view RvaToFileRange(uint32_t rva, uint32_t size) const;

  string_view GetRegion(uint64_t start, uint64_t n) const {
    return StrictSubstr(data_, start, n);
  }

  bool ok_;
  bool is_64bit_;
  const string_view data_;

  pe_dos_header dos_header_;
  pe_header pe_header_;

  string_view pe_headers_;
  string_view section_headers_;
  uint32_t section_count_;

  bool has_codeview_ = false;
  uint8_t codeview_guid_[16] = {};
  uint32_t codeview_age_ = 0;
  std::string pdb_path_;
};

bool PeFile::Initialize() {
  if (data_.size() < sizeof(dos_header_)) {
    return false;
  }

  memcpy(&dos_header_, data_.data(), sizeof(dos_header_));

  if (dos_header_.Magic != dos_magic) {
    // Not a PE file.
    return false;
  }

  PE_TYPE Magic;
  auto pe_end =
      CheckedAdd(dos_header_.AddressOfNewExeHeader, sizeof(pe_header_));
  if (CheckedAdd(pe_end, sizeof(Magic)) > data_.size()) {
    // Cannot fit the headers / magic from optional header
    return false;
  }

  memcpy(&pe_header_, data_.data() + dos_header_.AddressOfNewExeHeader,
         sizeof(pe_header_));

  if (!std::equal(pe_header_.signature, pe_header_.signature + sizeof(PE_Magic),
                  std::begin(PE_Magic))) {
    // Not a PE file.
    return false;
  }

  memcpy(&Magic, data_.data() + pe_end, sizeof(Magic));

  if (Magic != PE_TYPE::PE32 && Magic != PE_TYPE::PE32_PLUS) {
    // Unknown PE magic
    return false;
  }

  is_64bit_ = Magic == PE_TYPE::PE32_PLUS;

  section_count_ = pe_header_.NumberOfSections;

  // TODO(mj): Figure out if we should trust SizeOfOptionalHeader here
  const uint32_t sections_offset = dos_header_.AddressOfNewExeHeader +
                                   sizeof(pe_header_) +
                                   pe_header_.SizeOfOptionalHeader;

  auto sections_size = CheckedMul(section_count_, sizeof(pe_section));
  if ((sections_offset + sections_size) > data_.size()) {
    // Cannot fit the headers
    return false;
  }

  pe_headers_ = GetRegion(0, sections_offset);
  section_headers_ = GetRegion(sections_offset, sections_size);

  ReadCodeView(pe_end);

  return true;
}

string_view PeFile::RvaToFileRange(uint32_t rva, uint32_t size) const {
  for (uint32_t n = 0; n < section_count_; ++n) {
    pe_section section;
    memcpy(&section, section_headers_.data() + n * sizeof(section),
           sizeof(section));
    if (rva < section.VirtualAddress) continue;
    uint64_t offset = uint64_t{rva} - section.VirtualAddress;
    if (offset + size > section.SizeOfRawData) continue;
    uint64_t file_offset = uint64_t{section.PointerToRawData} + offset;
    if (file_offset + size > data_.size()) return string_view();
    return data_.substr(file_offset, size);
  }
  return string_view();
}

// Reads the CodeView record from the debug data directory, which links the
// image to its PDB file.  Malformed or missing debug info is not an error; the
// file simply has no build ID.
void PeFile::ReadCodeView(uint32_t optional_header_offset) {
  constexpr uint32_t kDebugDirectoryIndex = 6;
  constexpr uint32_t kDebugTypeCodeView = 2;
  constexpr char kRsdsSignature[4] = {'R', 'S', 'D', 'S'};
  constexpr size_t kRsdsHeaderSize = 4 + 16 + 4;  // Signature, GUID, age.

  const size_t directories_offset =
      is_64bit_ ? sizeof(pe64_optional_header) : sizeof(pe32_optional_header);
  const size_t debug_directory_offset =
      directories_offset + kDebugDirectoryIndex * sizeof(pe_data_directory);
  if (pe_header_.SizeOfOptionalHeader <
      debug_directory_offset + sizeof(pe_data_directory)) {
    return;
  }

  // NumberOfRvaAndSize is the last field before the data directories.
  uint32_t directory_count;
  memcpy(&directory_count,
         data_.data() + optional_header_offset + directories_offset -
             sizeof(directory_count),
         sizeof(directory_count));
  if (directory_count <= kDebugDirectoryIndex) return;

  pe_data_directory debug_directory;
  memcpy(&debug_directory,
         data_.data() + optional_header_offset + debug_directory_offset,
         sizeof(debug_directory));
  string_view entries = RvaToFileRange(debug_directory.RelativeVirtualAddress,
                                       debug_directory.Size);

  for (size_t i = 0; i + sizeof(pe_debug) <= entries.size();
       i += sizeof(pe_debug)) {
    pe_debug entry;
    memcpy(&entry, entries.data() + i, sizeof(entry));
    if (entry.Type != kDebugTypeCodeView ||
        entry.SizeOfData < kRsdsHeaderSize ||
        uint64_t{entry.PointerToRawData} + entry.SizeOfData > data_.size()) {
      continue;
    }

    string_view record = data_.substr(entry.PointerToRawData, entry.SizeOfData);
    if (memcmp(record.data(), kRsdsSignature, sizeof(kRsdsSignature)) != 0) {
      continue;
    }
    memcpy(codeview_guid_, record.data() + 4, sizeof(codeview_guid_));
    memcpy(&codeview_age_, record.data() + 20, sizeof(codeview_age_));
    string_view path = record.substr(kRsdsHeaderSize);
    pdb_path_ = std::string(path.substr(0, path.find('\0')));
    has_codeview_ = true;
    return;
  }
}

class Section {
 public:
  string name;

  uint32_t raw_offset() const { return header_.PointerToRawData; }
  uint32_t raw_size() const { return header_.SizeOfRawData; }

  uint32_t virtual_addr() const { return header_.VirtualAddress; }
  uint32_t virtual_size() const { return header_.VirtualSize; }

  Section(string_view header_data) {
    assert(header_data.size() == sizeof(header_));
    memcpy(&header_, header_data.data(), sizeof(header_));

    // TODO(mj): Handle long section names:
    // For longer names, this member contains a forward slash (/) followed by an
    // ASCII representation of a decimal number that is an offset into the
    // string table.
    name = string(header_.Name, strnlen(header_.Name, kNameSize));
  }

 private:
  pe_section header_;
};

template <class Func>
void ForEachSection(const PeFile& pe, Func&& section_func) {
  for (auto n = 0; n < pe.section_count(); ++n) {
    Section section(pe.section_header(n));
    section_func(section);
  }
}

void ParseSections(const PeFile& pe, RangeSink* sink) {
  assert(pe.IsOpen());
  ForEachSection(pe, [sink, &pe](const Section& section) {
    uint64_t vmaddr = section.virtual_addr();
    uint64_t vmsize = section.virtual_size();
    std::string_view section_data = StrictSubstr(
        pe.entire_file(), section.raw_offset(), section.raw_size());

    sink->AddRange("pe_sections", section.name, vmaddr, vmsize, section_data);
  });
}

// Covers whatever the debug information did not attribute (padding, linker
// generated data, ...) with the name of the section it lives in.
void AddSectionFallback(const PeFile& pe, RangeSink* sink) {
  ForEachSection(pe, [sink, &pe](const Section& section) {
    std::string_view section_data = StrictSubstr(
        pe.entire_file(), section.raw_offset(), section.raw_size());
    sink->AddRange("pe_fallback", "[section " + section.name + "]",
                   section.virtual_addr(), section.virtual_size(),
                   section_data);
  });
}

void AddCatchAll(const PeFile& pe, RangeSink* sink) {
  assert(pe.IsOpen());

  auto begin = pe.pe_headers().data() - sink->input_file().data().data();
  sink->AddRange("pe_catchall", "[PE Headers]", begin, pe.pe_headers().size(),
                 pe.pe_headers());

  begin = pe.section_headers().data() - sink->input_file().data().data();
  sink->AddRange("pe_catchall", "[PE Section Headers]", begin,
                 pe.section_headers().size(), pe.section_headers());

  // The last-line fallback to make sure we cover the entire file.
  sink->AddFileRange("pe_catchall", "[Unmapped]", sink->input_file().data());
}

class PEObjectFile : public ObjectFile {
 public:
  PEObjectFile(std::unique_ptr<InputFile> file_data,
               std::unique_ptr<pe::PeFile> pe)
      : ObjectFile(std::move(file_data)), pe_file(std::move(pe)) {}

  std::string GetBuildId() const override {
    if (!pe_file->has_codeview()) {
      return std::string();
    }
    // GUID followed by age, matching the PDB's build ID (see pdb.cc).
    uint32_t age = pe_file->codeview_age();
    std::string build_id(16 + sizeof(age), '\0');
    memcpy(&build_id[0], pe_file->codeview_guid(), 16);
    memcpy(&build_id[16], &age, sizeof(age));
    return build_id;
  }

  std::string GetDebugLinkPath() const override { return pe_file->pdb_path(); }

  void ProcessFile(const std::vector<RangeSink*>& sinks) const override {
    for (auto sink : sinks) {
      switch (sink->data_source()) {
        case DataSource::kSegments:
          // TODO(mj): sections: list out imports and other stuff!
        case DataSource::kSections:
          ParseSections(*pe_file, sink);
          break;
        case DataSource::kSymbols:
        case DataSource::kRawSymbols:
        case DataSource::kShortSymbols:
        case DataSource::kFullSymbols:
          ReadPDBSymbols(GetPdbData(), sink);
          AddSectionFallback(*pe_file, sink);
          break;
        case DataSource::kCompileUnits:
          ReadPDBCompileUnits(GetPdbData(), sink);
          AddSectionFallback(*pe_file, sink);
          break;
        case DataSource::kArchiveMembers:
        case DataSource::kInlines:
        default:
          THROW("PE doesn't support this data source");
      }
      AddCatchAll(*pe_file, sink);
    }
  }

  bool GetDisassemblyInfo(string_view /*symbol*/, DataSource /*symbol_source*/,
                          DisassemblyInfo* /*info*/) const override {
    WARN("PE files do not support disassembly yet");
    return false;
  }

 protected:
  string_view GetPdbData() const {
    string_view data = debug_file().file_data().data();
    if (&debug_file() == this || !IsPDBFile(data)) {
      THROW(
          "this data source requires the PE file's PDB; it was not found next "
          "to the binary or at the path recorded in it, use "
          "--debug-file=<file.pdb>");
    }
    return data;
  }

  std::unique_ptr<pe::PeFile> pe_file;
};

bool ReadMagic(const string_view& data) {
  // If the size is smaller than a dos header, it cannot be a PE file, right?
  if (data.size() < sizeof(pe_dos_header)) {
    return false;
  }

  uint16_t magic;
  memcpy(&magic, data.data(), sizeof(magic));

  return magic == dos_magic;
}
}  // namespace pe

std::unique_ptr<ObjectFile> TryOpenPEFile(std::unique_ptr<InputFile>& file) {
  // Do not bother creating an object if the first magic is not even there
  if (pe::ReadMagic(file->data())) {
    std::unique_ptr<pe::PeFile> pe(new pe::PeFile(file->data()));

    if (pe->IsOpen()) {
      return std::unique_ptr<ObjectFile>(
          new pe::PEObjectFile(std::move(file), std::move(pe)));
    }
  }

  return nullptr;
}

}  // namespace bloaty
