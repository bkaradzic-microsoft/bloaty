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

#include "test.h"

struct BloatyTestEntry {
  std::string name;
  std::vector<std::string> commandline;
  std::string input_file;
  std::string result_file;
};

std::string TestEntryName(
    const testing::TestParamInfo<struct BloatyTestEntry>& entry) {
  return entry.param.name;
}

std::ostream& operator<<(std::ostream& os, const BloatyTestEntry& entry) {
  os << "{ ";
  for (const auto& str : entry.commandline) {
    os << str << ", ";
  }
  os << entry.input_file << ", " << entry.result_file << " }";
  return os;
}

// Strip all trailing whitespace (including \r)
void Normalize(std::string& contents) {
  std::stringstream buffer(contents);
  contents.clear();
  std::string tmp;
  while (std::getline(buffer, tmp)) {
    auto end = tmp.find_last_not_of("\t \r");
    if (end != std::string::npos) {
      tmp = tmp.substr(0, end + 1);
    } else {
      tmp.clear();
    }
    if (!contents.empty()) {
      contents += "\n";
    }
    contents += tmp;
  }
}

inline bool GetFileContents(const std::string& filename,
                            std::string& contents) {
  FILE* file = fopen(filename.c_str(), "rb");
  if (!file) {
    std::cerr << "Couldn't get file size for: " << filename << "\n";
    return false;
  }
  fseek(file, 0L, SEEK_END);
  size_t size = ftell(file);
  fseek(file, 0L, SEEK_SET);
  contents.resize(size);
  size_t result = fread(&contents[0], 1, size, file);
  fclose(file);
  contents.resize(result);
  Normalize(contents);
  return result == size;
}

class BloatyOutputTest : public BloatyTest,
                         public testing::WithParamInterface<BloatyTestEntry> {
 public:
  BloatyOutputTest()
      : commandline(GetParam().commandline),
        input_file(GetParam().input_file),
        result_file(GetParam().result_file) {}

  const std::vector<std::string>& commandline;
  const std::string& input_file;
  const std::string& result_file;
};

TEST_P(BloatyOutputTest, CheckOutput) {
  uint64_t size;
  ASSERT_TRUE(GetFileSize(input_file, &size));
  std::string expect_result;
  ASSERT_TRUE(GetFileContents(result_file, expect_result));

  std::vector<std::string> cmdline = {"bloaty"};
  cmdline.insert(cmdline.end(), commandline.begin(), commandline.end());
  cmdline.push_back(input_file);
  RunBloaty(cmdline);

  bloaty::OutputOptions output_options;
  std::stringstream output_stream;
  output_options.output_format = bloaty::OutputFormat::kTSV;
  output_->Print(output_options, &output_stream);
  std::string tmp = output_stream.str();
  Normalize(tmp);
  EXPECT_EQ(tmp, expect_result);
}

static BloatyTestEntry tests[] = {
    {"MSVCR15DLL", {}, "msvc-15.0-foo-bar.dll", "msvc-15.0-foo-bar.dll.txt"},
    {"MSVCR15DLLSEG",
     {"-d", "segments"},
     "msvc-15.0-foo-bar.dll",
     "msvc-15.0-foo-bar.dll.seg.txt"},
    {"MSVC15EXE",
     {},
     "msvc-15.0-foo-bar-main-cv.bin",
     "msvc-15.0-foo-bar-main-cv.bin.txt"},
    {"MSVC15EXESEG",
     {"-d", "segments"},
     "msvc-15.0-foo-bar-main-cv.bin",
     "msvc-15.0-foo-bar-main-cv.bin.seg.txt"},

    {"MSVCR16DLL", {}, "msvc-16.0-foo-bar.dll", "msvc-16.0-foo-bar.dll.txt"},
    {"MSVCR16DLLSEG",
     {"-d", "segments"},
     "msvc-16.0-foo-bar.dll",
     "msvc-16.0-foo-bar.dll.seg.txt"},
    {"MSVC16EXE",
     {},
     "msvc-16.0-foo-bar-main-cv.bin",
     "msvc-16.0-foo-bar-main-cv.bin.txt"},
    {"MSVC16EXESEG",
     {"-d", "segments"},
     "msvc-16.0-foo-bar-main-cv.bin",
     "msvc-16.0-foo-bar-main-cv.bin.seg.txt"},
};

INSTANTIATE_TEST_SUITE_P(BloatyTest, BloatyOutputTest, testing::ValuesIn(tests),
                         TestEntryName);

// The test binaries are built for x86 and x64; x86 decorates C names with '_'.
static const bloaty::RollupRow* FindCSymbol(const bloaty::RollupRow& row,
                                            const std::string& name) {
  for (const auto& child : row.sorted_children) {
    if (child.name == name || child.name == "_" + name) {
      return &child;
    }
  }
  return nullptr;
}

TEST_F(BloatyTest, PdbSymbolsAutoLoaded) {
  // The PDB is found next to the binary using the name recorded in its
  // CodeView debug directory entry, and matched by GUID and age.
  for (const char* file :
       {"msvc-15.0-foo-bar-main-cv.bin", "msvc-16.0-foo-bar-main-cv.bin"}) {
    // Raw names: some demangled CRT names contain commas, which the CSV
    // consistency check in RunBloaty() can't handle.
    RunBloaty({"bloaty", "-d", "symbols", "--demangle=none", "-n", "0", file});

    // int bar_x[1000], initialized data.
    const bloaty::RollupRow* bar_x = FindCSymbol(*top_row_, "bar_x");
    ASSERT_TRUE(bar_x != nullptr) << file;
    EXPECT_EQ(bar_x->size.vm, 4000);
    EXPECT_EQ(bar_x->size.file, 4000);

    // Uninitialized data takes no space in the file.
    const bloaty::RollupRow* foo_x = FindCSymbol(*top_row_, "foo_x");
    ASSERT_TRUE(foo_x != nullptr) << file;
    EXPECT_GT(foo_x->size.vm, 0);
    EXPECT_EQ(foo_x->size.file, 0);

    // Procedures are sized exactly from S_GPROC32 records.
    ASSERT_TRUE(FindCSymbol(*top_row_, "main") != nullptr) << file;
    ASSERT_TRUE(FindCSymbol(*top_row_, "foo_func") != nullptr) << file;
  }
}

TEST_F(BloatyTest, PdbCompileUnits) {
  RunBloaty({"bloaty", "-d", "compileunits", "-n", "0",
             "--debug-file=msvc-16.0-foo-bar-main-cv.pdb",
             "msvc-16.0-foo-bar-main-cv.bin"});

  bool found_crt_object = false;
  for (const auto& child : top_row_->sorted_children) {
    if (child.name.size() > 14 && child.name.compare(child.name.size() - 14, 14,
                                                     "\\gs_report.obj") == 0) {
      found_crt_object = true;
      EXPECT_GT(child.size.vm, 0);
    }
  }
  EXPECT_TRUE(found_crt_object);

  // The test code was compiled with /GL, so its contributions are attributed
  // to the LTCG pseudo-module.
  const bloaty::RollupRow* cil = FindRow("* CIL *");
  ASSERT_TRUE(cil != nullptr);
  EXPECT_GT(cil->size.vm, 4000);
}

TEST_F(BloatyTest, PdbRequired) {
  // This DLL has no CodeView record, so there is no PDB to find.
  AssertBloatyFails({"bloaty", "-d", "symbols", "msvc-16.0-foo-bar.dll"},
                    "requires the PE file's PDB");
  // A PDB on its own has no file layout to attribute sizes to.
  AssertBloatyFails({"bloaty", "msvc-16.0-foo-bar-main-cv.pdb"},
                    "cannot be analyzed directly");
}
