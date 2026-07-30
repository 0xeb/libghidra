// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include "libghidra/status.hpp"
#include "libghidra/models.hpp"

namespace libghidra::client {

struct OpenProgramRequest {
  std::string project_path;
  std::string project_name;
  std::string program_path;
  bool analyze = false;
  bool read_only = false;
  std::string language_id;
  std::string compiler_spec_id;
  std::string format;
  std::uint64_t base_address = 0;
};

struct OpenProjectRequest {
  std::string project_path;
  std::string project_name;
  bool create = false;
  bool read_only = false;
};

struct ListProjectFilesRequest {
  bool include_folders = false;
  bool programs_only = false;
};

struct LoaderArg {
  std::string name;
  std::string value;
};

struct ImportProgramRequest {
  std::string source_path;
  std::string project_folder_path;
  std::string program_name;
  bool overwrite = false;
  bool analyze = false;
  std::string language_id;
  std::string compiler_spec_id;
  std::string loader_class;
  std::vector<LoaderArg> loader_args;
};

class ISessionClient {
 public:
  virtual ~ISessionClient() = default;

  virtual StatusOr<OpenProjectResponse> OpenProject(const OpenProjectRequest& request) = 0;
  virtual StatusOr<CloseProjectResponse> CloseProject(ShutdownPolicy policy) = 0;
  virtual StatusOr<ListProjectFilesResponse> ListProjectFiles(
      const ListProjectFilesRequest& request) = 0;
  virtual StatusOr<ImportProgramResponse> ImportProgram(const ImportProgramRequest& request) = 0;
  virtual StatusOr<OpenProgramResponse> OpenProgram(const OpenProgramRequest& request) = 0;
  virtual StatusOr<CloseProgramResponse> CloseProgram(ShutdownPolicy policy) = 0;
  virtual StatusOr<SaveProgramResponse> SaveProgram() = 0;
  virtual StatusOr<DiscardProgramResponse> DiscardProgram() = 0;
  virtual StatusOr<RevisionResponse> GetRevision() = 0;
  virtual StatusOr<ShutdownResponse> Shutdown(ShutdownPolicy policy) = 0;
  virtual StatusOr<AddPerfBenchmarkResponse> AddPerfBenchmark(
      const PerfBenchmarkRecord& record) = 0;
  virtual StatusOr<ListPerfBenchmarksResponse> ListPerfBenchmarks() = 0;
  virtual StatusOr<ClearPerfBenchmarksResponse> ClearPerfBenchmarks() = 0;
  virtual StatusOr<DeletePerfBenchmarkResponse> DeletePerfBenchmark(
      const std::string& bench_id) = 0;
};

}  // namespace libghidra::client
