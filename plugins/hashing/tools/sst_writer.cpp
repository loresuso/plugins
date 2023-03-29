#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <rocksdb/sst_file_writer.h>
#include <rocksdb/status.h>

using namespace ROCKSDB_NAMESPACE;

int main() {
  Options options;

  SstFileWriter sst_file_writer(EnvOptions(), options, options.comparator);
  // Path to where we will write the SST file
  std::string file_path = "/tmp/sst_test/file1.sst";

  // Open the file for writing
  Status s = sst_file_writer.Open(file_path);
  if (!s.ok()) {
    printf("Error while opening file %s, Error: %s\n", file_path.c_str(),
           s.ToString().c_str());
    return 1;
  }

  s = sst_file_writer.Add(
      "8696974df4fc39af88ee23e307139afc533064f976da82172de823c3ad66f444",
      "ls-malware");
  if (!s.ok()) {
    printf(s.ToString().c_str());
  }

  s = sst_file_writer.Add(
      "8b2e8564da06c4712a580fd7bd91a236ad3f891ae6ba0a50b117bbe050d328f0",
      "sleep-malware");
  if (!s.ok()) {
    printf(s.ToString().c_str());
  }

  sst_file_writer.Finish();
}