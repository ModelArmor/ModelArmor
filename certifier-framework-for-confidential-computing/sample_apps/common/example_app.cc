//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
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

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include <fstream>      // For std::ifstream and std::ofstream
#include <stdexcept>    // For std::exception
#include <cstdlib>      // For system()
#include <string>
#include <exception>

#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "certifier_algorithms.h"

// #include "bioinformatics.pb.h"
// #include <google/protobuf/text_format.h>

// --------------------------------------------------------------------------------------
// Ops are: cold-init, get-certified, run-app-as-client, run-app-as-server
// Added admin ops: acl-add, acl-remove, acl-list, reissue-identity
// -------------------------------------------------------------------------------------

using namespace certifier::framework;
using namespace certifier::utilities;
// using certifier::bioinformatics::BioinformaticsRequest;
// using certifier::bioinformatics::BioinformaticsResponse;

// Ops are: cold-init, get-certified, run-app-as-client, run-app-as-server
DEFINE_bool(print_all, false, "verbose");
DEFINE_string(operation, "", "operation");

DEFINE_string(policy_host, "localhost", "address for policy server");
DEFINE_int32(policy_port, 8123, "port for policy server");
DEFINE_string(data_dir, "./app1_data/", "directory for application data");

DEFINE_string(server_app_host, "localhost", "address for app server");
DEFINE_int32(server_app_port, 8124, "port for server app server");

DEFINE_string(policy_store_file, "store.bin", "policy store file name");

#ifdef SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

DEFINE_string(public_key_alg, Enc_method_rsa_2048, "public key algorithm");
DEFINE_string(auth_symmetric_key_alg,
              Enc_method_aes_256_cbc_hmac_sha256,
              "authenticated symmetric key algorithm");

// Per-client identity + ACL flags
DEFINE_int32(client_id, 1, "Client id for FL node");
DEFINE_string(acl_allow_file, "", "Path to newline-separated allowlist entries");
DEFINE_string(acl_deny_file, "", "Path to newline-separated denylist entries");
DEFINE_string(expected_server_peer_id, "", "If set, the client requires this exact server peer_id (pinning)");
DEFINE_bool(auto_data_dir_per_client, true, "If true and running as client with default data_dir, use ./app<client_id>_data/");

// --- FL runner flags ---
DEFINE_string(workdir, "/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS",
              "Working directory containing server.py/client.py");
DEFINE_string(python_bin, "python3", "Python interpreter to use (python3, python, path)");
DEFINE_string(venv_path, "/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/venv/bin/activate", "Path to venv activate script (e.g., /path/to/venv/bin/activate). Optional");
DEFINE_string(server_script, "/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/federated/binary/server.py", "Server script filename");
DEFINE_string(client_script, "/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/federated/binary/client.py", "Client script filename");
DEFINE_string(dataset_dir, "/root/certifier-framework-for-confidential-computing/sample_apps/simple_app/FL-IDS/federated/federated_datasets", "Directory containing dataset files for client script");
// DEFINE_int32(client_id, 1, "Client id to pass as -i <id> to client.py");
DEFINE_bool(stream_client_logs, true, "Send client stdout/stderr lines over the secure channel");


static string enclave_type("simulated-enclave");

// Helper function to read file contents
std::string read_file_contents(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), 
                      std::istreambuf_iterator<char>());
}

// Run a command via bash -lc "<cd && [source venv &&] cmd>".
// If chan is non-null, each stdout/stderr line is also sent over the secure channel.
bool run_command_stream(const std::string& workdir,
                        const std::string& venv_path,
                        const std::string& command_body,
                        secure_authenticated_channel* chan,
                        int* exit_code_out) {
  std::string shell = "bash -lc 'cd " + workdir + " && ";
  if (!venv_path.empty()) {
    shell += "source " + venv_path + " && ";
  }
  shell += command_body + "'";
  FILE* pipe = popen(shell.c_str(), "r");
  if (!pipe) {
    printf("[runner] Failed to start: %s\n", shell.c_str());
    if (exit_code_out) *exit_code_out = -1;
    return false;
  }
  char buffer[512];
  while (fgets(buffer, sizeof(buffer), pipe)) {
    // Always print locally
    fputs(buffer, stdout);
    fflush(stdout);
    // Optionally forward to peer
    if (chan != nullptr && FLAGS_stream_client_logs) {
      int n = static_cast<int>(strlen(buffer));
      chan->write(n, reinterpret_cast<byte*>(buffer));
      // chan->write(strlen(buffer), reinterpret_cast<const byte*>(buffer));
    }
  }
  int rc = pclose(pipe);
  if (exit_code_out) *exit_code_out = rc;
  if (rc != 0) {
    printf("[runner] Process exited with code %d\n", rc);
    return false;
  }
  return true;
}


// Parameters for simulated enclave
bool get_enclave_parameters(string **s, int *n) {

  // serialized attest key, measurement, serialized endorsement, in that order
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_attest_key_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file,
                             &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                             &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  *n = 3;
  return true;

err:
  delete[] args;
  *s = nullptr;
  return false;
}
#endif  // SIMPLE_APP



// --------------------------------------------------------------------------------------
// Utilities: file helpers, ACL loading, runner, etc.
// --------------------------------------------------------------------------------------
static inline bool file_exists(const std::string& p){ std::ifstream f(p, std::ios::binary); return f.good(); }


static std::unordered_set<std::string> load_set_file(const std::string& path){
std::unordered_set<std::string> s; if (path.empty()) return s; std::ifstream f(path);
for (std::string line; std::getline(f, line);){ if(!line.empty()) s.insert(line); }
return s;
}


static bool append_unique_line(const std::string& path, const std::string& line){
auto s = load_set_file(path); if (s.count(line)) return true; std::ofstream o(path, std::ios::app); if(!o.good()) return false; o<<line<<"\n"; return true;
}


static bool remove_line(const std::string& path, const std::string& line){
auto s = load_set_file(path); if (!s.erase(line)) return true; std::ofstream o(path, std::ios::trunc); if(!o.good()) return false; for(auto& e: s) o<<e<<"\n"; return true;
}

#ifdef GRAMINE_SIMPLE_APP
DEFINE_string(gramine_cert_file, "sgx.cert.der", "certificate file name");

static string enclave_type("gramine-enclave");

// Parameters for gramine enclave
bool get_enclave_parameters(string **s, int *n) {

  string *args = new string[1];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_gramine_cert_file,
                             &args[0])) {
    printf("%s() error, line %d, Can't read cert cert file\n",
           __func__,
           __LINE__);
    delete[] args;
    *s = nullptr;
    return false;
  }

  *n = 1;
  return true;
}
#endif  // GRAMINE_SIMPLE_APP

#ifdef SEV_SIMPLE_APP
DEFINE_string(ark_cert_file, "ark_cert.der", "ark cert file name");
DEFINE_string(ask_cert_file, "ask_cert.der", "ask cert file name");
DEFINE_string(vcek_cert_file, "vcek_cert.der", "vcek cert file name");

static string enclave_type("sev-enclave");

// Parameters for sev enclave for now.
// We will switch to using extended guest requests in the future.
bool get_enclave_parameters(string **s, int *n) {

  // ark cert file, ask cert file, vcek cert file
  string *args = new string[3];
  if (args == nullptr) {
    return false;
  }
  *s = args;

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ark_cert_file, &args[0])) {
    printf("%s() error, line %d, Can't read attest file\n", __func__, __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_ask_cert_file, &args[1])) {
    printf("%s() error, line %d, Can't read measurement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  if (!read_file_into_string(FLAGS_data_dir + FLAGS_vcek_cert_file, &args[2])) {
    printf("%s() error, line %d, Can't read endorsement file\n",
           __func__,
           __LINE__);
    goto err;
  }

  *n = 3;
  return true;

err:
  delete[] args;
  *s = nullptr;
  return false;
}
#endif  // SEV_SIMPLE_APP

#ifdef ISLET_SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

static string enclave_type("islet-enclave");

// Parameters not needed for ISLET enclave
bool get_enclave_parameters(string **s, int *n) {
  *s = nullptr;
  *n = 0;
  return true;
}
#endif  // ISLET_SIMPLE_APP

#ifdef KEYSTONE_SIMPLE_APP
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");

static string enclave_type("keystone-enclave");

// Parameters not needed for Keystone enclave
bool get_enclave_parameters(string **s, int *n) {
  *s = nullptr;
  *n = 0;
  return true;
}
#endif  // KEYSTONE_SIMPLE_APP

// The test app performs five possible roles
//    cold-init: This creates application keys and initializes the policy store.
//    get-certified: This obtains the app admission cert naming the public app
//    key from the service. run-app-as-client: This runs the app as a client.
//    run-app-as-server: This runs the app as server.
//    warm-restart:  This retrieves the policy store data. Operation is subsumed
//      under other ops.

#include "policy_key.cc"

cc_trust_manager *trust_mgr = nullptr;

// --------------------------------------------------------------------------------------
// Client & Server application logic
// --------------------------------------------------------------------------------------
static std::unordered_set<std::string> ACL_ALLOW, ACL_DENY;
static inline bool acl_is_allowed(const std::string& id){
if (!FLAGS_acl_deny_file.empty() && ACL_DENY.count(id)) return false;
if (!FLAGS_acl_allow_file.empty() && !ACL_ALLOW.empty() && !ACL_ALLOW.count(id)) return false;
return true;
}


// We use peer_id_ (measurement identity) as a baseline identity string.
// For strictly per-client control, prefer adding a cryptographic fingerprint of the client's
// admissions certificate here if your channel API exposes it. This sample gates on peer_id_
// PLUS a logical client-id announced by the client during handshake.

// -----------------------------------------------------------------------------------------

bool client_application(secure_authenticated_channel &channel) {
  printf("Client peer id is %s\n", channel.peer_id_.c_str());

  // Handshake
  // const char *msg = "Hi from FL client\n";
  // channel.write(strlen(msg), (byte *)msg);
  // 1) Announce logical client id to server
  {
  std::ostringstream hello; hello << "HELLO id=" << FLAGS_client_id << "\n";
  auto s = hello.str(); channel.write((int)s.size(), (byte*)s.data());
  }

  std::string out;
  channel.read(&out);
  printf("Server response: %s\n", out.data());
  // 2) Receive server ack (or unauthorized)
  if (out.find("unauthorized") != std::string::npos){ 
    channel.close(); return false; 
  }

  // Build: python client.py -i <id>
  std::string cmd = FLAGS_python_bin + std::string(" ") +
                   FLAGS_client_script
                  +  " -i " + std::to_string(FLAGS_client_id) + 
                   " -d " + FLAGS_dataset_dir;

  printf("[client] Executing in %s: %s\n", FLAGS_workdir.c_str(), cmd.c_str());
  int exit_code = 0;
  bool ok = run_command_stream(FLAGS_workdir,
                               FLAGS_venv_path,
                               cmd,
                               &channel,         // stream logs to server
                               &exit_code);

  channel.close();
  return ok && exit_code == 0;
}



void server_application(secure_authenticated_channel &channel) {
    printf("Server peer id is %s\n", channel.peer_id_.c_str());
  // Read message from client over authenticated, encrypted channel
  // string out;
  // int    n = channel.read(&out);
  // printf("SSL server read: %s\n", (const char *)out.data());

  // // Reply over authenticated, encrypted channel
  // const char *msg = "Hi from your secret server\n";
  // channel.write(strlen(msg), (byte *)msg);
//   channel.close();
  // Gate by measurement (peer_id_) and by announced client-id
  if (!FLAGS_acl_allow_file.empty()) ACL_ALLOW = load_set_file(FLAGS_acl_allow_file);
  if (!FLAGS_acl_deny_file.empty())  ACL_DENY  = load_set_file(FLAGS_acl_deny_file);
  std::string first; 
  int n = channel.read(&first);
  int announced_id = -1; 
  if (first.find("HELLO id=") == 0){ 
    announced_id = atoi(first.c_str()+9); 
  }

  std::string logical_id = (announced_id>=0)? ("client-"+std::to_string(announced_id)) : std::string("client-unknown");
  std::string composite = channel.peer_id_ + "|" + logical_id; // composite identity

  printf("[acl] peer='%s' logical='%s'\n", channel.peer_id_.c_str(), logical_id.c_str());
  printf("[acl] composite='%s'\n", composite.c_str());
  if (ACL_DENY.count(composite)) printf("[acl] matched DENY\n");
  if (!ACL_ALLOW.empty() && !ACL_ALLOW.count(composite)) printf("[acl] not in ALLOW -> deny\n");

  if (!acl_is_allowed(composite)){
    const char* msg = "unauthorized client\n"; 
    channel.write((int)strlen(msg), (byte*)msg);
    channel.close(); 
    return; 
  }

  const char *okmsg = "ok\n"; 
  channel.write((int)strlen(okmsg), (byte*)okmsg);
}

// --------------------------------------------------------------------------------------
// Admin operations: ACL mutate & list, and reissue-identity (client-side rotate)
// --------------------------------------------------------------------------------------
DEFINE_string(acl_entry, "", "Entry to add/remove in ACL. Format: <peer_id>|client-<id>");
DEFINE_string(acl_list, "allow", "Which list to act on: allow|deny");


static int op_acl_add(){
  if (FLAGS_acl_entry.empty()) { printf("--acl_entry is required\n"); return 2; }
  const std::string& path = (FLAGS_acl_list=="deny")? FLAGS_acl_deny_file : FLAGS_acl_allow_file;
  if (path.empty()){ printf("Set --acl_%s_file to use this op\n", (FLAGS_acl_list=="deny")?"deny":"allow"); return 2; }
  if (!append_unique_line(path, FLAGS_acl_entry)){ printf("Failed to write %s\n", path.c_str()); return 1; }
  printf("Added to %s: %s\n", path.c_str(), FLAGS_acl_entry.c_str()); return 0;
}


static int op_acl_remove(){
  if (FLAGS_acl_entry.empty()) { printf("--acl_entry is required\n"); return 2; }
  const std::string& path = (FLAGS_acl_list=="deny")? FLAGS_acl_deny_file : FLAGS_acl_allow_file;
  if (path.empty()){ printf("Set --acl_%s_file to use this op\n", (FLAGS_acl_list=="deny")?"deny":"allow"); return 2; }
  if (!remove_line(path, FLAGS_acl_entry)){ printf("Failed to write %s\n", path.c_str()); return 1; }
  printf("Removed from %s: %s\n", path.c_str(), FLAGS_acl_entry.c_str()); return 0;
}


static int op_acl_list(){
  const std::string& path = (FLAGS_acl_list=="deny")? FLAGS_acl_deny_file : FLAGS_acl_allow_file;
  auto s = load_set_file(path);
  printf("%s (%zu entries)\n", path.c_str(), s.size());
  for (auto &e: s) printf(" %s\n", e.c_str());
  return 0;
}

// Reissue identity: backup/delete policy_store, then cold-init + get-certified
static int op_reissue_identity() {
  std::string store = FLAGS_data_dir + FLAGS_policy_store_file;

  // 1) Backup existing policy store (if any)
  if (file_exists(store)) {
    std::string bak = store + ".bak";
    std::remove(bak.c_str());
    if (std::rename(store.c_str(), bak.c_str()) != 0) {
      printf("Could not backup existing policy store: %s (errno=%d)\n",
             store.c_str(), errno);
      // not fatal; continue
    } else {
      printf("Backed up existing policy store to %s\n", bak.c_str());
    }
  }

  // 2) Cold-init with current algorithms
#ifdef SIMPLE_APP
  std::string public_key_alg(FLAGS_public_key_alg);
  std::string auth_symmetric_key_alg(FLAGS_auth_symmetric_key_alg);
#else
  std::string public_key_alg(Enc_method_rsa_2048);
  std::string auth_symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);
#endif

  if (!trust_mgr->cold_init(public_key_alg,
                            auth_symmetric_key_alg,
                            "simple-app-home_domain",
                            FLAGS_policy_host,
                            FLAGS_policy_port,
                            FLAGS_server_app_host,
                            FLAGS_server_app_port)) {
    printf("cold-init failed during reissue\n");
    return 1;
  }

  // 3) Get-certified
  if (!trust_mgr->certify_me()) {
    printf("get-certified failed during reissue\n");
    return 1;
  }

  printf("Reissue complete (new keys + admissions cert).\n");
  return 0;
}


int main(int an, char **av) {
  string usage("Simple App");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  // clang-format off
  if (FLAGS_operation == "") {
    printf("                                                                            (Defaults)\n");
    printf("%s --operation=<op>                                        ; %s", av[0], "(See below)");
    printf("\n\
                  --policy_host=policy-host-address                       ; %s\n\
                  --policy_port=policy-host-port                          ; %d\n\
                  --server_app_host=my-server-host-address                ; %s\n\
                  --server_app_port=my-server-port-number                 ; %d\n\
                  --data_dir=-directory-for-app-data                      ; %s\n\
                  --policy_cert_file=self-signed-policy-cert-file-name    ; \n\
                  --policy_store_file=policy-store-file-name              ; %s\n\
                  --print_all=true|false",
                  FLAGS_policy_host.c_str(),
                  FLAGS_policy_port,
                  FLAGS_server_app_host.c_str(),
                  FLAGS_server_app_port,
                  FLAGS_data_dir.c_str(),
                  FLAGS_policy_store_file.c_str());
#ifdef SIMPLE_APP
    printf("\n\
                  --platform_file_name=platform-cert-bin-file-name        ; %s\n\
                  --platform_attest_endorsement=endorsement-bin-file-name ; %s\n\
                  --measurement_file=measurement-bin-file-name            ; %s\n\
                  --attest_key_file=attest-key-bin-file-name              ; %s\n",
                  FLAGS_platform_file_name.c_str(),
                  FLAGS_platform_attest_endorsement.c_str(),
                  FLAGS_measurement_file.c_str(),
                  FLAGS_attest_key_file.c_str());
#endif  // SIMPLE_APP

#ifdef SEV_SIMPLE_APP
    printf("\n\
                  --ark_cert_file=./service/milan_ark_cert.der \n\
                  --ask_cert_file=./service/milan_ask_cert.der \n\
                  --vcek_cert_file=./service/milan_vcek_cert.der ");
#endif  // SEV_SIMPLE_APP
#ifdef GRAMINE_SIMPLE_APP
    printf("\n\
                  --gramine_cert_file=sgx.cert.der");
#endif  // GRAMINE_SIMPLE_APP
    printf("\n\nOperations are: cold-init, get-certified, "
           "run-app-as-client, run-app-as-server\n");

#ifdef SIMPLE_APP

    // clang-format off
    printf("\nFor the simple_app, you can additionally drive 'cold-init' with different pairs of:\n");
    printf("\n\
    --public_key_alg=public-key-algorigthm-name                          : %s\n\
    --auth_symmetric_key_alg=authenticated-symmetric-key-algorigthm-name : %s\n",
            FLAGS_public_key_alg.c_str(),
            FLAGS_auth_symmetric_key_alg.c_str());
    // clang-format on

    printf("\nPublic-key algorithms supported:\n");
    for (int i = 0; i < Num_public_key_algorithms; i++) {
      printf("  %s\n", Enc_public_key_algorithms[i]);
    }
    printf("\nSymmetric-key algorithms supported:\n");
    for (int i = 0; i < Num_symmetric_key_algorithms; i++) {
      printf("  %s\n", Enc_authenticated_symmetric_key_algorithms[i]);
    }

#endif  // SIMPLE_APP
    return 0;
  }
  // clang-format on

  SSL_library_init();
  string purpose("authentication");

  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  trust_mgr = new cc_trust_manager(enclave_type, purpose, store_file);
  if (trust_mgr == nullptr) {
    printf("%s() error, line %d, couldn't initialize trust object\n",
           __func__,
           __LINE__);
    return 1;
  }

  // Init policy key info
  if (!trust_mgr->init_policy_key(initialized_cert, initialized_cert_size)) {
    printf("%s() error, line %d, Can't init policy key\n", __func__, __LINE__);
    return 1;
  }

  // Get parameters
  string *params = nullptr;
  int     n = 0;
  if (!get_enclave_parameters(&params, &n)) {
    printf("%s() error, line %d, get enclave parameters\n", __func__, __LINE__);
    return 1;
  }

  // Init simulated enclave
  if (!trust_mgr->initialize_enclave(n, params)) {
    printf("%s() error, line %d, Can't init enclave\n", __func__, __LINE__);
    return 1;
  }
  if (params != nullptr) {
    delete[] params;
    params = nullptr;
  }

  // clang-format off

  // Use specified algorithms for the enclave            Defaults:
#ifdef SIMPLE_APP
  // We support --public_key_alg and --auth_symmetric_key_alg only for simple_app
  // (as a way to exercise tests w/ different pairs of algorithms).
  string public_key_alg(FLAGS_public_key_alg);                  // Enc_method_rsa_2048
  string auth_symmetric_key_alg(FLAGS_auth_symmetric_key_alg);  // Enc_method_aes_256_cbc_hmac_sha256
  if (FLAGS_print_all) {
      printf("measurement file='%s', ", FLAGS_measurement_file.c_str());
  }
#else
  string public_key_alg(Enc_method_rsa_2048);
  string auth_symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);
#endif  // SIMPLE_APP

  // clang-format on
  // Preload ACL files if provided
// ACL_ALLOW = load_set_file(FLAGS_acl_allow_file);
// ACL_DENY = load_set_file(FLAGS_acl_deny_file);
if (!FLAGS_acl_allow_file.empty()) ACL_ALLOW = load_set_file(FLAGS_acl_allow_file);
if (!FLAGS_acl_deny_file.empty())  ACL_DENY  = load_set_file(FLAGS_acl_deny_file);


  if (FLAGS_print_all && (FLAGS_operation == "cold-init")) {
    printf("public_key_alg='%s', authenticated_symmetric_key_alg='%s\n",
           public_key_alg.c_str(),
           auth_symmetric_key_alg.c_str());
  }

  // Carry out operation
  int ret = 0;
  if (FLAGS_operation == "acl-add") {
    ret = op_acl_add();
    goto done;
  }
  if (FLAGS_operation == "acl-remove") {
    ret = op_acl_remove();
    goto done;
  }
  if (FLAGS_operation == "acl-list") {
    ret = op_acl_list();
    goto done;
  }

  if (FLAGS_operation == "cold-init") {
    if (!trust_mgr->cold_init(public_key_alg,
                              auth_symmetric_key_alg,
                              "simple-app-home_domain",
                              FLAGS_policy_host,
                              FLAGS_policy_port,
                              FLAGS_server_app_host,
                              FLAGS_server_app_port)) {
      printf("%s() error, line %d, cold-init failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  } else if (FLAGS_operation == "get-certified") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    if (!trust_mgr->certify_me()) {
      printf("%s() error, line %d, certification failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    // Debug
#ifdef DEBUG
    trust_mgr->print_trust_data();
#endif  // DEBUG
  }else if (FLAGS_operation == "reissue-identity"){
    if (!trust_mgr->warm_restart()) { /* continue; may be first run */ }
    ret = op_reissue_identity(); goto done;
  } else if (FLAGS_operation == "run-app-as-client") {
    if (FLAGS_auto_data_dir_per_client){
      FLAGS_data_dir = std::string("./app") + std::to_string(FLAGS_client_id) + std::string("_data/");
      printf("[init] Using per-client data_dir: %s\n", FLAGS_data_dir.c_str());
    }

    string                       my_role("client");
    secure_authenticated_channel channel(my_role);

    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }

    printf("Running App as client\n");
    if (!trust_mgr->cc_auth_key_initialized_
        || !trust_mgr->cc_policy_info_initialized_) {
      printf("%s() error, line %d, trust data not initialized\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    if (!trust_mgr->primary_admissions_cert_valid_) {
      printf("%s() error, line %d, primary admissions cert not valid\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
    if (!channel.init_client_ssl(FLAGS_server_app_host,
                                 FLAGS_server_app_port,
                                 *trust_mgr)) {
      printf("%s() error, line %d, Can't init client app\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }

    // Optional: pin server identity
    // if (!FLAGS_expected_server_peer_id.empty() && channel.peer_id_ != FLAGS_expected_server_peer_id){
    // fprintf(stderr, "[client] Server identity mismatch! got=%s\n", channel.peer_id_.c_str());
    // channel.close(); ret=1; goto done;
    // }

    // This is the actual application code.
    if (!client_application(channel)) {
      printf("%s() error, line %d, client_application failed\n",
             __func__,
             __LINE__);
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "run-app-as-server") {
    if (!trust_mgr->warm_restart()) {
      printf("%s() error, line %d, warm-restart failed\n", __func__, __LINE__);
      ret = 1;
      goto done;
    }
    printf("Running App as server\n");

     // Start the Python FL server *once* in background and log to server.log
    {
      std::string cmd = FLAGS_python_bin + std::string(" ") + FLAGS_server_script;
      // Redirect to a logfile so the process keeps running after we return.
      cmd += " > server.log 2>&1 &";
      int rc = 0;
      bool ok = run_command_stream(FLAGS_workdir, FLAGS_venv_path, cmd, /*chan*/nullptr, &rc);
      // run_command_stream will wait; to truly background, wrap in bash -lc above with '&'
      // We already appended '&', so it returns quickly; rc==0 just means bash accepted it.
      if (!ok) {
        printf("[server] WARNING: attempted to start server.py but got rc=%d. Check server.log\n", rc);
      } else {
        printf("[server] server.py launched (background). Tail %s/server.log for details.\n", FLAGS_workdir.c_str());
      }
    }


    if (!server_dispatch(FLAGS_server_app_host,
                         FLAGS_server_app_port,
                         *trust_mgr,
                         server_application)) {
      ret = 1;
      goto done;
    }
  } else {
    printf("%s() error, line %d, Unknown operation\n", __func__, __LINE__);
  }

done:
  // trust_mgr->print_trust_data();
  trust_mgr->clear_sensitive_data();
  if (trust_mgr != nullptr) {
    delete trust_mgr;
  }
  return ret;
}