// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//#include "net/quic/test_tools/crypto_test_utils.h"

#include <utility>

#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_ptr.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "net/base/net_errors.h"
//#include "net/base/test_completion_callback.h"
//#include "net/base/test_data_directory.h"
//#include "net/cert/cert_status_flags.h"
//#include "net/cert/cert_verifier.h"
//#include "net/cert/cert_verify_result.h"
//#include "net/cert/ct_verifier.h"
//#include "net/cert/mock_cert_verifier.h"
//#include "net/cert/multi_log_ct_verifier.h"
//#include "net/cert/test_root_certs.h"
//#include "net/cert/x509_certificate.h"
//#include "net/cert/x509_util.h"
//#include "net/http/transport_security_state.h"
//#include "net/log/net_log.h"
#include "net/quic/crypto/crypto_utils.h"
//#include "net/quic/crypto/proof_source_chromium.h"
//#include "net/quic/crypto/proof_verifier_chromium.h"
//#include "net/ssl/ssl_config_service.h"
//#include "net/test/cert_test_util.h"

using base::StringPiece;
using base::StringPrintf;
using std::string;
using std::vector;

namespace net {

namespace test {

namespace {

class TestProofVerifierChromium : public ProofVerifierChromium {
 public:
  TestProofVerifierChromium(
      scoped_ptr<CertVerifier> cert_verifier,
      scoped_ptr<TransportSecurityState> transport_security_state,
      scoped_ptr<CTVerifier> cert_transparency_verifier,
      const std::string& cert_file)
      : ProofVerifierChromium(cert_verifier.get(),
                              nullptr,
                              transport_security_state.get(),
                              cert_transparency_verifier.get()),
        cert_verifier_(std::move(cert_verifier)),
        transport_security_state_(std::move(transport_security_state)),
        cert_transparency_verifier_(std::move(cert_transparency_verifier)) {
    // Load and install the root for the validated chain.
    scoped_refptr<X509Certificate> root_cert =
        ImportCertFromFile(GetTestCertsDirectory(), cert_file);
    scoped_root_.Reset(root_cert.get());
  }

  ~TestProofVerifierChromium() override {}

  CertVerifier* cert_verifier() { return cert_verifier_.get(); }

 private:
  ScopedTestRoot scoped_root_;
  scoped_ptr<CertVerifier> cert_verifier_;
  scoped_ptr<TransportSecurityState> transport_security_state_;
  scoped_ptr<CTVerifier> cert_transparency_verifier_;
};

const char kSignature[] = "signature";
const char kSCT[] = "CryptoServerTests";

class FakeProofSource : public ProofSource {
 public:
  FakeProofSource() {}
  ~FakeProofSource() override {}

  // ProofSource interface
  bool Initialize(const base::FilePath& cert_path,
                  const base::FilePath& key_path,
                  const base::FilePath& sct_path) {
    /*std::string cert_data;
    if (!base::ReadFileToString(cert_path, &cert_data)) {
      DLOG(FATAL) << "Unable to read certificates.";
      return false;
    }

    CertificateList certs_in_file =
        X509Certificate::CreateCertificateListFromBytes(
            cert_data.data(), cert_data.size(), X509Certificate::FORMAT_AUTO);

    if (certs_in_file.empty()) {
      DLOG(FATAL) << "No certificates.";
      return false;
    }

    for (const scoped_refptr<X509Certificate>& cert : certs_in_file) {
      std::string der_encoded_cert;
      if (!X509Certificate::GetDEREncoded(cert->os_cert_handle(),
                                          &der_encoded_cert)) {
        return false;
      }
      certificates_.push_back(der_encoded_cert);
    }  */
    return true;

}
}  // namespace

// static
ProofSource* CryptoTestUtils::ProofSourceForTesting() {
#if defined(USE_OPENSSL)
  ProofSourceChromium* source = new ProofSourceChromium();
#else
  FakeProofSource* source = new FakeProofSource();
#endif
  base::FilePath certs_dir = GetTestCertsDirectory();
  CHECK(source->Initialize(
      certs_dir.AppendASCII("quic_chain.crt"),
      certs_dir.AppendASCII("quic_test.example.com.key.pkcs8"),
      certs_dir.AppendASCII("quic_test.example.com.key.sct")));
  return source;
}



}  // namespace test

}  // namespace net
