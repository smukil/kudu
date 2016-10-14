// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "kudu/util/net/ssl_factory.h"
#include "kudu/util/net/ssl_socket.h"
#include "kudu/util/locks.h"

namespace kudu {

simple_spinlock ssl_factory_lock_;

SSLFactory::SSLFactory() {
  LOG (INFO) << "Creating SSL Factory";
  std::lock_guard<simple_spinlock> l(ssl_factory_lock_);
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  RAND_poll();

  LOG (INFO) << "Created SSL Factory";
}

SSLFactory::~SSLFactory() {
  std::lock_guard<simple_spinlock> l(ssl_factory_lock_);
  SSL_CTX_free(ctx_);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
  ERR_remove_state(0);
  LOG (INFO) << "Cleaned up SSL Factory";
}

Status SSLFactory::Init() {
  LOG (INFO) << "Going to Init SSLFactory";
  std::lock_guard<simple_spinlock> l(ssl_factory_lock_);
  ctx_ = SSL_CTX_new(SSLv23_method());
  if (ctx_ == NULL) {
    LOG (INFO) << "Creating SSL context failed";
    return Status::RuntimeError("Could not create SSL context");
  }
  SSL_CTX_set_mode(ctx_, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  LOG (INFO) << "Inited SSLFactory!";
  return Status::OK();
}

Status SSLFactory::LoadCertificate(const char* certificate_path) {
  if (SSL_CTX_use_certificate_file(ctx_, certificate_path, SSL_FILETYPE_PEM) != 1) {
    LOG (INFO) << "LoadCertificate Error!";
    return Status::RuntimeError("Could not load certificate file");
  }
  LOG (INFO) << "LoadCertificate Passed! ";
  return Status::OK();
}

Status SSLFactory::LoadPrivateKey(const char* key_path) {
  if (SSL_CTX_use_PrivateKey_file(ctx_, key_path, SSL_FILETYPE_PEM) != 1) {
    LOG (INFO) << "LoadPrivateKey Failed! ";
    return Status::RuntimeError("Could not load private key file");
  }
  LOG (INFO) << "LoadPrivateKey Passed! ";
  return Status::OK();
}

Status SSLFactory::LoadCertificateAuthority(const char* certificate_path) {
  if (SSL_CTX_load_verify_locations(ctx_, certificate_path, NULL) != 1) {
    LOG (INFO) << "LoadCertificate Error!";
    return Status::NetworkError("Load verify locations failed!");
  }
  LOG (INFO) << "LoadCertificateAuthority Passed! ";
  return Status::OK();
}

SSLSocket* SSLFactory::CreateSocket(int socket_fd, bool is_server) {
  if (ctx_ == NULL) return NULL;

  SSL* ssl = SSL_new(ctx_);
  if (ssl == NULL) {
    LOG (INFO) << "Could not create SSL* object";
    return NULL;
  }
  SSLSocket* ssl_socket = new SSLSocket(socket_fd, ssl, is_server, ctx_);
  if (!ssl_socket) return NULL;
  return ssl_socket;
}

}
