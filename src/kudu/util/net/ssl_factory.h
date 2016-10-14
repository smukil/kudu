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
#ifndef KUDU_UTIL_NET_SSL_FACTORY_H
#define KUDU_UTIL_NET_SSL_FACTORY_H

#include <sys/uio.h>
#include <string>
#include <openssl/ssl.h>

#include "kudu/gutil/macros.h"
#include "kudu/util/status.h"

namespace kudu {

class Sockaddr;
class SSLSocket;

class SSLFactory {
 public:
  SSLFactory();

  ~SSLFactory();

  Status Init();

  Status LoadCertificate(const char* certificate_path);

  Status LoadPrivateKey(const char* key_path);

  Status LoadCertificateAuthority(const char* certificate_path);

  SSLSocket* CreateSocket(int socket_fd, bool is_server);

 private:
  SSL_CTX* ctx_;
};

}

#endif
