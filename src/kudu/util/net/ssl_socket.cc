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

#include "kudu/util/net/ssl_socket.h"
#include "kudu/util/errno.h"
#include <openssl/err.h>
#include <errno.h>

namespace kudu {

SSLSocket::SSLSocket() : Socket() {
}

SSLSocket::SSLSocket(int fd, SSL* ssl, bool is_server, SSL_CTX* ctx) : Socket(fd) {
  ssl_ = ssl;
  ctx_ = ctx;
  SSL_set_fd(ssl_, fd);
  is_server_ = is_server;
}

SSLSocket::~SSLSocket() {
  //SSL_free(ssl_);
}

std::string GetLastError(int errno_copy) {
  LOG (INFO) << "SSL_SOCKET ERROR: We hit an error!! ";
  int error_code = ERR_peek_last_error();
  std::string reason;
  if (error_code != 0) {
    const char* error_reason = ERR_reason_error_string(error_code);
    if (error_reason != NULL) {
      reason = error_reason;
    } else {
      reason = "SSL error " + error_code;
    }
    LOG (INFO) << "SSL_SOCKET ERROR: " << reason;
    return reason;
  } else {
    reason = ErrnoToString(errno_copy);
    LOG (INFO) << "errno SSL_SOCKET ERROR: " << reason;
    return reason;
  }
}

Status SSLSocket::DoHandshake() {
  if (ssl_ == NULL) return Status::NetworkError("SSL context unavailable");
  int ret;
  if (is_server_) {
    LOG (INFO) << "Calling SSL_accept()";
    ret = SSL_accept(ssl_);
  } else {
    LOG (INFO) << "Calling SSL_connect()";
    ret = SSL_connect(ssl_);
  }
  if (ret <= 0) return Status::NetworkError(GetLastError(errno));

  // Verify if the handshake was successful.
  int rc = SSL_get_verify_result(ssl_);
  if (rc != X509_V_OK) {
    return Status::NetworkError("SSL_get_verify_result()",
        X509_verify_cert_error_string(rc));
  }
  return Status::OK();
}

Status SSLSocket::Write(const uint8_t *buf, int32_t amt, int32_t *nwritten) {
  LOG (INFO) << "Calling SSLSocket::Write() " << is_server_;
  if (ssl_ == NULL) return Status::NetworkError("SSL_write: SSL context unavailable");
  int32_t bytes_written = SSL_write(ssl_, buf, amt);
  if (bytes_written <= 0) {
    if (SSL_get_error(ssl_, bytes_written) == SSL_ERROR_WANT_WRITE) {
      *nwritten = 0;
      return Status::OK();
    }
    return Status::NetworkError(GetLastError(errno));
  }
  *nwritten = bytes_written;
  LOG (INFO) << "SSLSocket::Write() Wrote " << bytes_written << " bytes." << is_server_;
  return Status::OK();
}

Status SSLSocket::Writev(const struct ::iovec *iov, int iov_len,
                      int32_t *nwritten) {
  if (ssl_ == NULL) return Status::NetworkError("SSL_writev: SSL context unavailable");

  int32_t total_written = 0;
  for (int i = 0; i < iov_len; ++i) {
    int32_t frame_size = iov[i].iov_len;
    int32_t bytes_written = SSL_write(ssl_, iov[i].iov_base, frame_size);
    if (bytes_written <= 0) {
      if (SSL_get_error(ssl_, bytes_written) == SSL_ERROR_WANT_WRITE) {
        *nwritten = 0;
        return Status::OK();
      }
      return Status::NetworkError(GetLastError(errno));
    }
    total_written += bytes_written;
    if (bytes_written < frame_size) break;
  }
  *nwritten = total_written;
  return Status::OK();
}

Status SSLSocket::Recv(uint8_t *buf, int32_t amt, int32_t *nread) {
  LOG (INFO) << "Calling SSLSocket::Recv() " << is_server_;
  if (ssl_ == NULL) return Status::NetworkError("SSL_read: SSL context unavailable");
  int32_t bytes_read = SSL_read(ssl_, buf, amt);
  if (bytes_read <= 0) {
    if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_WANT_READ) {
      *nread = 0;
      return Status::OK();
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_WANT_WRITE) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_WANT_WRITE_ERROR!";
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_SYSCALL) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_ERROR_SYSCALL!";
      int e = ERR_get_error();
      LOG (INFO) << "e is " << e;
      if (e == 0 && errno == EINTR) {
        LOG (INFO) << "It's all fine!!";
        *nread = 0;
        return Status::OK();
      }
      LOG (INFO) << "It's NOT fine!!";
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_SSL) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_ERROR_SSL!";
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_WANT_CONNECT) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_WANT_CONNECT!";
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_WANT_ACCEPT) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_WANT_ACCEPT!";
    } else if (SSL_get_error(ssl_, bytes_read) == SSL_ERROR_ZERO_RETURN) {
      LOG (INFO) << "SSLSocket::Recv()  SSL_WANT_ACCEPT!";
    } else {
      LOG (INFO) << "SSLSocket::Recv() " << SSL_get_error(ssl_, bytes_read);
    }
    return Status::NetworkError(GetLastError(errno));
  }
  *nread = bytes_read;
  LOG (INFO) << "SSLSocket::Recv() Read " << bytes_read << " bytes.";
  return Status::OK();
}

Status SSLSocket::Close() {
  LOG (INFO) << "Calling SSLSocket::Close() " << is_server_;
  if (ssl_ == NULL) return Status::NetworkError("SSL_close: SSL context unavailable");

  int32_t ret = SSL_shutdown(ssl_);
  // Do a bi-directional shutdown.
  if (ret == 0) ret = SSL_shutdown(ssl_);

  if (ret < 0) {
    LOG (INFO) << "SSL_Shutdown: " << GetLastError(errno);
  }
  SSL_free(ssl_);
  ssl_ = NULL;
  ERR_remove_state(0);
  return Socket::Close();
}

}
