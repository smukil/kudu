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

#include "kudu/security/init.h"

#include <krb5/krb5.h>
#include <string>

#include "kudu/gutil/strings/util.h"
#include "kudu/util/flags.h"
#include "kudu/util/flag_tags.h"
#include "kudu/util/net/net_util.h"
#include "kudu/util/scoped_cleanup.h"
#include "kudu/util/thread.h"

DEFINE_string(keytab, "", "Path to the Kerberos Keytab for this server");
TAG_FLAG(keytab, experimental);

DEFINE_string(kerberos_principal, "kudu/_HOST",
              "Kerberos principal that this daemon will log in as. The special token "
              "_HOST will be replaced with the FQDN of the local host.");
TAG_FLAG(kerberos_principal, experimental);

DEFINE_int32(kerberos_reinit_interval, 60, "Duration in minutes before which an attempt to "
             "renew or reacquire a ticket is made.");
TAG_FLAG(kerberos_reinit_interval, experimental);

// TODO(todd): this currently only affects the keytab login which is used
// for client credentials, but doesn't affect the SASL server code path.
// We probably need to plumb the same configuration into the RPC code.

using std::string;

namespace kudu {
namespace security {

namespace {

struct KinitContext {
  krb5_principal principal;
  krb5_keytab keytab;
  krb5_ccache ccache;
  krb5_get_init_creds_opt* opts;
  krb5_context krb5_ctx;
};
static struct KinitContext* kinit_ctx;

static scoped_refptr<Thread> renew_thread;

Status Krb5CallToStatus(krb5_context ctx, krb5_error_code code) {
  if (code == 0) return Status::OK();
  return Status::RuntimeError(krb5_get_error_message(ctx, code));
}
#define KRB5_RETURN_NOT_OK_PREPEND(call, prepend) \
  RETURN_NOT_OK_PREPEND(Krb5CallToStatus(kinit_ctx->krb5_ctx, (call)), (prepend))

#define KRB5_LOG_NOT_OK_ERROR(call, prepend_msg, ret) \
  *ret = (call); \
  if (*ret) { \
  LOG(ERROR) << prepend_msg << " " << Krb5CallToStatus(kinit_ctx->krb5_ctx, *ret).ToString(); \
  }

void PrintTicketsInternal() {
  {
    krb5_cc_cursor cursor;
    krb5_creds creds;
    LOG (INFO) << "Going to start printing " << kinit_ctx;
    krb5_error_code rc = krb5_cc_start_seq_get(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor);
    if (rc) LOG (INFO) << "FAILED TO krb5_cc_start_seq_get()";

    LOG (INFO) << "Going to start iterating";
    while (!(rc = krb5_cc_next_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor, &creds))) {
      if (krb5_is_config_principal(kinit_ctx->krb5_ctx, creds.server)) continue;
      LOG (INFO) << "Creds are: " << creds.server->data[0].data << " | " << creds.server->data[1].data;
      LOG (INFO) << "Creds starttime: " << creds.times.starttime;
      LOG (INFO) << "Creds endtime: " << creds.times.endtime;
      LOG (INFO) << "Creds renew till: " << creds.times.renew_till;
      LOG (INFO) << "End - start: " << creds.times.endtime - creds.times.starttime;
      LOG (INFO) << "Renew - start: " << creds.times.renew_till - creds.times.starttime;
      time_t now = time(NULL);
      LOG (INFO) << "Time now: " << now;
    }
  }
}

void RenewThread() {

  LOG (INFO) << "Started Kerberos renewal thread " << kinit_ctx;
  while (true) {

  {
    krb5_cc_cursor cursor;
    krb5_creds creds;
    krb5_error_code rc = krb5_cc_start_seq_get(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor);
    if (rc) LOG (INFO) << "FAILED TO krb5_cc_start_seq_get()";

    while (!(rc = krb5_cc_next_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor, &creds))) {
      if (krb5_is_config_principal(kinit_ctx->krb5_ctx, creds.server)) continue;
      LOG (INFO) << "Creds are: " << creds.server->data[0].data << " | " << creds.server->data[1].data;
      LOG (INFO) << "Creds starttime: " << creds.times.starttime;
      LOG (INFO) << "Creds endtime: " << creds.times.endtime;
      LOG (INFO) << "Creds renew till: " << creds.times.renew_till;
      LOG (INFO) << "End - start: " << creds.times.endtime - creds.times.starttime;
      LOG (INFO) << "Renew - start: " << creds.times.renew_till - creds.times.starttime;
      time_t now = time(NULL);
      LOG (INFO) << "Time now: " << now;
    }
  }
    // Sleep first as this starts immediately after the first Kinit.
    //SleepFor(MonoDelta::FromSeconds(FLAGS_kerberos_reinit_interval * 60));
    SleepFor(MonoDelta::FromSeconds(2));

    krb5_cc_cursor cursor;
    {
      krb5_error_code ret;
      KRB5_LOG_NOT_OK_ERROR(krb5_cc_start_seq_get(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor),
                            "Kerberos error: Failed to peek into ccache", &ret);
      if (ret) continue;
    }

    krb5_creds creds;
    krb5_error_code rc;
    while (!(rc = krb5_cc_next_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor, &creds))) {
      if (krb5_is_config_principal(kinit_ctx->krb5_ctx, creds.server)) {
        krb5_free_cred_contents(kinit_ctx->krb5_ctx, &creds);
        continue;
      }
      if (strcmp(creds.server->data[0].data, "krbtgt") ||
          strcmp(creds.server->data[1].data, kinit_ctx->principal->realm.data) ||
          creds.server->length != 2) {
        krb5_free_cred_contents(kinit_ctx->krb5_ctx, &creds);
        continue;
      }

      time_t now = time(NULL);
      MonoDelta current_time = MonoDelta::FromSeconds(now);
      MonoDelta ticket_expiry = MonoDelta::FromSeconds(creds.times.endtime);
      MonoDelta renew_till = MonoDelta::FromSeconds(creds.times.renew_till);
      MonoDelta renew_deadline = MonoDelta::FromSeconds(renew_till.ToSeconds() - 30);

      krb5_creds new_creds;
      auto cleanup_new_creds = MakeScopedCleanup([&]() {
          krb5_free_cred_contents(kinit_ctx->krb5_ctx, &new_creds); });

      if (ticket_expiry.LessThan(current_time) || renew_deadline.LessThan(current_time)) {
        // Acquire new ticket.
        krb5_error_code ret;
        KRB5_LOG_NOT_OK_ERROR(krb5_get_init_creds_keytab(kinit_ctx->krb5_ctx, &creds,
                                                        kinit_ctx->principal,
                                                        kinit_ctx->keytab, 0 /* valid from now */,
                                                        nullptr /* TKT service name */,
                                                        kinit_ctx->opts),
                             "Reacquire error: unable to login from keytab", &ret);
        LOG (INFO) << "Successfully reacquired a new kerberos TGT";
      } else {
        // Renew existing ticket.
        krb5_error_code ret;
        KRB5_LOG_NOT_OK_ERROR(krb5_get_renewed_creds(kinit_ctx->krb5_ctx, &new_creds,
                                                     kinit_ctx->principal,
                                                     kinit_ctx->ccache, nullptr),
                              "Renew error: Failed to renew ticket", &ret);
        if (ret) goto end;
        KRB5_LOG_NOT_OK_ERROR(krb5_cc_initialize(kinit_ctx->krb5_ctx, kinit_ctx->ccache,
                                                 kinit_ctx->principal),
                              "Renew error: Failed to re-initialize ccache", &ret);
        if (ret) goto end;
        KRB5_LOG_NOT_OK_ERROR(krb5_cc_store_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache,
                                                 &new_creds),
                              "Renew error: Failed to store credentials in ccache", &ret);
        if (ret) goto end;
        LOG (INFO) << "Successfully renewed kerberos TGT";
      }

      end:
      krb5_free_cred_contents(kinit_ctx->krb5_ctx, &creds);
      break;

    }
    krb5_cc_end_seq_get(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor);

    //SleepFor(MonoDelta::FromSeconds(1));
  }
}

// Equivalent implementation of 'kinit -kt <keytab path> <principal>'.
//
// This logs in from the given keytab as the given principal, returning
// RuntimeError if any part of this process fails.
//
// If the log-in is successful, then the default ticket cache is overwritten
// with the credentials of the newly logged-in principal.
Status Kinit(const string& keytab_path, const string& principal) {
  if (krb5_init_context(&kinit_ctx->krb5_ctx) != 0) {
    return Status::RuntimeError("could not initialize krb5 library");
  }

  // Parse the principal
  KRB5_RETURN_NOT_OK_PREPEND(krb5_parse_name(kinit_ctx->krb5_ctx, principal.c_str(),
                                             &kinit_ctx->principal),
                             "could not parse principal");

  KRB5_RETURN_NOT_OK_PREPEND(krb5_kt_resolve(kinit_ctx->krb5_ctx, keytab_path.c_str(), 
                                             &kinit_ctx->keytab),
                             "unable to resolve keytab");

  KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_default(kinit_ctx->krb5_ctx, &kinit_ctx->ccache),
                             "unable to get default credentials cache");

  KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_opt_alloc(kinit_ctx->krb5_ctx, &kinit_ctx->opts),
                             "unable to allocate get_init_creds_opt struct");

#ifndef __APPLE__
  KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_opt_set_out_ccache(kinit_ctx->krb5_ctx,
                                                                    kinit_ctx->opts,
                                                                    kinit_ctx->ccache),
                             "unable to set init_creds options");
#endif

  krb5_creds creds;
  KRB5_RETURN_NOT_OK_PREPEND(krb5_get_init_creds_keytab(kinit_ctx->krb5_ctx, &creds,
                                                        kinit_ctx->principal,
                                                        kinit_ctx->keytab, 0 /* valid from now */,
                                                        nullptr /* TKT service name */,
                                                        kinit_ctx->opts),
                             "unable to login from keytab");
  auto cleanup_creds = MakeScopedCleanup([&]() {
      krb5_free_cred_contents(kinit_ctx->krb5_ctx, &creds); });

/*
  krb5_cc_cursor cursor;
  int rc = krb5_cc_start_seq_get(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor);
  if (rc) LOG (INFO) << "FAILED TO krb5_cc_start_seq_get()";

  while (!(rc = krb5_cc_next_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &cursor, &creds))) {
    if (krb5_is_config_principal(kinit_ctx->krb5_ctx, creds.server)) continue;
    LOG (INFO) << "Creds are: " << creds.server->data[0].data << " | " << creds.server->data[1].data;
    LOG (INFO) << "Creds starttime: " << creds.times.starttime;
    LOG (INFO) << "Creds endtime: " << creds.times.endtime;
    LOG (INFO) << "Creds renew till: " << creds.times.renew_till;
    LOG (INFO) << "End - start: " << creds.times.endtime - creds.times.starttime;
    LOG (INFO) << "Renew - start: " << creds.times.renew_till - creds.times.starttime;
  }
*/

#ifdef __APPLE__
  // Heimdal krb5 doesn't have the 'krb5_get_init_creds_opt_set_out_ccache' option,
  // so use this alternate route.
  KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_initialize(kinit_ctx->krb5_ctx, kinit_ctx->ccache,
                                                kinit_ctx->principal),
                             "could not init ccache");

  KRB5_RETURN_NOT_OK_PREPEND(krb5_cc_store_cred(kinit_ctx->krb5_ctx, kinit_ctx->ccache, &creds),
                             "could not store creds in cache");
#endif
  return Status::OK();
}

Status GetLoginPrincipal(string* principal) {
  string p = FLAGS_kerberos_principal;
  string hostname;
  // Try to fill in either the FQDN or hostname.
  if (!GetFQDN(&hostname).ok()) {
    RETURN_NOT_OK(GetHostname(&hostname));
  }
  GlobalReplaceSubstring("_HOST", hostname, &p);
  *principal = p;
  return Status::OK();
}

} // anonymous namespace

void PrintTickets() {
  PrintTicketsInternal();
}

Status InitKerberosForServer() {
  if (FLAGS_keytab.empty()) return Status::OK();

  // Have the daemons use an in-memory ticket cache, so they don't accidentally
  // pick up credentials from test cases or any other daemon.
  // TODO(todd): extract these krb5 env vars into some constants since they're
  // typo-prone.
  setenv("KRB5CCNAME", "MEMORY:kudu", 1);
  setenv("KRB5_KTNAME", FLAGS_keytab.c_str(), 1);

  kinit_ctx = new KinitContext();
  string principal;
  RETURN_NOT_OK(GetLoginPrincipal(&principal));
  RETURN_NOT_OK_PREPEND(Kinit(FLAGS_keytab, principal), "unable to kinit");

  // Start a renewal thread here.
  RETURN_NOT_OK(Thread::Create("kerberos", "renewal thread", &RenewThread, &renew_thread));

  return Status::OK();
}

} // namespace security
} // namespace kudu
