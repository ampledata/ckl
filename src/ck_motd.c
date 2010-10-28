/*
 * Licensed to Cloudkick, Inc under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * libcloud.org licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ckl.h"
#include "ckl_version.h"

static int do_motd(ckl_conf_t *conf, char* node_id)
{
  int rv;
  ckl_transport_t *transport = calloc(1, sizeof(ckl_transport_t));

  rv = ckl_transport_init(transport, conf);
  if (rv < 0) {
    ckl_error_out("transport_init failed.");
    return rv;
  }

  rv = ckl_transport_motd(transport, conf, node_id);
  if (rv < 0) {
    ckl_error_out("ckl_transport_list failed.");
    return rv;
  }

  ckl_transport_free(transport);

  return 0;
}

int main(int argc, char *const *argv)
{
  int rv;
  ckl_conf_t *conf = calloc(1, sizeof(ckl_conf_t));

  curl_global_init(CURL_GLOBAL_ALL);
  rv = ckl_conf_init(conf);

  if (rv < 0) {
    ckl_error_out("conf_init failed");
  }

  // TODO: try grabbing file path from an environment variable
  char *node_id_file = "/usr/lib/cloudkick-agent/node_id";
  FILE *fp = fopen(node_id_file, "r");
  if (fp == NULL) {
    ckl_error_out("couldn't open node_id file");
  }
  char node_id[128];
  char *p = NULL;
  p = fgets(node_id, sizeof(node_id), fp);

  fclose(fp);

  do_motd(conf, node_id);

  ckl_conf_free(conf);

  curl_global_cleanup();

  return rv;
}
