/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ROUTE_TABLE_NOTIFY_H
#define ROUTE_TABLE_NOTIFY_H 1

#include <stdbool.h>
#include "openvswitch/hmap.h"
#include "hash.h"

struct route_table_watch_request {
    struct hmap_node node;
    uint32_t table_id;
};

static inline uint32_t
route_table_notify_hash_watch(uint32_t table_id)
{
    return hash_add(0, table_id);
}

/* returns true if any route table has changed enough that we need to learn
 * new routes. */
bool route_table_notify_run(void);
void route_table_notify_wait(void);
/* updates the list of route table watches that are currently active.
 * hmap should contain struct route_table_watch_request */
void route_table_notify_update_watches(struct hmap *route_table_watches);

#endif /* ROUTE_TABLE_NOTIFY_H */
