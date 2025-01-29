/*
 * Copyright (c) 2024, STACKIT GmbH & Co. KG
 *
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

/* Sets "changed" to true if any route table has changed enough that we need
 * to learn new routes. */
void route_table_notify_run(bool *changed);
void route_table_notify_wait(void);

/* Add a watch request to the hmap. The hmap should later be passed to
 * route_table_notify_update_watches*/
void route_table_add_watch_request(struct hmap *route_table_watches,
                                   uint32_t table_id);

/* Updates the list of route table watches that are currently active.
 * hmap should contain struct route_table_watch_request */
void route_table_notify_update_watches(struct hmap *route_table_watches);

#endif /* ROUTE_TABLE_NOTIFY_H */
