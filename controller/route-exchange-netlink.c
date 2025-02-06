/*
 * Copyright (c) 2025 Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#include <config.h>

#include <errno.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>

#include "netlink-socket.h"
#include "openvswitch/hmap.h"
#include "hmapx.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-util.h"
#include "route-table.h"
#include "route.h"

#include "route-exchange-netlink.h"

VLOG_DEFINE_THIS_MODULE(route_exchange_netlink);

#define TABLE_ID_VALID(table_id) (table_id != RT_TABLE_UNSPEC &&              \
                                  table_id != RT_TABLE_COMPAT &&              \
                                  table_id != RT_TABLE_DEFAULT &&             \
                                  table_id != RT_TABLE_MAIN &&                \
                                  table_id != RT_TABLE_LOCAL &&               \
                                  table_id != RT_TABLE_MAX)

int
re_nl_create_vrf(const char *ifname, uint32_t table_id)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to create VRF using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    size_t linkinfo_off, infodata_off;
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    int err;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_NEWLINK,
                        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    ifinfo = ofpbuf_put_zeros(&request, sizeof *ifinfo);
    nl_msg_put_string(&request, IFLA_IFNAME, ifname);

    ifinfo->ifi_change = ifinfo->ifi_flags = IFF_UP;
    linkinfo_off = nl_msg_start_nested(&request, IFLA_LINKINFO);
    nl_msg_put_string(&request, IFLA_INFO_KIND, "vrf");
    infodata_off = nl_msg_start_nested(&request, IFLA_INFO_DATA);
    nl_msg_put_u32(&request, IFLA_VRF_TABLE, table_id);
    nl_msg_end_nested(&request, infodata_off);
    nl_msg_end_nested(&request, linkinfo_off);

    err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);

    return err;

}

int
re_nl_delete_vrf(const char *ifname)
{
    struct ifinfomsg *ifinfo;
    struct ofpbuf request;
    int err;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    ifinfo = ofpbuf_put_zeros(&request, sizeof *ifinfo);
    nl_msg_put_string(&request, IFLA_IFNAME, ifname);
    err = nl_transact(NETLINK_ROUTE, &request, NULL);

    ofpbuf_uninit(&request);

    return err;
}

static int
modify_route(uint32_t type, uint32_t flags_arg, uint32_t table_id,
             const struct in6_addr *dst, unsigned int plen)
{
    uint32_t flags = NLM_F_REQUEST | NLM_F_ACK;
    bool is_ipv4 = IN6_IS_ADDR_V4MAPPED(dst);
    struct ofpbuf request;
    struct rtmsg *rt;
    int err;

    flags |= flags_arg;

    ofpbuf_init(&request, 0);
    nl_msg_put_nlmsghdr(&request, 0, type, flags);
    rt = ofpbuf_put_zeros(&request, sizeof *rt);
    rt->rtm_family = is_ipv4 ? AF_INET : AF_INET6;
    rt->rtm_table = RT_TABLE_UNSPEC; /* RTA_TABLE attribute allows id > 256 */
    /* Manage only OVN routes */
    rt->rtm_protocol = RTPROT_OVN;
    rt->rtm_type = RTN_BLACKHOLE;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_dst_len = plen;

    nl_msg_put_u32(&request, RTA_TABLE, table_id);

    if (is_ipv4) {
        nl_msg_put_be32(&request, RTA_DST, in6_addr_get_mapped_ipv4(dst));
    } else {
        nl_msg_put_in6_addr(&request, RTA_DST, dst);
    }

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds msg = DS_EMPTY_INITIALIZER;

        if (type == RTM_DELROUTE) {
            ds_put_cstr(&msg, "Removing blackhole route from ");
        } else {
            ds_put_cstr(&msg, "Adding blackhole route to ");
        }

        ds_put_format(&msg, "table %"PRIu32 " for prefix ", table_id);
        if (IN6_IS_ADDR_V4MAPPED(dst)) {
            ds_put_format(&msg, IP_FMT,
                          IP_ARGS(in6_addr_get_mapped_ipv4(dst)));
        } else {
            ipv6_format_addr(dst, &msg);
        }
        ds_put_format(&msg, "/%u", plen);

        VLOG_DBG("%s", ds_cstr(&msg));
        ds_destroy(&msg);
    }

    err = nl_transact(NETLINK_ROUTE, &request, NULL);
    ofpbuf_uninit(&request);

    return err;
}

int
re_nl_add_route(uint32_t table_id, const struct in6_addr *dst,
                unsigned int plen)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to add route using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    return modify_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, table_id,
                        dst, plen);
}

int
re_nl_delete_route(uint32_t table_id, const struct in6_addr *dst,
                   unsigned int plen)
{
    if (!TABLE_ID_VALID(table_id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl,
                     "attempt to delete route using invalid table id %"PRIu32,
                     table_id);
        return EINVAL;
    }

    return modify_route(RTM_DELROUTE, 0, table_id, dst, plen);
}

void
re_nl_learned_routes_destroy(struct ovs_list *learned_routes)
{
    struct re_nl_received_route_node *rr;
    LIST_FOR_EACH_POP (rr, list_node, learned_routes) {
        free(rr);
    }
}

struct route_msg_handle_data {
    const struct sbrec_datapath_binding *db;
    struct hmapx *routes_to_advertise;
    struct ovs_list *learned_routes;
    const struct hmap *routes;
};

static void
handle_route_msg(const struct route_table_msg *msg, void *data)
{
    const struct route_data *rd = &msg->rd;
    struct route_msg_handle_data *handle_data = data;
    struct advertise_route_entry *ar;
    int err;

    /* This route is not from us, so we learn it. */
    if (rd->rtm_protocol != RTPROT_OVN) {
        if (prefix_is_link_local(&rd->rta_dst, rd->rtm_dst_len)) {
            return;
        }
        struct route_data_nexthop *nexthop;
        LIST_FOR_EACH (nexthop, nexthop_node, &rd->nexthops) {
            if (ipv6_is_zero(&nexthop->addr)) {
                /* This is most likely an address on the local link.
                 * As we just want to learn remote routes we do not need it.*/
                continue;
            }
            struct re_nl_received_route_node *rr = xmalloc(sizeof *rr);
            rr->db = handle_data->db;
            rr->prefix = rd->rta_dst;
            rr->plen = rd->rtm_dst_len;
            rr->nexthop = nexthop->addr;
            memcpy(rr->ifname, nexthop->ifname, IFNAMSIZ);
            rr->ifname[IFNAMSIZ] = 0;
            ovs_list_push_back(handle_data->learned_routes, &rr->list_node);
        }
        return;
    }

    uint32_t hash = advertise_route_hash(&rd->rta_dst, rd->rtm_dst_len);
    HMAP_FOR_EACH_WITH_HASH (ar, node, hash, handle_data->routes) {
        if (ipv6_addr_equals(&ar->addr, &rd->rta_dst)
                && ar->plen == rd->rtm_dst_len) {
            hmapx_find_and_delete(handle_data->routes_to_advertise, ar);
            return;
        }
    }
    err = re_nl_delete_route(rd->rta_table_id, &rd->rta_dst,
                             rd->rtm_dst_len);
    if (err) {
        char addr_s[INET6_ADDRSTRLEN + 1];
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_WARN_RL(&rl, "Delete route table_id=%"PRIu32" dst=%s plen=%d "
                     "failed: %s", rd->rta_table_id,
                     ipv6_string_mapped(
                         addr_s, &rd->rta_dst) ? addr_s : "(invalid)",
                     rd->rtm_dst_len,
                     ovs_strerror(err));
    }
}

void
re_nl_sync_routes(uint32_t table_id, const struct hmap *routes,
                  struct ovs_list *learned_routes,
                  const struct sbrec_datapath_binding *db)
{
    struct hmapx routes_to_advertise = HMAPX_INITIALIZER(&routes_to_advertise);
    struct advertise_route_entry *ar;
    HMAP_FOR_EACH (ar, node, routes) {
        hmapx_add(&routes_to_advertise, ar);
    }

    /* Remove routes from the system that are not in the routes hmap and
     * remove entries from routes hmap that match routes already installed
     * in the system. */
    struct route_msg_handle_data data = {
        .routes = routes,
        .routes_to_advertise = &routes_to_advertise,
        .learned_routes = learned_routes,
        .db = db,
    };
    route_table_dump_one_table(table_id, handle_route_msg,
                               &data);

    /* Add any remaining routes in the routes hmap to the system routing
     * table. */
    struct hmapx_node *hn;
    HMAPX_FOR_EACH (hn, &routes_to_advertise) {
        ar = hn->data;
        int err = re_nl_add_route(table_id, &ar->addr, ar->plen);
        if (err) {
            char addr_s[INET6_ADDRSTRLEN + 1];
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
            VLOG_WARN_RL(&rl, "Add route table_id=%"PRIu32" dst=%s "
                         "plen=%d: %s",
                         table_id,
                         ipv6_string_mapped(
                             addr_s, &ar->addr) ? addr_s : "(invalid)",
                         ar->plen,
                         ovs_strerror(err));
        }
    }
    hmapx_destroy(&routes_to_advertise);
}
