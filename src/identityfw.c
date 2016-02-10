/*
  Copyright (C) 2015-2018 www.shield.com - All Rights Reserved.
  Shield UTM/NGFW [http://www.shield.com]
  You are granted a non-exclusive License to use the Shield UTM/NGFW
  software for any purposes for an unlimited period of time. The software
  product under this License is provided free of charge.
  Even though a license fee is not paid for the use of Freeware Version
  software, it does not mean that there are no conditions for using such
  software:

   1. The Software may be installed and used by the Licensee for any legal
      purpose.

   2. The Software may be installed and used by the Licensee on any number
      of systems.

   3. The Software can be copied and distributed under the condition that
      original copyright notice and disclaimer of warranty will stay intact,
      and the Licensee will not charge money or fees for the Software
      product, except to cover distribution costs.

   4. The Licensee will not have any proprietary rights in and to the
      Software. The Licensee acknowledges and agrees that the Licensor retains
      all copyrights and other proprietary rights in and to the Software.

   5. Use within the scope of this License is free of charge and no royalty
      or licensing fees shall be paid by the Licensee.
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/inet.h>
#include  <linux/vmalloc.h>
#include "net/netfilter/nf_conntrack.h"
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>

#include "identityfw.h"

struct sock *nl_sk = NULL;

#define NETLINK_USER  31
#define MAX_USERS_BIT 10
#define USER_NAME_LEN 32
#define NULL_TERM '\0'
#define MAX_LINE_LEN 100

static int num_packets = 10;
static int maxdatalen = 1500; // this is the default

DEFINE_HASHTABLE(user_map, MAX_USERS_BIT);
DEFINE_SPINLOCK(user_tbl_lock);

static struct proc_dir_entry* identityfw;

struct user_grp_entry {
    char usergroup[MAX_USERGROUP_LEN];
    struct list_head list_node;
};

struct user_entry {
    int addr;
    char user[USER_NAME_LEN];
    struct user_grp_entry user_groups;

    struct hlist_node user_node;
};

#define UPDATE_USER   0
#define DELETE_USER   1
#define RELOAD_USER   2
#define FLUSH_ALL     3
#define PRINT_CACHE   4

DEFINE_SPINLOCK(user_lock);

#define CONFIG_NETFILTER_XT_MATCH_IDENTITYFW_DEBUG 0

#ifdef CONFIG_NETFILTER_XT_MATCH_IDENTITYFW_DEBUG
    #define IDFW_DBG(format,args...) printk(format,##args)
#else
    #define IDFW_DBG(format,args...)
#endif

unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}

static int total_acct_packets(struct nf_conn *ct)
{
    struct nf_conn_counter *acct;

    BUG_ON(ct == NULL);
    acct = nf_conn_acct_find(ct);
    if (!acct)
        return 0;
    return (atomic64_read(&acct[IP_CT_DIR_ORIGINAL].packets) + atomic64_read(&acct[IP_CT_DIR_REPLY].packets));
}

void print_users_in_cache() {
    struct user_entry *temp;
    struct user_grp_entry* ug_entry;

    int i = 0,j;
    unsigned char ipaddress[4]  = {0,0,0,0};

    printk("########################################\n");
    printk("Printing the entries in user_auth_cache.\n");
    printk("\tEntries:\n");
    hash_for_each(user_map, i, temp, user_node) {
        i++;
        for (j=0; j<4; j++)
        {
            ipaddress[j] = ( temp->addr >> (j*8) ) & 0xFF;
        }
        printk("\n");
        printk("%s :: %d.%d.%d.%d\n",temp->user, ipaddress[0],ipaddress[1],ipaddress[2],ipaddress[3]);

        list_for_each_entry(ug_entry, &temp->user_groups.list_node, list_node) {
            printk(KERN_INFO "%s ", ug_entry->usergroup );
        }

        printk("\n");
    }
    printk("########################################\n");
}

static struct user_entry* find_user_entry(int addr) {
    struct user_entry *found;

    hash_for_each_possible(user_map, found, user_node, addr)    {
        if (found->addr == addr)
            return found;
    }

    return NULL;
}

static void _delete_user_entry(struct user_entry* found)
{
    struct user_grp_entry *user_group, *temp;
     if ( found == NULL ) {
        return;
    }

    list_for_each_entry_safe(user_group, temp, &found->user_groups.list_node, list_node) {
        list_del(&user_group->list_node);
           kfree(user_group);
    }

    hash_del(&found->user_node);
    kfree(found);
}

static long long atoi(char *psz_buf) {
    char *pch = psz_buf;
    int base = 0;

    while (isspace(*pch))
        pch++;

    if (*pch == '-' || *pch == '+') {
        base = 10;
        pch++;
    } else if (*pch && tolower(pch[strlen(pch) - 1]) == 'h') {
        base = 16;
    }

    return simple_strtol(pch, NULL, base);
}

static void _update_user_map(int addr, char* user, char* usergroups) {
    struct user_entry* entry;
    struct user_entry* found;
    struct user_grp_entry* ug_entry;
    unsigned long flags;
    char* record = NULL;

    if ( addr == NULL )
        return;

    if ( user == NULL || strlen(user) == 0 || strlen(user) > USER_NAME_LEN )
        return;

    if ( usergroups== NULL || strlen(usergroups) == 0 || strlen(usergroups) > MAX_USERGROUP_LEN )
        return;

    entry = kzalloc(sizeof(struct user_entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->addr = addr;
    strncpy(entry->user, user, strlen(user));
    INIT_LIST_HEAD(&(entry->user_groups.list_node));

    do {
        record = strsep(&usergroups, ",");

        if (record != NULL) {
            ug_entry = kzalloc(sizeof(struct user_grp_entry), GFP_KERNEL);
            strncpy(ug_entry->usergroup, record, strlen(record));
            INIT_LIST_HEAD(&ug_entry->list_node);
            list_add_tail(&ug_entry->list_node, &entry->user_groups.list_node);
        }
        else {
            break;
        }
    } while ( 1 );

    spin_lock_irqsave(&user_tbl_lock, flags);

    found = find_user_entry(addr);

    if (found) {
        _delete_user_entry(found);
        found = entry;
    }
    else {
        found = entry;
    }

    hash_add(user_map, &found->user_node, found->addr);

    spin_unlock_irqrestore(&user_tbl_lock, flags);
}

static void update_user_map(char* msgbuf)
{
    long int addr = 0;
    char *username;
    char *usergroups;
    char* ip;
    char* record = NULL;
    char *msgptr = msgbuf;

    do
    {
        record = strsep(&msgptr, ";");
        if ( record == NULL ) {
            break;
        }

        ip = strsep(&record, ":");
        if ( ip == NULL ) {
            break;
        }
        addr=inet_addr(ip);

        username = strsep(&record, ":");
        if ( username == NULL ) {
            break;
        }
        IDFW_DBG(" user name :%s \n",username);
        usergroups = strsep(&record, ":");
        if ( usergroups == NULL ) {
            break;
        }
        IDFW_DBG(" user group :%s \n",usergroups);

        _update_user_map(addr, username, usergroups);
    } while (1);
}

static void reload_user_map(char* msgbuf) {
    char* record;
    char *msgptr = msgbuf;

    do {
        record = strsep(&msgptr, ";");

        if (record != NULL) {
            update_user_map(record);
        }
        else {
            break;
        }
    } while ( 1 );
}

static void flush_user_map() {
    struct user_entry* found;
    int i = 0;

    hash_for_each(user_map, i, found, user_node) {
        _delete_user_entry(found);
    }
}

static void _delete_user(int addr, char* user) {
    struct user_entry* found;
    unsigned long flags;

    if ( user == NULL || strlen(user) == 0 || strlen(user) > USER_NAME_LEN )
        return;

    spin_lock_irqsave(&user_tbl_lock, flags);

    found = find_user_entry(addr);
    if ( found != NULL ) {
        _delete_user_entry(found);
    }

    spin_unlock_irqrestore(&user_tbl_lock, flags);
}

static void delete_user(char* msgbuf) {
    char *username;
    char *ip;
    char *record = NULL;
    char *msgptr = msgbuf;
    int addr=0;

    do {
        record = strsep(&msgptr, ";");
        if (record == NULL) {
            break;
        }

        ip = strsep(&record, ":");
        if (ip == NULL) {
            break;
        }
        addr=inet_addr(ip);
        username = strsep(&record, ":");
        if (username == NULL) {
            break;
        }

        _delete_user(addr, username);
    } while (1);
}

#if 0
static void _delete_user_by_name(char *user) {
    int i;
    struct user_entry *temp;

    hash_for_each(user_map, i, temp, user_node) {
        if(strcmp(temp->user, user) == 0) {
            _delete_user_entry(temp);
    }
}
#endif

static void handle_user_message(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    char* msg;
    char flag;
    char *id;

    nlh = (struct nlmsghdr*) skb->data;
        msg = (char*) nlmsg_data(nlh);

    id = strsep(&msg, ":");

    flag = atoi(id);

    switch (flag) {
        case UPDATE_USER:
            IDFW_DBG(" Receiving command from update \n");
            update_user_map(msg);
            break;
        case DELETE_USER:
            delete_user(msg);
            break;
        case RELOAD_USER:
            reload_user_map(msg);
            break;
        case FLUSH_ALL:
            flush_user_map();
            break;
        case PRINT_CACHE:
            print_users_in_cache();
            break;
        default:
            break;
    }
}

static int can_handle(const struct sk_buff *skb)
{
    struct iphdr iphdr_tmp;
    struct iphdr *iphdr;
    int offset;

    if(!ip_hdr(skb)) /* not IP */
        return 0;

    offset = ((uintptr_t)ip_hdr(skb)) - ((uintptr_t)skb->data);
    iphdr = skb_header_pointer(skb, offset, sizeof(*iphdr), &iphdr_tmp);

    if (!iphdr)
        return 0;

    if(iphdr->protocol != IPPROTO_TCP &&
       iphdr->protocol != IPPROTO_UDP &&
       iphdr->protocol != IPPROTO_ICMP)
        return 0;
    return 1;
}

static bool match(const struct sk_buff *skbin, struct xt_action_param *par)
{
    struct sk_buff *sock_buff;
    struct iphdr *ip_header;
    int ipaddr=0;
    char ip[20] ;
    unsigned int match_result = 0;
    unsigned int user_match = 0;
    unsigned int group_match = 0;
    struct user_grp_entry* ug_entry;

    struct sk_buff * skb = (struct sk_buff *)skbin;

    const struct xt_identityfw_info * info =
        par->matchinfo;

    enum ip_conntrack_info master_ctinfo, ctinfo;
    struct nf_conn *master_conntrack, *conntrack;

    IDFW_DBG("Inside match function... match begin \n");

    if ( strlen(info->user) == 0 && strlen(info->usergroup) == 0 ) {
        printk(KERN_WARNING  "identityfw: match object not found.\n");
        return info->invert;
    }

    spin_lock_bh(&user_lock);

    if (!can_handle(skbin)) {
        printk(KERN_WARNING  "identityfw: This is some protocol I can't handle.\n");
        spin_unlock_bh(&user_lock);
        return info->invert;
    }

    conntrack = nf_ct_get(skbin, &ctinfo);
    master_conntrack = nf_ct_get(skbin, &master_ctinfo);
    if(!(conntrack) || !(master_conntrack)) {
        printk(KERN_WARNING "identityfw: couldn't get conntrack.\n");
        spin_unlock_bh(&user_lock);
        return info->invert;
    }

    while (master_ct(master_conntrack) != NULL)
        master_conntrack = master_ct(master_conntrack);

    IDFW_DBG(" master_conntrack  \n");

    if(!info->pkt &&
       master_conntrack->identityfw.user || master_conntrack->identityfw.user_group) {

        if ( master_conntrack->identityfw.user ) {
            if ( strcmp(master_conntrack->identityfw.user, info->user) == 0 ) {
                match_result = 1;
                user_match = 1;
            }
        }
        if ( master_conntrack->identityfw.user_group ) {
            if ( strcmp(master_conntrack->identityfw.user_group, info->usergroup) == 0 ) {
                match_result = 1;
                group_match = 1;
            }
        }
        skb->cb[0] = 1;

        spin_unlock_bh(&user_lock);
        return (match_result ^ info->invert);
    }

    sock_buff = skb;
    ip_header = (struct iphdr *) skb_network_header(sock_buff);

    snprintf(ip , 16 , "%d.%d.%d.%d" ,ip_header->saddr & 0x000000FF,
            (ip_header->saddr & 0x0000FF00) >> 8,
            (ip_header->saddr & 0x00FF0000) >> 16,
            (ip_header->saddr & 0xFF000000) >> 24);
    ipaddr = inet_addr(ip) ;
    struct user_entry* found = find_user_entry(ipaddr);
    if ( found == NULL )
    {
        IDFW_DBG("user not found in the user_map.\n");
        match_result = 0;

        spin_unlock_bh(&user_lock);
        return match_result;
    }

    if (strlen(info->user) > 0) {
        if (strcmp(found->user, info->user) == 0) {
            match_result = 1;
            user_match = 1;
        }
    }
    if (strlen(info->usergroup) > 0) {
        list_for_each_entry(ug_entry, &found->user_groups.list_node, list_node) {
            if(strcmp(ug_entry->usergroup, info->usergroup) == 0 ) {
                match_result = 1;
                group_match = 1;
           }
        }
    }

    if ( match_result == 1 ) {
        if ( user_match == 1 ) {
              master_conntrack->identityfw.user =
                  kmalloc(strlen(info->user)+1, GFP_ATOMIC);

              if(!master_conntrack->identityfw.user) {
                   if (net_ratelimit())
                        printk(KERN_ERR "identityfw: out of memory in "
                             "match, bailing.\n");
                   spin_unlock_bh(&user_lock);
                   return (match_result ^ info->invert);
              }
              strcpy(master_conntrack->identityfw.user, info->user);
          }

        if ( group_match == 1 ) {
              master_conntrack->identityfw.user_group =
                  kmalloc(strlen(info->usergroup)+1, GFP_ATOMIC);
              if(!master_conntrack->identityfw.user_group) {
                   if (net_ratelimit())
                        printk(KERN_ERR "identityfw: out of memory in "
                             "match, bailing.\n");
                   spin_unlock_bh(&user_lock);
                   return (match_result ^ info->invert);
              }
              strcpy(master_conntrack->identityfw.user_group, info->usergroup);
        }
    }

    skb->cb[0] = 1;

    spin_unlock_bh(&user_lock);
    return match_result;
}

static int check(const struct xt_mtchk_param *par) {
    if (nf_ct_l3proto_try_module_get(par->match->family) < 0) {
        printk(KERN_WARNING "can't load conntrack support for "
            "proto=%d\n", par->match->family);
     return -EINVAL;
    }
    return 0;
}

static void destroy(const struct xt_mtdtor_param *par) {
    nf_ct_l3proto_module_put(par->match->family);
}

static int identityfw_numpackets_proc_show(struct seq_file *s, void *p) {

 seq_printf(s, "%d identityfw \n", num_packets);
 printk(KERN_INFO  "%d\n", num_packets);
 return 0;
}

static int identityfw_numpackets_proc_open(struct inode *inode, struct file *file) {

 return single_open(file, identityfw_numpackets_proc_show, NULL);
}


static ssize_t identityfw_numpackets_write_proc(struct file* file, const char __user *buffer,
     size_t count, loff_t *data) {

     char value[1024];
     int new_num_packets;

     if (copy_from_user(&value, buffer, sizeof(value)))
     return -EFAULT;

     new_num_packets = atoi(value);

     if ((new_num_packets < 1) || (new_num_packets > 99)) {
         printk(KERN_WARNING "identityfw: numpackets must be between 1 and 99\n");
     return -EFAULT;
    }

     num_packets = new_num_packets;

 return count;
}


static struct xt_match xt_identityfw_match[] __read_mostly = {
    {
        .name       = "identityfw",
        .family     = AF_INET,
        .checkentry = check,
        .match      = match,
        .destroy    = destroy,
        .matchsize  = sizeof(struct xt_identityfw_info),
        .me     = THIS_MODULE
    }
};

static const struct file_operations identityfw_numpackets_proc_fops = {
     .owner = THIS_MODULE,
     .open = identityfw_numpackets_proc_open,
     .read = seq_read,
     .llseek = seq_lseek,
     .release = single_release,
     .write = identityfw_numpackets_write_proc,
    };



static int __init identityfw_init(void) {
    int xt_status;
    IDFW_DBG("identityfw_init.\n");

    hash_init(user_map);

    need_conntrack();

    identityfw  = proc_create("identityfw_numpackets", 0, NULL, &identityfw_numpackets_proc_fops);

    if(maxdatalen < 1) {
         printk(KERN_WARNING "identityfw: maxdatalen can't be < 1, " "using 1\n");
         maxdatalen = 1;
    }
    else if(maxdatalen > 65536) {
         printk(KERN_WARNING "identityfw: maxdatalen can't be > 65536, " "using 65536\n");
         maxdatalen = 65536;
    }


    struct netlink_kernel_cfg cfg = { .input = handle_user_message, };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

    if (!nl_sk) {
        printk(KERN_ALERT "Error creating netlink user socket.\n");
        return -10;
    }

    xt_status = xt_register_matches(xt_identityfw_match, ARRAY_SIZE(xt_identityfw_match));

    return xt_status;
}

void release_users() {
    flush_user_map();
}

static void __exit identityfw_exit(void) {
    IDFW_DBG("identityfw_exit.\n");
    remove_proc_entry("identityfw_numpackets", NULL);
    xt_unregister_matches(xt_identityfw_match, ARRAY_SIZE(xt_identityfw_match));
    netlink_kernel_release(nl_sk);
}

module_init(identityfw_init);
module_exit(identityfw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Shield Identity FW");
MODULE_AUTHOR("www.shield.com");
