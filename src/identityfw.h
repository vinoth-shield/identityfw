#ifndef _XT_IDENTITY_FW_H
#define _XT_IDENTITY_FW_H

#define MAX_USER_LEN      32
#define MAX_USERGROUP_LEN 32

struct xt_identityfw_info {
    char user[MAX_USER_LEN];
    char usergroup[MAX_USERGROUP_LEN];
    u_int8_t invert;
    u_int8_t pkt;
};

static void update_user_map(char* );
static void _update_user_map(int, char*, char* );
static void reload_user_map(char* );
static void _reload_user_map(void* );
static void delete_user(char* );
static void _delete_user_by_name(char* ) ;
static void _delete_user(int, char* ) ;

#endif

