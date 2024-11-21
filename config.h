#ifndef CONFIG_H
#define CONFIG_H


#include <stdint.h>

#include "json.h"
#include "defines.h"




typedef struct tun_encryptor_s {
    char name[MAX_ENCRYPTOR_NAME];
    char module_path[PATH_MAX];
} tun_encryptor_t;

typedef struct tun_info_s {
    //mandatory params
    ipv4_addr remote_endpoint;
    ipv4_addr local_endpoint;
    uint16_t remote_port;
    uint16_t local_port;
    tun_proto_t proto;
    tun_mode_t mode;
    char encryptor_name[MAX_ENCRYPTOR_NAME]; //name of encryption plugin which registered in global config. This name uses as ID. By default "none" means no encryption

    //optional params (actualy some of them are necessary)
    char dev_name[MAX_DEV_NAME_LENGTH]; //overrided name of the virtual interface
    char bringup_script[PATH_MAX]; //helper script for setup which must be executed after starting of the virtual interface
    char shutdown_script[PATH_MAX]; //helper script for tear down which must be executed before removing of the virtual interface
    char encryption_params[MAX_JSON_STR_LENGTH];
    uint16_t icmp_id; //override icmp id field in icmp packet (used only for icmp tunnel's type)
} tun_info_t;

typedef struct config_s {
    tun_proto_t default_proto;
    uint16_t default_port;
    char global_bringup_script[PATH_MAX]; //helper script for setup which must be executed after starting ALL tunnels
    char global_shutdown_script[PATH_MAX]; //helper script for tear down which must be executed before removing ALL tunnels
    tun_info_t* tunnels;
    uint16_t tunnels_count;
    tun_encryptor_t* encryptors;
    uint16_t encryptors_count;
} config_t;


int parse_config(config_t* cfg, char* json_cfg_path);


#endif
