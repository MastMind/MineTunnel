#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "config.h"
#include "json.h"
#include "utils.h"
#include "defines.h"




struct proto_map_s {
    char* proto_name;
    tun_proto_t proto;
};

struct tunmode_map_s {
    char* tunmode_name;
    tun_mode_t mode;
};

static const struct proto_map_s proto_map[] = {
    { "none", PROTO_NONE },
    // { "tcp", PROTO_TCP }, //TODO for future usage
    { "udp", PROTO_UDP },
    { "icmp", PROTO_ICMP },
    { NULL, PROTO_NONE }
};

static const struct tunmode_map_s tunmode_map[] = {
    { "tun", MODE_TUN },
    { "tap", MODE_TAP },
    { NULL, MODE_UNKNOWN }
};

static int str_to_proto(const char* str, tun_proto_t* proto);
static int str_to_tunmode(const char* str, tun_mode_t* mode);
static int tunnels_parsing(json_array_t json_tunnnels, config_t* cfg);
static int encryptors_parsing(json_array_t json_encryptors, config_t* cfg);
static int tunnel_exists(tun_info_t* tunnels, uint16_t tunnels_count, ipv4_addr remote_addr, ipv4_addr local_addr, uint16_t remote_port, uint16_t local_port);
static int encryptor_exists(tun_encryptor_t* encryptors, uint16_t encryptors_count, const char* name);

int parse_config(config_t* cfg, char* json_cfg_path) {
    int ret = 0;
    json_object_t json_root_msg = NULL;
    json_value_t json_root = NULL;

    if (!cfg || !json_cfg_path || *json_cfg_path == '\0') {
        PrintError("Empty json config path\n");
        ret = -1;
        goto err;
    }

    memset(cfg, 0, sizeof(config_t));

    json_root = json_from_file(json_cfg_path);

    if (!json_root) {
        PrintError("Syntax error in root node of config file\n");
        ret = -2;
        goto err;
    }

    json_root_msg = (json_object_t)(json_root->value);

    if (!json_root_msg) {
        PrintError("Syntax error in root node of config file\n");
        ret = -3;
        goto err;
    }

    json_value_t element = json_object_get_element(json_root_msg, "proto");

    if (!element) {
        PrintError("Syntax error in json config. Key \"proto\" expected in root section but not found\n");
        ret = -3;
        goto err;
    }

    //default proto parsing
    char* default_proto_string = (char*)(element->value);

    if (str_to_proto(default_proto_string, &cfg->default_proto)) {
        PrintError("Syntax error in json config. Bad global proto value\n");
        ret = -4;
        goto err;
    }

    //default port parsing
    element = json_object_get_element(json_root_msg, "port");

    if (!element) {
        PrintError("Syntax error in json config. Key \"port\" expected in root section but not found\n");
        ret = -5;
        goto err;
    }

    char* default_port_string = (char*)(element->value);

    uint32_t value = 0;

    if (sscanf(default_port_string, "%u", &value) != 1) {
        PrintError("Syntax error in json config. Bad global port value\n");
        ret = -5;
        goto err;
    }

    cfg->default_port = value;

    //global bringup script parsing
    element = json_object_get_element(json_root_msg, "bringup_script");

    if (element && element->type == STRING) {
        char* default_bringup_string = (char*)(element->value);

        if (default_bringup_string) {
            strncpy(cfg->global_bringup_script, default_bringup_string, PATH_MAX);
        }
    }

    //global shutdown script parsing
    element = json_object_get_element(json_root_msg, "shutdown_script");

    if (element && element->type == STRING) {
        char* default_shutdown_string = (char*)((json_object_get_element(json_root_msg, "shutdown_script"))->value);

        if (default_shutdown_string) {
            strncpy(cfg->global_shutdown_script, default_shutdown_string, PATH_MAX);
        }
    }

    //encryption plugins parsing
    element = json_object_get_element(json_root_msg, "encryption_plugins");

    if (element && element->type == JSON_ARRAY) {
        if (encryptors_parsing((json_array_t)(element->value), cfg)) {
            PrintError("Syntax error in json config. Error in \"encryption_plugins\" section\n");
            ret = -7;
            goto err;
        }
    }

    //tunnels parsing
    element = json_object_get_element(json_root_msg, "tunnels");

    if (element && element->type == JSON_ARRAY) {
        if (tunnels_parsing((json_array_t)(element->value), cfg)) {
            PrintError("Syntax error in json config. Error in \"tunnels\" section\n");
            ret = -8;
            goto err;
        }
    }

err:
    if (json_root_msg) {
        json_object_clear(json_root_msg);
    }

    if (json_root) {
        free(json_root);
    }

    return ret;
}

static int str_to_proto(const char* str, tun_proto_t* proto) {
    char str_proto[MAX_PROTO_LENGTH];

    if (!str || *str == '\0') {
        return -1;
    }

    strncpy(str_proto, str, MAX_PROTO_LENGTH);
    
    char* p_str_proto = str_proto;

    //convert string proto to lowercase
    while (*p_str_proto != '\0') {
        *p_str_proto = tolower(*p_str_proto);

        p_str_proto++;
    }

    const struct proto_map_s* current_proto_map = proto_map;

    while (current_proto_map->proto_name) {
        if (!strncmp(current_proto_map->proto_name, str_proto, MAX_PROTO_LENGTH)) {
            *proto = current_proto_map->proto;
            break;
        }

        current_proto_map++;
    }

    if (!current_proto_map->proto_name) {
        return -2;
    }

    return 0;
}

static int str_to_tunmode(const char* str, tun_mode_t* mode) {
    char str_tunmode[MAX_TUNMODE_LENGTH];

    if (!str || *str == '\0') {
        return -1;
    }

    strncpy(str_tunmode, str, MAX_TUNMODE_LENGTH);

    char* p_str_tunmode = str_tunmode;

    while (*p_str_tunmode != '\0') {
        *p_str_tunmode = tolower(*p_str_tunmode);

        p_str_tunmode++;
    }

    const struct tunmode_map_s* current_tunmode_map = tunmode_map;

    while (current_tunmode_map->tunmode_name) {
        if (!strncmp(current_tunmode_map->tunmode_name, str_tunmode, MAX_TUNMODE_LENGTH)) {
            *mode = current_tunmode_map->mode;
            break;
        }

        current_tunmode_map++;
    }

    if (!current_tunmode_map->tunmode_name) {
        return -2;
    }

    return 0;
}

static int tunnels_parsing(json_array_t json_tunnnels, config_t* cfg) {
    tun_info_t* tun_info = NULL;
    int ret = 0;

    if (!json_tunnnels) {
        PrintError("Syntax error in json config. No \"tunnels\" message\n");
        ret = -1;
        goto err;
    }

    cfg->tunnels = (tun_info_t*)malloc(sizeof(tun_info_t) * json_tunnnels->size);

    if (!cfg->tunnels) {
        cfg->tunnels_count = 0;
        ret = -2;
        goto err;
    }

    tun_info = cfg->tunnels;

    for (int i = 0; i < json_tunnnels->size; i++) {
        memset(tun_info, 0, sizeof(tun_info_t));

        json_value_t element = json_array_get_element(json_tunnnels, i);

        if (element->type != JSON_OBJECT) {
            PrintError("Syntax error in json config tunnels section. JSON object as JSON array's element expected but not found\n");
            ret = -3;
            goto err;
        }

        json_object_t json_tunnel = (json_object_t)(element->value);

        //parsing tunnel's json
        //getting remote endpoint
        char* tunnel_remote = (char*)((json_object_get_element(json_tunnel, "remote"))->value);

        if (!tunnel_remote) {
            PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Key \"remote\" not found\n");
            ret = -4;
            goto err;
        }

        tun_info->remote_port = cfg->default_port;
        tun_info->local_port = cfg->default_port;
        tun_info->icmp_id = DEFAULT_ICMP_ID;

        uint32_t value1 = 0;
        uint32_t value2 = 0;
        uint32_t value3 = 0;
        uint32_t value4 = 0;
        uint32_t value5 = 0;

        if (sscanf(tunnel_remote, "%u.%u.%u.%u:%u", &value1,
                                            &value2,
                                            &value3,
                                            &value4,
                                            &value5) != 5) {
            //try to sscanf with port
            if (sscanf(tunnel_remote, "%u.%u.%u.%u", &value1,
                                            &value2,
                                            &value3,
                                            &value4) != 4) {
                PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Bad \"remote\" ip address value\n");
                ret = -5;
                goto err;
            }
        }

        tun_info->remote_endpoint.addr[0] = value1;
        tun_info->remote_endpoint.addr[1] = value2;
        tun_info->remote_endpoint.addr[2] = value3;
        tun_info->remote_endpoint.addr[3] = value4;

        //fill port
        if (value5) {
            tun_info->remote_port = value5;
        }

        //getting remote endpoint
        char* tunnel_local = (char*)((json_object_get_element(json_tunnel, "local"))->value);

        if (!tunnel_remote) {
            PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Key \"local\" not found\n");
            ret = -6;
            goto err;
        }

        value1 = 0;
        value2 = 0;
        value3 = 0;
        value4 = 0;
        value5 = 0;

        if (sscanf(tunnel_local, "%u.%u.%u.%u:%u", &value1,
                                            &value2,
                                            &value3,
                                            &value4,
                                            &value5) != 5) {
            //try to sscanf with port
            if (sscanf(tunnel_local, "%u.%u.%u.%u", &value1,
                                            &value2,
                                            &value3,
                                            &value4) != 4) {
                PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Bad \"local\" ip address value\n");
                ret = -7;
                goto err;
            }
        }

        tun_info->local_endpoint.addr[0] = value1;
        tun_info->local_endpoint.addr[1] = value2;
        tun_info->local_endpoint.addr[2] = value3;
        tun_info->local_endpoint.addr[3] = value4;

        //fill port
        if (value5) {
            tun_info->local_port = value5;
        }

        //check for duplicate
        if (i) {
            if (tunnel_exists(cfg->tunnels, i, tun_info->remote_endpoint, tun_info->local_endpoint, tun_info->remote_port, tun_info->local_port)) {
                PrintError("Syntax error in json config tunnels section. Duplicate found for tunnel with local ip %u.%u.%u.%u and remote ip %u.%u.%u.%u\n", tun_info->local_endpoint.addr[0],
                                                                                                                                                            tun_info->local_endpoint.addr[1],
                                                                                                                                                            tun_info->local_endpoint.addr[2],
                                                                                                                                                            tun_info->local_endpoint.addr[3],
                                                                                                                                                            tun_info->remote_endpoint.addr[0],
                                                                                                                                                            tun_info->remote_endpoint.addr[1],
                                                                                                                                                            tun_info->remote_endpoint.addr[2],
                                                                                                                                                            tun_info->remote_endpoint.addr[3]);
                ret = -8;
                goto err;
            }
        }

        tun_info->proto = cfg->default_proto;

        element = json_object_get_element(json_tunnel, "proto");

        //tunnel's proto parsing
        if (element) {
            if (str_to_proto((char*)(element->value), &tun_info->proto)) {
                PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Bad \"proto\" value\n");
                ret = -9;
                goto err;
            }
        }

        tun_info->mode = MODE_UNKNOWN;

        element = json_object_get_element(json_tunnel, "mode");

        if (!element) {
            PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Key \"mode\" not found\n");
            ret = -10;
            goto err;
        }

        //tunnel's mode parsing
        if (str_to_tunmode((char*)(element->value), &tun_info->mode)) {
            PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Bad \"mode\" value\n");
            ret = -11;
            goto err;
        }

        //parse optional tunnel encryptor name
        element = json_object_get_element(json_tunnel, "encryption");

        if (element) {
            char* encryption_str = (char*)(element->value);

            //check encryption exists exists
            if (encryption_str) {
                if (!encryptor_exists(cfg->encryptors, cfg->encryptors_count, encryption_str)) {
                    PrintError("Syntax error in json config tunnels section. Bad tunnel json's object. Invalid encryptor's name\n");
                    ret = -12;
                    goto err;
                }

                strncpy(tun_info->encryptor_name, encryption_str, MAX_ENCRYPTOR_NAME);

                //add encryption params
                element = json_object_get_element(json_tunnel, "encryption_params");

                if (!element || element->type != JSON_OBJECT) {
                    PrintError("Syntax error in json config tunnels section. Bad tunnel's encryption json's object. Key \"encryption_params\" not found\n");
                    ret = -13;
                    goto err;
                }

                // tun_info->encryption_params = (json_object_t)(element->value);
                if (json_object_to_str((json_object_t)(element->value), tun_info->encryption_params)) {
                    PrintError("Syntax error in json config tunnels section. Bad tunnel's encryption json's object. Bad \"encryption_params\" value\n");
                    ret = -14;
                    goto err;
                }
            }
        }

        //parse optional device name
        element = json_object_get_element(json_tunnel, "device");

        if (element) {
            char* device_str = (char*)(element->value);

            if (device_str) {
                strncpy(tun_info->dev_name, device_str, MAX_DEV_NAME_LENGTH);
            }
        }

        //parse optional bringup script path
        element = json_object_get_element(json_tunnel, "bringup_script");

        if (element) {
            char* bringup_script_str = (char*)(element->value);

            if (bringup_script_str) {
                strncpy(tun_info->bringup_script, bringup_script_str, PATH_MAX);
            }
        }

        //parse optional shutdown script path
        element = json_object_get_element(json_tunnel, "shutdown_script");

        if (element) {
            char* shutdown_script_str = (char*)(element->value);

            if (shutdown_script_str) {
                strncpy(tun_info->shutdown_script, shutdown_script_str, PATH_MAX);
            }
        }

        //parse optional icmp id (only for icmp proto)
        element = json_object_get_element(json_tunnel, "icmp_id");

        if (element) {
            char* icmp_id_str = (char*)(element->value);

            if (icmp_id_str) {
                value1 = 0;

                sscanf(icmp_id_str, "%u", &value1);

                tun_info->icmp_id = (uint16_t)value1;
            }
        }

        tun_info++;
    }

    cfg->tunnels_count = json_tunnnels->size;

err:
    if (ret) {
        if (cfg->tunnels) {
            free(cfg->tunnels);
            cfg->tunnels = NULL;
        }

        cfg->tunnels_count = 0;
    }

    return ret;
}

static int encryptors_parsing(json_array_t json_encryptors, config_t* cfg) {
    tun_encryptor_t* encryptors = NULL;
    int ret = 0;

    if (!json_encryptors) {
        //encryptors are optional and could be NULL
        return 0;
    }

    cfg->encryptors = (tun_encryptor_t*)malloc(sizeof(tun_encryptor_t) * json_encryptors->size);

    if (!cfg->encryptors) {
        ret = -3;
        goto err;
    }

    encryptors = cfg->encryptors;

    for (int i = 0; i < json_encryptors->size; i++) {
        memset(encryptors, 0, sizeof(tun_encryptor_t));

        json_value_t element = json_array_get_element(json_encryptors, i);

        if (element->type != JSON_OBJECT) {
            PrintError("Syntax error in json config tunnels section. Bad encryptor json's array value. JSON object as value not found\n");
            ret = -2;
            goto err;
        }

        json_object_t json_encryptor = (json_object_t)(element->value);

        element = json_object_get_element(json_encryptor, "name");

        if (!element || element->type != STRING) {
            PrintError("Syntax error in json config tunnels section. Bad encryptor json's array value. Key \"name\" not found\n");
            ret = -4;
            goto err;
        }

        char* encryptor_name = (char*)(element->value);

        //check for duplicate
        if (i) {
            if (encryptor_exists(cfg->encryptors, i, encryptor_name)) {
                PrintError("Syntax error in json config tunnels section. Duplicate encryptor. Encryptor %s had been declared early\n", encryptor_name);
                ret = -5;
                goto err;
            }
        }

        strncpy(encryptors->name, encryptor_name, MAX_ENCRYPTOR_NAME);

        element = json_object_get_element(json_encryptor, "path");

        if (!element || element->type != STRING) {
            PrintError("Syntax error in json config tunnels section. Bad encryptor json's array value. Key \"path\" not found\n");
            ret = -6;
            goto err;
        }

        char* module_path = (char*)(element->value);

        strncpy(encryptors->module_path, module_path, PATH_MAX);

        encryptors++;
    }

    cfg->encryptors_count = json_encryptors->size;

err:
    if (ret) {
        if (cfg->encryptors) {
            free(cfg->encryptors);
            cfg->encryptors = NULL;
        }

        cfg->encryptors_count = 0;
    }

    return ret;
}

static int tunnel_exists(tun_info_t* tunnels, uint16_t tunnels_count, ipv4_addr remote_addr, ipv4_addr local_addr, uint16_t remote_port, uint16_t local_port) {
    
    for (uint16_t i = 0; i < tunnels_count; i++) {
        if (tunnels->remote_endpoint.value == remote_addr.value &&
            tunnels->local_endpoint.value == local_addr.value &&
            tunnels->remote_port == remote_port &&
            tunnels->local_port == local_port) {
            //tunnel found
            return 1;
        }

        tunnels++;
    }

    return 0;
}

static int encryptor_exists(tun_encryptor_t* encryptors, uint16_t encryptors_count, const char* name) {
    for (uint16_t i = 0; i < encryptors_count; i++) {
        if (!strncmp(encryptors->name, name, MAX_ENCRYPTOR_NAME)) {
            //encryptor found
            return 1;
        }

        encryptors++;
    }

    return 0;
}
