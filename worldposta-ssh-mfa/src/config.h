/*
 * WorldPosta SSH MFA - Configuration Reader
 * Copyright (c) 2024 WorldPosta
 */

#ifndef WORLDPOSTA_CONFIG_H
#define WORLDPOSTA_CONFIG_H

#define CONFIG_PATH "/etc/worldposta/worldposta.conf"
#define MAX_CONFIG_LINE 1024
#define MAX_CONFIG_VALUE 512

/* Authentication methods */
#define AUTH_METHOD_PUSH  0x01
#define AUTH_METHOD_OTP   0x02
#define AUTH_METHOD_BOTH  0x03

/* Log levels */
#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3

/* Configuration structure */
typedef struct {
    /* API settings */
    char endpoint[MAX_CONFIG_VALUE];
    char integration_key[MAX_CONFIG_VALUE];
    char secret_key[MAX_CONFIG_VALUE];
    int timeout;

    /* Authentication settings */
    int auth_methods;  /* AUTH_METHOD_PUSH, AUTH_METHOD_OTP, or AUTH_METHOD_BOTH */
    char service_name[MAX_CONFIG_VALUE];

    /* Options */
    char exclude_users[MAX_CONFIG_VALUE];
    char require_groups[MAX_CONFIG_VALUE];
    int log_level;
} worldposta_config_t;

/*
 * Load configuration from file
 * Returns 0 on success, -1 on error
 */
int config_load(worldposta_config_t *config);

/*
 * Check if a user should be excluded from 2FA
 * Returns 1 if excluded, 0 if not
 */
int config_is_user_excluded(const worldposta_config_t *config, const char *username);

/*
 * Check if a user is in a required group
 * Returns 1 if in group (or no groups required), 0 if not
 */
int config_is_user_in_required_group(const worldposta_config_t *config, const char *username);

/*
 * Log a message based on log level
 */
void config_log(const worldposta_config_t *config, int level, const char *fmt, ...);

#endif /* WORLDPOSTA_CONFIG_H */
