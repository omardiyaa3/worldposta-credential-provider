/*
 * WorldPosta SSH MFA - Configuration Reader
 * Copyright (c) 2024 WorldPosta
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include "config.h"

/* Helper to trim whitespace */
static char *trim(char *str) {
    char *end;
    while (*str == ' ' || *str == '\t') str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) end--;
    end[1] = '\0';
    return str;
}

/* Parse auth_methods string */
static int parse_auth_methods(const char *value) {
    if (strcasecmp(value, "push") == 0) return AUTH_METHOD_PUSH;
    if (strcasecmp(value, "otp") == 0) return AUTH_METHOD_OTP;
    if (strcasecmp(value, "both") == 0) return AUTH_METHOD_BOTH;
    return AUTH_METHOD_BOTH; /* Default */
}

/* Parse log_level string */
static int parse_log_level(const char *value) {
    if (strcasecmp(value, "debug") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(value, "info") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(value, "warn") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(value, "error") == 0) return LOG_LEVEL_ERROR;
    return LOG_LEVEL_INFO; /* Default */
}

int config_load(worldposta_config_t *config) {
    FILE *fp;
    char line[MAX_CONFIG_LINE];
    char *key, *value, *eq;

    /* Set defaults */
    memset(config, 0, sizeof(worldposta_config_t));
    strncpy(config->endpoint, "https://api.worldposta.com", MAX_CONFIG_VALUE - 1);
    strncpy(config->service_name, "Linux SSH Login", MAX_CONFIG_VALUE - 1);
    config->timeout = 60;
    config->auth_methods = AUTH_METHOD_BOTH;
    config->log_level = LOG_LEVEL_INFO;

    fp = fopen(CONFIG_PATH, "r");
    if (!fp) {
        syslog(LOG_ERR, "worldposta: Cannot open config file: %s", CONFIG_PATH);
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comments and empty lines */
        char *trimmed = trim(line);
        if (*trimmed == '#' || *trimmed == ';' || *trimmed == '[' || *trimmed == '\0') {
            continue;
        }

        /* Parse key = value */
        eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        key = trim(trimmed);
        value = trim(eq + 1);

        /* API settings */
        if (strcmp(key, "endpoint") == 0) {
            strncpy(config->endpoint, value, MAX_CONFIG_VALUE - 1);
        } else if (strcmp(key, "integration_key") == 0) {
            strncpy(config->integration_key, value, MAX_CONFIG_VALUE - 1);
        } else if (strcmp(key, "secret_key") == 0) {
            strncpy(config->secret_key, value, MAX_CONFIG_VALUE - 1);
        } else if (strcmp(key, "timeout") == 0) {
            config->timeout = atoi(value);
            if (config->timeout <= 0) config->timeout = 60;
        }
        /* Auth settings */
        else if (strcmp(key, "auth_methods") == 0) {
            config->auth_methods = parse_auth_methods(value);
        } else if (strcmp(key, "service_name") == 0) {
            strncpy(config->service_name, value, MAX_CONFIG_VALUE - 1);
        }
        /* Options */
        else if (strcmp(key, "exclude_users") == 0) {
            strncpy(config->exclude_users, value, MAX_CONFIG_VALUE - 1);
        } else if (strcmp(key, "require_groups") == 0) {
            strncpy(config->require_groups, value, MAX_CONFIG_VALUE - 1);
        } else if (strcmp(key, "log_level") == 0) {
            config->log_level = parse_log_level(value);
        }
    }

    fclose(fp);

    /* Validate required fields */
    if (strlen(config->integration_key) == 0 || strlen(config->secret_key) == 0) {
        syslog(LOG_ERR, "worldposta: Missing integration_key or secret_key in config");
        return -1;
    }

    return 0;
}

int config_is_user_excluded(const worldposta_config_t *config, const char *username) {
    char *list, *token, *saveptr;
    char buf[MAX_CONFIG_VALUE];

    if (strlen(config->exclude_users) == 0) {
        return 0;
    }

    strncpy(buf, config->exclude_users, MAX_CONFIG_VALUE - 1);
    buf[MAX_CONFIG_VALUE - 1] = '\0';

    token = strtok_r(buf, ",", &saveptr);
    while (token != NULL) {
        char *trimmed = trim(token);
        if (strcmp(trimmed, username) == 0) {
            return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

int config_is_user_in_required_group(const worldposta_config_t *config, const char *username) {
    char *token, *saveptr;
    char buf[MAX_CONFIG_VALUE];
    struct passwd *pw;
    struct group *gr;
    int ngroups = 64;
    gid_t groups[64];

    /* If no groups required, allow all */
    if (strlen(config->require_groups) == 0) {
        return 1;
    }

    /* Get user's groups */
    pw = getpwnam(username);
    if (!pw) return 0;

    if (getgrouplist(username, pw->pw_gid, groups, &ngroups) == -1) {
        return 0;
    }

    /* Check each required group */
    strncpy(buf, config->require_groups, MAX_CONFIG_VALUE - 1);
    buf[MAX_CONFIG_VALUE - 1] = '\0';

    token = strtok_r(buf, ",", &saveptr);
    while (token != NULL) {
        char *trimmed = trim(token);
        gr = getgrnam(trimmed);
        if (gr) {
            for (int i = 0; i < ngroups; i++) {
                if (groups[i] == gr->gr_gid) {
                    return 1;
                }
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

void config_log(const worldposta_config_t *config, int level, const char *fmt, ...) {
    va_list args;
    int syslog_level;

    if (level < config->log_level) {
        return;
    }

    switch (level) {
        case LOG_LEVEL_DEBUG: syslog_level = LOG_DEBUG; break;
        case LOG_LEVEL_INFO:  syslog_level = LOG_INFO; break;
        case LOG_LEVEL_WARN:  syslog_level = LOG_WARNING; break;
        case LOG_LEVEL_ERROR: syslog_level = LOG_ERR; break;
        default: syslog_level = LOG_INFO;
    }

    va_start(args, fmt);
    vsyslog(syslog_level, fmt, args);
    va_end(args);
}
