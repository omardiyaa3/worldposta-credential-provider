/*
 * WorldPosta SSH MFA - PAM Module
 * Copyright (c) 2024 WorldPosta
 *
 * PAM module for SSH two-factor authentication using WorldPosta
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "config.h"
#include "api.h"

/* Maximum OTP code length */
#define MAX_OTP_LENGTH 16

/* Get the remote host (client IP) */
static const char *get_remote_host(pam_handle_t *pamh) {
    const char *rhost = NULL;

    /* Try PAM_RHOST first (set by sshd) */
    if (pam_get_item(pamh, PAM_RHOST, (const void **)&rhost) == PAM_SUCCESS && rhost && *rhost) {
        return rhost;
    }

    /* Fallback to SSH_CONNECTION environment variable */
    const char *ssh_conn = pam_getenv(pamh, "SSH_CONNECTION");
    if (ssh_conn && *ssh_conn) {
        /* SSH_CONNECTION format: "client_ip client_port server_ip server_port" */
        static char client_ip[64];
        char *space = strchr(ssh_conn, ' ');
        if (space) {
            size_t len = space - ssh_conn;
            if (len < sizeof(client_ip)) {
                strncpy(client_ip, ssh_conn, len);
                client_ip[len] = '\0';
                return client_ip;
            }
        }
    }

    return "unknown";
}

/* Inform user with a message */
static void inform_user(pam_handle_t *pamh, const char *message) {
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *pmsg = &msg;
    struct pam_response *resp = NULL;

    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
        return;
    }

    if (!conv || !conv->conv) {
        return;
    }

    msg.msg_style = PAM_TEXT_INFO;
    msg.msg = message;

    conv->conv(1, &pmsg, &resp, conv->appdata_ptr);

    if (resp) {
        free(resp->resp);
        free(resp);
    }
}

/* Prompt user for input */
static int prompt_user(pam_handle_t *pamh, const char *prompt, char *response, size_t resp_len, int echo) {
    const struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *pmsg = &msg;
    struct pam_response *resp = NULL;
    int ret;

    /* Get conversation function */
    ret = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (ret != PAM_SUCCESS || !conv || !conv->conv) {
        return PAM_CONV_ERR;
    }

    /* Set up prompt */
    msg.msg_style = echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt;

    /* Call conversation function */
    ret = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
    if (ret != PAM_SUCCESS || !resp || !resp->resp) {
        if (resp) {
            free(resp->resp);
            free(resp);
        }
        return PAM_CONV_ERR;
    }

    /* Copy response */
    strncpy(response, resp->resp, resp_len - 1);
    response[resp_len - 1] = '\0';

    /* Clean up */
    memset(resp->resp, 0, strlen(resp->resp));
    free(resp->resp);
    free(resp);

    return PAM_SUCCESS;
}

/* Prompt user for OTP code */
static int prompt_otp(pam_handle_t *pamh, char *otp_code, size_t otp_len) {
    return prompt_user(pamh, "Verification code: ", otp_code, otp_len, 1);
}

/* Prompt user for auth method choice */
static int prompt_auth_choice(pam_handle_t *pamh) {
    char choice[8];
    int ret;

    inform_user(pamh, "");
    inform_user(pamh, "=== WorldPosta 2FA ===");
    inform_user(pamh, "1) Push notification to mobile app");
    inform_user(pamh, "2) Enter OTP code");

    ret = prompt_user(pamh, "Select option (1 or 2): ", choice, sizeof(choice), 1);
    if (ret != PAM_SUCCESS) {
        return -1;
    }

    if (choice[0] == '1') {
        return 1;  /* Push */
    } else if (choice[0] == '2') {
        return 2;  /* OTP */
    }

    return -1;  /* Invalid choice */
}

/* Main authentication function */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    worldposta_config_t config;
    const char *username = NULL;
    const char *rhost;
    char hostname[256];
    char request_id[MAX_REQUEST_ID];
    char otp_code[MAX_OTP_LENGTH];
    int ret;
    int push_result;
    int auth_choice;

    (void)flags;
    (void)argc;
    (void)argv;

    openlog("worldposta", LOG_PID, LOG_AUTH);

    /* Get username */
    ret = pam_get_user(pamh, &username, NULL);
    if (ret != PAM_SUCCESS || !username) {
        syslog(LOG_ERR, "worldposta: Failed to get username");
        closelog();
        return PAM_USER_UNKNOWN;
    }

    /* Load configuration */
    if (config_load(&config) != 0) {
        syslog(LOG_ERR, "worldposta: Failed to load configuration");
        closelog();
        return PAM_AUTH_ERR;
    }

    /* Check if user is excluded */
    if (config_is_user_excluded(&config, username)) {
        config_log(&config, LOG_LEVEL_INFO, "worldposta: User %s is excluded from 2FA", username);
        closelog();
        return PAM_SUCCESS;
    }

    /* Check if user is in required group */
    if (!config_is_user_in_required_group(&config, username)) {
        config_log(&config, LOG_LEVEL_INFO, "worldposta: User %s not in required group, skipping 2FA", username);
        closelog();
        return PAM_SUCCESS;
    }

    /* Get remote host and hostname */
    rhost = get_remote_host(pamh);
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname));
    }

    config_log(&config, LOG_LEVEL_INFO, "worldposta: Authenticating user %s from %s", username, rhost);

    /* Initialize API */
    api_init();

    /* Determine available auth methods and prompt user to choose */
    int has_push = (config.auth_methods & AUTH_METHOD_PUSH) != 0;
    int has_otp = (config.auth_methods & AUTH_METHOD_OTP) != 0;

    if (has_push && has_otp) {
        /* Both methods available - let user choose */
        auth_choice = prompt_auth_choice(pamh);
        if (auth_choice == -1) {
            /* Invalid choice, default to OTP */
            auth_choice = 2;
        }
    } else if (has_push) {
        auth_choice = 1;
    } else if (has_otp) {
        auth_choice = 2;
    } else {
        config_log(&config, LOG_LEVEL_ERROR, "worldposta: No auth methods configured");
        api_cleanup();
        closelog();
        return PAM_AUTH_ERR;
    }

    /* Handle Push authentication */
    if (auth_choice == 1) {
        config_log(&config, LOG_LEVEL_DEBUG, "worldposta: Sending push notification for %s", username);

        if (api_send_push(&config, username, rhost, hostname, request_id, sizeof(request_id)) == 0) {
            inform_user(pamh, "Push notification sent. Please approve on your mobile device...");

            push_result = api_wait_for_push(&config, request_id, config.timeout);

            if (push_result == PUSH_STATUS_APPROVED) {
                config_log(&config, LOG_LEVEL_INFO, "worldposta: Push approved for user %s", username);
                api_cleanup();
                closelog();
                return PAM_SUCCESS;
            } else if (push_result == PUSH_STATUS_DENIED) {
                config_log(&config, LOG_LEVEL_WARN, "worldposta: Push denied for user %s", username);
                inform_user(pamh, "Push notification was denied.");
            } else {
                config_log(&config, LOG_LEVEL_WARN, "worldposta: Push expired/failed for user %s", username);
                inform_user(pamh, "Push notification expired or failed.");
            }
        } else {
            config_log(&config, LOG_LEVEL_ERROR, "worldposta: Failed to send push for user %s", username);
            inform_user(pamh, "Failed to send push notification.");
        }

        /* Push failed - offer OTP as fallback if available */
        if (has_otp) {
            inform_user(pamh, "Falling back to OTP...");
            auth_choice = 2;
        } else {
            config_log(&config, LOG_LEVEL_ERROR, "worldposta: Authentication failed for user %s", username);
            api_cleanup();
            closelog();
            return PAM_AUTH_ERR;
        }
    }

    /* Handle OTP authentication */
    if (auth_choice == 2) {
        config_log(&config, LOG_LEVEL_DEBUG, "worldposta: Prompting OTP for %s", username);

        ret = prompt_otp(pamh, otp_code, sizeof(otp_code));
        if (ret != PAM_SUCCESS) {
            config_log(&config, LOG_LEVEL_ERROR, "worldposta: Failed to get OTP from user %s", username);
            api_cleanup();
            closelog();
            return PAM_AUTH_ERR;
        }

        /* Verify OTP */
        if (api_verify_otp(&config, username, otp_code) == 0) {
            config_log(&config, LOG_LEVEL_INFO, "worldposta: OTP verified for user %s", username);
            memset(otp_code, 0, sizeof(otp_code));
            api_cleanup();
            closelog();
            return PAM_SUCCESS;
        }

        config_log(&config, LOG_LEVEL_WARN, "worldposta: Invalid OTP for user %s", username);
        memset(otp_code, 0, sizeof(otp_code));
    }

    config_log(&config, LOG_LEVEL_ERROR, "worldposta: Authentication failed for user %s", username);
    api_cleanup();
    closelog();
    return PAM_AUTH_ERR;
}

/* Required PAM functions */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
