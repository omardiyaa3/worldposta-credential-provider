/*
 * WorldPosta SSH MFA - API Client
 * Copyright (c) 2024 WorldPosta
 */

#ifndef WORLDPOSTA_API_H
#define WORLDPOSTA_API_H

#include <stddef.h>
#include "config.h"

/* Push notification status */
#define PUSH_STATUS_PENDING  0
#define PUSH_STATUS_APPROVED 1
#define PUSH_STATUS_DENIED   2
#define PUSH_STATUS_EXPIRED  3
#define PUSH_STATUS_ERROR    -1

/* Maximum response size */
#define MAX_RESPONSE_SIZE 4096
#define MAX_REQUEST_ID 128

/*
 * Initialize API client (call once at startup)
 */
void api_init(void);

/*
 * Cleanup API client (call at shutdown)
 */
void api_cleanup(void);

/*
 * Verify OTP code
 * Returns 0 if valid, -1 if invalid or error
 */
int api_verify_otp(const worldposta_config_t *config, const char *username, const char *code);

/*
 * Send push notification
 * Returns request_id in output buffer on success, NULL on failure
 * Returns 0 on success, -1 on error
 */
int api_send_push(const worldposta_config_t *config, const char *username,
                  const char *client_ip, const char *hostname,
                  char *request_id, size_t request_id_len);

/*
 * Check push notification status
 * Returns PUSH_STATUS_* constant
 */
int api_check_push_status(const worldposta_config_t *config, const char *request_id);

/*
 * Wait for push approval with polling
 * Returns PUSH_STATUS_APPROVED on success, other status on failure
 */
int api_wait_for_push(const worldposta_config_t *config, const char *request_id, int timeout_seconds);

#endif /* WORLDPOSTA_API_H */
