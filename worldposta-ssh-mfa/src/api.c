/*
 * WorldPosta SSH MFA - API Client
 * Copyright (c) 2024 WorldPosta
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include "api.h"
#include "crypto.h"

/* Response buffer for curl */
typedef struct {
    char *data;
    size_t size;
} response_buffer_t;

/* Curl write callback */
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;

    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = '\0';

    return realsize;
}

/* Build authorization headers */
static struct curl_slist *build_headers(const worldposta_config_t *config, const char *body) {
    struct curl_slist *headers = NULL;
    char header[512];
    char nonce[NONCE_LENGTH + 1];
    char signature[SIGNATURE_LENGTH + 1];
    long timestamp = (long)time(NULL);

    /* Generate nonce */
    if (crypto_generate_nonce(nonce, sizeof(nonce)) != 0) {
        return NULL;
    }

    /* Generate signature */
    if (crypto_sign_request(config->secret_key, timestamp, nonce, body,
                            signature, sizeof(signature)) != 0) {
        return NULL;
    }

    /* Add headers */
    headers = curl_slist_append(headers, "Content-Type: application/json");

    snprintf(header, sizeof(header), "X-Integration-Key: %s", config->integration_key);
    headers = curl_slist_append(headers, header);

    snprintf(header, sizeof(header), "X-Signature: %s", signature);
    headers = curl_slist_append(headers, header);

    snprintf(header, sizeof(header), "X-Timestamp: %ld", timestamp);
    headers = curl_slist_append(headers, header);

    snprintf(header, sizeof(header), "X-Nonce: %s", nonce);
    headers = curl_slist_append(headers, header);

    return headers;
}

/* Perform HTTP POST request */
static int http_post(const worldposta_config_t *config, const char *endpoint,
                     const char *body, response_buffer_t *response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers;
    char url[1024];
    long http_code = 0;

    snprintf(url, sizeof(url), "%s%s", config->endpoint, endpoint);

    response->data = malloc(1);
    response->size = 0;
    response->data[0] = '\0';

    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    headers = build_headers(config, body);
    if (!headers) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)config->timeout);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return -1;
    }

    return (http_code >= 200 && http_code < 300) ? 0 : -1;
}

/* Perform HTTP GET request */
static int http_get(const worldposta_config_t *config, const char *endpoint,
                    response_buffer_t *response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers;
    char url[1024];
    long http_code = 0;

    snprintf(url, sizeof(url), "%s%s", config->endpoint, endpoint);

    response->data = malloc(1);
    response->size = 0;
    response->data[0] = '\0';

    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    /* For GET requests, sign with empty body */
    headers = build_headers(config, "");
    if (!headers) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)config->timeout);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return -1;
    }

    return (http_code >= 200 && http_code < 300) ? 0 : -1;
}

void api_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

void api_cleanup(void) {
    curl_global_cleanup();
}

int api_verify_otp(const worldposta_config_t *config, const char *username, const char *code) {
    response_buffer_t response = {0};
    char body[512];
    int result = -1;

    /* Build request JSON - use simple formatting like Windows code */
    snprintf(body, sizeof(body), "{\"externalUserId\":\"%s\",\"code\":\"%s\"}", username, code);

    /* Send request */
    if (http_post(config, "/v1/totp/verify", body, &response) == 0) {
        /* Parse response - API returns {"valid":true} */
        if (response.data && strstr(response.data, "\"valid\":true")) {
            result = 0;
        }
    }

    free(response.data);

    return result;
}

int api_send_push(const worldposta_config_t *config, const char *username,
                  const char *client_ip, const char *hostname,
                  char *request_id, size_t request_id_len) {
    response_buffer_t response = {0};
    char body[1024];
    int result = -1;
    char *req_start, *req_end;

    /* Build request JSON - use simple formatting to avoid signature issues */
    snprintf(body, sizeof(body),
        "{\"externalUserId\":\"%s\",\"serviceName\":\"%s\",\"deviceInfo\":\"%s\",\"ipAddress\":\"%s\"}",
        username,
        config->service_name,
        hostname,
        client_ip ? client_ip : "unknown");

    /* Send request */
    if (http_post(config, "/v1/push/send", body, &response) == 0) {
        /* Parse response for requestId using simple string search */
        if (response.data) {
            req_start = strstr(response.data, "\"requestId\":\"");
            if (req_start) {
                req_start += 13; /* Skip past "requestId":" */
                req_end = strchr(req_start, '"');
                if (req_end) {
                    size_t len = req_end - req_start;
                    if (len < request_id_len) {
                        strncpy(request_id, req_start, len);
                        request_id[len] = '\0';
                        result = 0;
                    }
                }
            }
        }
    }

    free(response.data);

    return result;
}

int api_check_push_status(const worldposta_config_t *config, const char *request_id) {
    response_buffer_t response = {0};
    struct json_object *resp_obj, *status_obj;
    char endpoint[256];
    int result = PUSH_STATUS_ERROR;

    snprintf(endpoint, sizeof(endpoint), "/v1/push/status/%s", request_id);

    if (http_get(config, endpoint, &response) == 0) {
        resp_obj = json_tokener_parse(response.data);
        if (resp_obj) {
            if (json_object_object_get_ex(resp_obj, "status", &status_obj)) {
                const char *status = json_object_get_string(status_obj);
                if (status) {
                    if (strcasecmp(status, "approved") == 0) {
                        result = PUSH_STATUS_APPROVED;
                    } else if (strcasecmp(status, "denied") == 0) {
                        result = PUSH_STATUS_DENIED;
                    } else if (strcasecmp(status, "expired") == 0) {
                        result = PUSH_STATUS_EXPIRED;
                    } else if (strcasecmp(status, "pending") == 0) {
                        result = PUSH_STATUS_PENDING;
                    }
                }
            }
            json_object_put(resp_obj);
        }
    }

    free(response.data);
    return result;
}

int api_wait_for_push(const worldposta_config_t *config, const char *request_id, int timeout_seconds) {
    int elapsed = 0;
    int status;

    while (elapsed < timeout_seconds) {
        status = api_check_push_status(config, request_id);

        if (status == PUSH_STATUS_APPROVED) {
            return PUSH_STATUS_APPROVED;
        } else if (status == PUSH_STATUS_DENIED || status == PUSH_STATUS_EXPIRED) {
            return status;
        }

        /* Poll every 500ms */
        usleep(500000);
        elapsed++;

        /* Actually count properly - 2 polls per second */
        if (elapsed % 2 == 0) {
            /* One second has passed */
        }
    }

    return PUSH_STATUS_EXPIRED;
}
