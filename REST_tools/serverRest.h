#ifndef SERVER_REST_H
#define SERVER_REST_H

#include <microhttpd.h>
#include <time.h>

// Function declarations
struct MHD_Daemon* start_rest_server(int port);
char* search_logs_by_account_id(unsigned int account_id, time_t start_time, time_t end_time);
char* search_logs_by_username(const char *username, time_t start_time, time_t end_time);
time_t parse_human_timestamp(const char *timestamp_str);
char* format_human_time(time_t timestamp);
char* get_user_status_json(unsigned int account_id, const char *username);

#endif // SERVER_REST_H 