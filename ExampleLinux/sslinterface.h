/*
The main applications consumes the respective ssl_library via this interface,
which must be implemented individually
*/

void ssl_init(char *current_path);
void ssl_cleanup(void);
//Read for incoming messages and echo them back
void echo_connection(int client_fd);