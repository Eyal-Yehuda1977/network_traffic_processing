#include "../inc/data_type.h"







int daemon_run() {

	int ret{0};

	int init_mem_pool(const int&);
	int init_epoll();

	init_mem_pool(DEFAULT_MEM_POOL_SZ);
	init_epoll();


	
	return ret;
}

void deastroy_daemon() {

	void destroy_mem_pool();
	void destroy_epoll();

	destroy_epoll();

	destroy_mem_pool();
}


static void signal_handler(int signal)
{
	if ( (signal == SIGTERM) || (signal == SIGINT) || (signal == SIGKILL) ) {
		deastroy_daemon();
	}
}





int main() {

	pid_t process_id{0}, sid{0};
	
	signal(SIGINT,   signal_handler);
	signal(SIGTERM,  signal_handler);  
	signal(SIGHUP,   signal_handler);

	process_id = fork();

	if( process_id<0 ) {
		//fork failed.
		exit(2);
	}

	if( process_id > 0 ) exit(1);     

	umask(0); 
	sid = setsid();

	if( sid < 0 ) {
		// sid failed .
		exit(3);
	} 

	chdir("/");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	daemon_run();

	return 0;
}
