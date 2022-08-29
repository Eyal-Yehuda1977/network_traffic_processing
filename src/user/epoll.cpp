#include "../inc/data_type.h"
#include <vector>
#include <fcntl.h>
#include <sys/epoll.h>
#include <memory>
#include <algorithm>
#include <signal.h>
#include <pthread.h>
#include <unordered_map>




volatile static unsigned char thread_run{1};
#define _THREAD_RUN (thread_run !=0)



struct thread_data { int epoll_fd, fd; };

void* epoll_worker(void* vptr)
{
	int epoll_fd = 0, listener_fd = 0, events_count = 0, fd = 0, ret = 0;
	struct epoll_event epoll_events[ EPOLL_MAX_EVENTS ];
	
	if ( !vptr ) pthread_exit(vptr);
	
	epoll_fd = ((struct thread_data *)vptr)->epoll_fd;
	listener_fd = ((struct thread_data *)vptr)->fd;

	vptr = nullptr;
	
	memset(epoll_events, 0, sizeof(struct epoll_event) * EPOLL_MAX_EVENTS );
	/*
	auto is_new_connection = [&fd](std::unordered_map<int, struct connection*>
				       m_connections) -> int {
		std::unordered_map<int, struct connection*>::iterator
			itr = m_connections.find(fd);		
		return ( itr != m_connections.end() ) ? 1 : 0;
		};*/

	
	     
	while ( _THREAD_RUN )
	{
		
		events_count = epoll_wait(epoll_fd, &epoll_events[0],
					  EPOLL_MAX_EVENTS, EPOLL_WAITE_MS);
		
		if ( events_count < 0 ) {
			fprintf(stdout, "Err: epoll_wait() failed: [ %s ]" \
				"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
				__FILE__, __LINE__ );

			pthread_exit(vptr);
		}

		if ( events_count == 0 ) continue;
		
		for (int i = 0; i < events_count; i++ )
		{
			/* extract fd from connection */
			fd = epoll_events[i].data.fd;
			/*ret = container_operations(is_new_connection, []()->int{ return int{}; }
			  ,m_connections );*/

			/*new socket is connected to a bound socket port,
			  establish a new connection */
			if ( ret == 0 ) {
				fprintf(stdout, "New connection EPOLLIN\n");
				/*create_new_connection(epoll_fd, listener_fd);*/
				break;
			}
			
			if ( (epoll_events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) ) {
				/*fprintf(stdout, "Got event: ( EPOLLRDHUP | EPOLLHUP | EPOLLERR ) " \
				  "on conn [ %p ]\n", m_connections[fd]);*/
				/*m_connections[fd]->on_disconnected();*/				
			}else if (epoll_events[i].events & EPOLLOUT) {
				/*fprintf(stdout, "Got event: EPOLLOUT on conn [ %p ]\n",
				  m_connections[fd]);*/
				/*m_connections[fd]->on_send();*/
			}else if (epoll_events[i].events & EPOLLIN) {
				/*fprintf(stdout, "Got event: EPOLLIN on conn [ %p ]\n",
				  m_connections[fd]);*/
				/*m_connections[fd]->on_received();*/
			}			
		}
	}

	pthread_exit(vptr);
}




int init_epoll() {

	int ret{0};

	return ret;
}



void destroy_epoll() {


}

