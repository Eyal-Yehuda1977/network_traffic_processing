#include "../inc/data_type.h"



int create_new_connection(int epoll_fd, int listener_fd) {

	/*
	struct epoll_event event;
	struct sockaddr_in address;
	socklen_t address_len = sizeof(address);
	struct connection* conn = nullptr;
	int fd = 0;

	memset(&event, 0, sizeof(struct epoll_event));
	memset(&address, 0, sizeof(struct sockaddr_in));
	
	fd = accept4( listener_fd, (struct sockaddr *) &address,
		      &address_len, (SOCK_NONBLOCK | SOCK_CLOEXEC) );
	
	if ( fd == -1 )
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK) 
			return 0;
		else {
			fprintf(stdout, "Err: accept: [ %s ].  "	\
				"[ %s ][ %s ]:[ %d ] \n", strerror(errno),
				__func__, __FILE__, __LINE__ );
			return 1;
		}
	}

	conn = new struct connection(fd, epoll_fd, address);
	
	event = { .events = { EPOLLIN | EPOLLET | EPOLLRDHUP
			      | EPOLLHUP | EPOLLERR },
		  .data = { .fd = { fd } }
	};		 
		
	if ( (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) )
	{
		fprintf(stdout, "Err: epoll_ctl(EPOLL_CTL_ADD) failed: [ %s ]" \
			"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
			__FILE__, __LINE__ );
		close(epoll_fd);
		return 1;
	}

	//m_connections.emplace(std::make_pair(fd, conn));
	m_connections[fd] = conn;
	fprintf( stdout, "Info: conn: [ %p ] connected with peer [ %s ] on port [ %d ] fd: [ %d ]." \
		 "[ %s ][ %s ]:[ %d ] \n", conn, inet_ntoa(address.sin_addr),
		 ntohs(address.sin_port), fd, __func__, __FILE__, __LINE__ );

	conn = nullptr;
	*/
	return 0;
}


int register_file_descriptors_to_epoll(int epoll_fd, int fd) {

	/*
	struct epoll_event event{};
	
	event = { .events = { EPOLLIN | EPOLLET }, .data = {.fd = {fd} } };		 

	if ( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0 ) {
		fprintf(stdout, "Err: epoll_ctl(EPOLL_CTL_ADD) failed: [ %s ]" \
			"[ %s ][ %s ]:[ %d ] \n", strerror(errno), __func__,
			__FILE__, __LINE__ );
		close(epoll_fd);
		return 1;
	}	
	*/
	return 0;
}


int create_listener_sock_fd() {
	
	struct sockaddr_in sevr_addr{};
	int old_option{0}, new_option{0}, opt{1}, fd{0};
	  
	sevr_addr.sin_family = AF_INET;
	sevr_addr.sin_port = htons(PORT);
	sevr_addr.sin_addr.s_addr = inet_addr(LO_LISTENER);

	//sevr_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( fd < 0 ) {
		fprintf(stdout, "Err: socket creation failed: [ %s ]\n",
			strerror(errno));
		return (-1);
	}
	  
          	  
	if ( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
			 &opt, sizeof(int)) )
	{
		fprintf(stdout, "Err: setsockopt failed: [ %s ]\n",
			strerror(errno));
		return (-1);	  

	}

	old_option = fcntl( fd, F_GETFL);
	new_option = old_option | O_NONBLOCK;

	if ( ::fcntl( fd, F_SETFL, new_option) < 0 ) {
		fprintf(stdout, "Err: fcntl(F_SETFL) failed: [ %s ]\n",
			strerror(errno));
		return (-1);
	}

	if ( bind( fd, (struct sockaddr *) &sevr_addr, sizeof(sevr_addr)) != 0 ) {
		fprintf(stdout, "Err: socket bind failed: [ %s ]\n",
			strerror(errno));
		return (-1);	  
	}
	  
	if ( listen( fd, SOMAXCONN) < 0 ) {
		fprintf(stdout, "Err: listen failed: [ %s ]\n",
			strerror(errno));
		return (-1);
	}

	//_fprintf("Info: Listening address: [ %s ] on port [ %d ]", inet_ntoa(sevr_addr.sin_addr),
	//	 ntohs(sevr_addr.sin_port))
		
	fprintf(stdout, "Info: Listening address: [ %s ] on port [ %d ]" \
		"[ %s ][ %s ]:[ %d ] \n", inet_ntoa(sevr_addr.sin_addr),
		ntohs(sevr_addr.sin_port), __func__, __FILE__, __LINE__ );
		
	
  	return fd;
}
