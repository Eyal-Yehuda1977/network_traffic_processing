#ifndef __DATA_TYPE_USER__
#define __DATA_TYPE_USER__


#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <vector>
#include <fcntl.h>
#include <sys/epoll.h>
#include <memory>
#include <algorithm>
#include <signal.h>
#include <pthread.h>
#include <unordered_map>
#include <queue>


#define BYTE                    1
#define KILO_BYTE               (1024 * BYTE)
#define MEGA_BYTE               (KILO_BYTE * KILO_BYTE)
#define TERA_BYTE               (KILO_BYTE * MEGA_BYTE)

#define BASE                    (2)  
#define POWER_OF                (3) 
#define MEM_ALIGNED_8BIT        ( BASE ^ POWER_OF )
#define MEM_ALIGNED_16BIT       ( BASE ^ (POWER_OF + 1 ) )
#define MEM_ALIGNED_32BIT       ( BASE ^ (POWER_OF + 2 ) )
#define MEM_ALIGNED_64BIT       ( BASE ^ (POWER_OF + 3 ) )
#define MEM_ALIGNED_128BIT      ( BASE ^ (POWER_OF + 4 ) )

#define PORT                    8000
#define BUFF_MAX_SZ             1024
#define LO_LISTENER             "127.0.0.1"
#define EPOLL_MAX_EVENTS        10
#define EPOLL_WAITE_MS          3000
#define DEFAULT_MEM_POOL_SZ     ( ( KILO_BYTE / 2 ) * MEGA_BYTE )



#define _spin_lock(l) while( !__sync_bool_compare_and_swap(&l, 0, 1));
#define _spin_unlock(l) __sync_bool_compare_and_swap(&l, 1, 0);



struct connection;



template<typename func,typename decl_type, typename container >
	auto container_operations(func fn,
				  decl_type dtype,
				  container& c) -> typename std::result_of<decltype(dtype)()>::type
{
	decltype(dtype()) ret = fn(c); return ret;
}

#pragma pack(1)
template<typename T> struct _queue_ {
	
	std::queue<T> q_data;
	pthread_mutex_t mtx; pthread_cond_t  cnd;

	void erase() {
		
		while( !q_data.empty() )
			q_data.pop();
	}

	_queue_<T>() {
		pthread_mutex_init(&mtx ,NULL);
		pthread_cond_init(&cnd, NULL);
	}
	
	~_queue_<T>() {
		
		pthread_mutex_destroy(&mtx);
		pthread_cond_destroy(&cnd); }
};
#pragma pack(0)



template<typename T> inline T _pop(struct _queue_<T>* q){
  pthread_mutex_lock(&q->mtx);
  T t;
  while(q->q_data.size()==0) pthread_cond_wait(&q->cnd,&q->mtx);                  
  t = q->q_data.front(); q->q_data.pop();
  pthread_mutex_unlock(&q->mtx);  
  return t; 
}   


template<typename T> inline void _push(T t, struct _queue_<T>* q){         
  pthread_mutex_lock(&q->mtx);
  q->q_data.push(t);
  pthread_cond_signal(&q->cnd);
  pthread_mutex_unlock(&q->mtx);      
}

struct rwlock {
	
	pthread_mutex_t lock;
	pthread_cond_t read, write;
	unsigned short readers, writers, read_wait, write_wait;
	
        rwlock():read_wait(0), write_wait(0) {
		
		pthread_mutex_init(&lock,NULL);
		pthread_cond_init(&read,NULL);
		pthread_cond_init(&write,NULL);
	}
	
	~rwlock() {

		pthread_mutex_destroy(&lock);
		pthread_cond_destroy(&read);
		pthread_cond_destroy(&write);
	}
};


template<typename Func> inline void rlock(struct rwlock* l, Func condition) {
	
	pthread_mutex_lock(&l->lock);
	
	if( l->writers || l->write_wait || condition() ) {

		l->read_wait++;
		do{
			pthread_cond_wait(&l->read, &l->lock );
		} while( l->writers || l->write_wait || condition() );
		
		l->read_wait--;  
	}
	
	l->readers++;
	pthread_mutex_unlock(&l->lock);
}

inline void runlock(struct rwlock* l) {

	pthread_mutex_lock(&l->lock);
	l->readers--;
	
	if( l->write_wait )
		pthread_cond_signal(&l->write);
	
	pthread_mutex_unlock(&l->lock);
}


inline void wlock(struct rwlock* l) {

	pthread_mutex_lock(&l->lock);
	
	if ( l->readers || l->writers ) {
		
		l->write_wait++;
		do{
			pthread_cond_wait(&l->write, &l->lock);
		} while( l->readers || l->writers );

		l->write_wait--;
	}
	
	l->writers = 1;
	pthread_mutex_unlock(&l->lock);
}

inline void wunlock(struct rwlock* l) {

	pthread_mutex_lock(&l->lock);
	l->writers = 0;

	if ( l->write_wait )
		pthread_cond_signal(&l->write);
	else if ( l->read_wait )
		pthread_cond_broadcast(&l->read);

	pthread_mutex_unlock(&l->lock);
}



#pragma pack(1)
template<typename T> struct rw_queue_ {
	
	std::queue<T> q_data;
	struct rwlock* l; 

	void erase() {

		while ( !q_data.empty() ) {
			q_data.pop();
			if(l) delete l;
		}
	}
	
        rw_queue_():l(NULL) { l = new struct rwlock; }
	~rw_queue_() { if (l) delete l; }
};
#pragma pack(0)


template<typename T> inline T rw_pop(struct rw_queue_<T>* q) {

	rlock(q->l, [q]() { return ( q->q_data.size() == 0 ); } );
	T t = q->q_data.front();
	q->q_data.pop();
	runlock(q->l);
	
	return t;
}   

template<typename T> inline void rw_push(T t, struct rw_queue_<T>* q) {         

	wlock(q->l);
	q->q_data.push(t);
	wunlock(q->l);
}






void* malloc(size_t);
void* realloc(size_t);
void* calloc(size_t);
void* operator new(size_t);
void free(void*);
void operator delete(void*);
void operator delete[](void*);

#endif
