#include "../inc/data_type.h"





struct mem_pool {

	/*inline __attribute__((always_inline))*/
	int initialize_this(const int& sz) {
       
		p_mem = (void*) ::malloc(sz * sizeof(char));
		if ( p_mem == nullptr ) return 1;
	
		memset(p_mem, sz, sizeof(unsigned char) * sz);

		return 0;
	}

	void destroy_mem_pool() {
		if ( p_mem != nullptr )
			::free(p_mem);
		p_mem = nullptr;			      
	}
	
	static struct mem_pool instance() {
		static struct mem_pool _mem_pool_;
		return _mem_pool_;
	}
	
	//	friend int allocate_memory_ouffset_x(const int& sz);
	
	~mem_pool(){};
	mem_pool operator=(const struct mem_pool&) = delete;
private:
	
	mem_pool(){};
	mem_pool(const struct mem_pool&){};
	void* p_mem{nullptr};	
	
};

void* malloc(size_t sz) { return {nullptr}; }
void* realloc(size_t sz) { return {nullptr}; }
void* calloc(size_t sz) { return {nullptr}; }

void* operator new(size_t sz) { return {nullptr}; }


void free(void* p) { }
void operator delete(void* p) { }
void operator delete[](void* p) { }




int init_mem_pool(const int& poll_size) {

	mem_pool::instance().initialize_this(poll_size);
	return 0;
}



void destroy_mem_pool() {

	mem_pool::instance().destroy_mem_pool();

}
