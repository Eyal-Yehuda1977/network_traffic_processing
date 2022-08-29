#include "../inc/data_type.h"






struct daemon_data_type {

	/*
	inline __attribute__((always_inline)) int initialize_this() {
		return (is_initialized != 0) ? 0 : 1;
			: return initialize_daemon_data_type(); ? return 0;
		}*/
	
	static struct daemon_data_type instance() {
		
		static daemon_data_type _daemon_data_type_;			
	        return _daemon_data_type_;
	}


        ~daemon_data_type(){};
	daemon_data_type operator=(const daemon_data_type) = delete;
	
private:

	int is_initialized{1};

	//std::unordered_map<int ,struct connection> map_connections;


	
	daemon_data_type(){};
        daemon_data_type(const daemon_data_type&){ initialize_this(); };
		
	int initialize_this() {
		
		int ret{0};

		return ret;
	}
};


