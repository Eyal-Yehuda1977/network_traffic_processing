#ifndef _FINGERP_PARAMS_H_
#define _FINGERP_PARAMS_H_

#define FINGERP_NMAP_IP_ID_ZERO    (0x8000) 
//nmap + nexpos
#define FINGERP_IP_ID_PROB_TYPE_1  1
#define FINGERP_IP_ID_PROB_TYPE_2  2
#define FINGERP_IP_ID_PROB_TYPE_3  3
#define FINGERP_IP_ID_PROB_TYPE_4  4
#define FINGERP_IP_ID_PROB_TYPE_5  5
#define FINGERP_IP_ID_PROB_TYPE_6  6
#define FINGERP_IP_ID_PROB_TYPE_7  7
#define FINGERP_IP_ID_PROB_TYPE_8  8
#define FINGERP_IP_ID_PROB_TYPE_9  9
#define FINGERP_IP_ID_PROB_TYPE_10 10
#define FINGERP_IP_ID_PROB_TYPE_11 11
#define FINGERP_IP_ID_PROB_TYPE_12 12
#define FINGERP_IP_ID_PROB_TYPE_13 13
#define FINGERP_IP_ID_PROB_TYPE_14 14
#define FINGERP_IP_ID_PROB_TYPE_15 15
#define FINGERP_IP_ID_PROB_TYPE_16 16
#define FINGERP_IP_ID_PROB_TYPE_17 17
//end nmap + nexpos 

//nessus
#define FINGERP_IP_ID_PROB_TYPE_18 18
#define FINGERP_IP_ID_PROB_TYPE_19 19
#define FINGERP_IP_ID_PROB_TYPE_20 20
#define FINGERP_IP_ID_PROB_TYPE_21 21
#define FINGERP_IP_ID_PROB_TYPE_22 22
#define FINGERP_IP_ID_PROB_TYPE_23 23
#define FINGERP_IP_ID_PROB_TYPE_24 24
#define FINGERP_IP_ID_PROB_TYPE_25 25
#define FINGERP_IP_ID_PROB_TYPE_26 26
#define FINGERP_IP_ID_PROB_TYPE_27 27
#define FINGERP_IP_ID_PROB_TYPE_28 28
#define FINGERP_IP_ID_PROB_TYPE_29 29
#define FINGERP_IP_ID_PROB_TYPE_30 30
#define FINGERP_IP_ID_PROB_TYPE_31 31
#define FINGERP_IP_ID_PROB_TYPE_32 32
#define FINGERP_IP_ID_PROB_TYPE_33 33
#define FINGERP_IP_ID_PROB_TYPE_34 34
//end nessus


// color outgoing traffic 
#define FINGERP_IP_ID_PROB_TYPE_OUT_35 35 // tcp
#define FINGERP_IP_ID_PROB_TYPE_OUT_36 36 // udp
//end coloring 
#define ICMP_DNR 37

#define FINGERP_IP_ID_PROB_TYPE_SUSPECTED_TRAP 38
#define LOOP_BACK_ADDR "127.0.0.1"


                               /* 2 */  
struct tcp_option_mss      {uint8_t kind; uint8_t len; uint16_t  mss;                  }__attribute__((packed));
                               /* 1 */
struct tcp_option_nop      {uint8_t kind;                                              }__attribute__((packed));
                               /* 3 */ 
struct tcp_option_wnds     {uint8_t kind; uint8_t len; uint8_t shftc;                  }__attribute__((packed));
                               /* 8 */
struct tcp_option_tsval    {uint8_t kind; uint8_t len; uint32_t tsval; uint32_t tsecr; }__attribute__((packed));
                               /* 4 */ 
struct tcp_option_sack_per {uint8_t kind; uint8_t len;                                 }__attribute__((packed));
                               /* 0 */ 
struct eol_option          {uint8_t kind;                                              }__attribute__((packed));
                               /* 5 */
struct tcp_option_sack     {uint8_t kind; uint8_t len;                                 }__attribute__((packed));




/* The way to identify icmp echo test by nmap */
static const __be16  FINGERP_NMAP_ICMP_ECHO_SEQ1      = __constant_htons(0x0127);
static const  int    FINGERP_NMAP_ICMP_ECHO_DATA_LEN1 = 120;
static const __be16  FINGERP_NMAP_ICMP_ECHO_SEQ2      = __constant_htons(0x0128);
static const  int    FINGERP_NMAP_ICMP_ECHO_DATA_LEN2 = 150;


#endif /* _FINGERP_PARAMS_H_ */

