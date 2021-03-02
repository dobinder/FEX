#ifndef __FLAGCOUNTER_H_
#define __FLAGCOUNTER_H_

typedef struct flag_counter {
        int fin;
        int syn;
        int rst;
        int psh;
        int ack;
        int urg;
        int cwr;
        int ece;
        int psh_forward;
        int psh_backward;
        int urg_forward;
        int urg_backward;
} flag_counter;

#endif //__FLAGCOUNTER_H_