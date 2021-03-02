#ifndef __STATCOUNTER_H_
#define __STATCOUNTER_H_

typedef struct stat_counter {
    int count;
    float mean;
    float M2;
    float variance;
    float max_val;
    float min_val;
    float sum_val;
} stat_counter;

#endif //__STATCOUNTER_H_