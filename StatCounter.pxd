cdef extern from "StatCounter.h":
    struct stat_counter:
        int count
        float mean
        float M2
        float variance
        float max_val
        float min_val
        float sum_val
    ctypedef stat_counter data_t
