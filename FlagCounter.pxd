cdef extern from "FlagCounter.h":
    struct flag_counter:
        int fin
        int syn
        int rst
        int psh
        int ack
        int urg
        int cwr
        int ece
        int psh_forward
        int psh_backward
        int urg_forward
        int urg_backward

    ctypedef flag_counter data_t
