from StatCounter cimport stat_counter


cdef void update(stat_counter *stats, float new_value):
    stats.count += 1
    stats.sum_val += new_value

    if new_value > stats.max_val:
        stats.max_val = new_value
    if new_value < stats.min_val:
        stats.min_val = new_value

    cdef float delta = new_value - stats.mean
    stats.mean += delta / stats.count
    cdef float delta2 = new_value - stats.mean
    stats.M2 += delta * delta2

    if stats.count >= 2:
        stats.variance = stats.M2 / (stats.count -1)
    else:
        stats.variance = 0

        