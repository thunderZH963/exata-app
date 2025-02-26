#ifndef SNMP_TC_H_NETSNMP
#define SNMP_TC_H_NETSNMP

    /*
     * snmp-tc.h: Provide some standard #defines for Textual Convention
     * related value information
     */

    int
    netsnmp_dateandtime_set_buf_from_vars(u_char* buf, size_t* bufsize,
                                          u_short y, u_char mon, u_char d,
                                          u_char h, u_char min, u_char s,
                                          u_char deci_seconds,
                                          int utc_offset_direction,
                                          u_char utc_offset_hours,
                                          u_char utc_offset_minutes);

    u_char*         date_n_time(const time_t* , size_t*);
    time_t          ctime_to_timet(const char*);

    /*
     * TrueValue
     */
#define TV_TRUE 1
#define TV_FALSE 2

    /*
     * RowStatus
     */
#define RS_NONEXISTENT    0
#define RS_ACTIVE            1
#define RS_NOTINSERVICE            2
#define RS_NOTREADY            3
#define RS_CREATEANDGO            4
#define RS_CREATEANDWAIT    5
#define RS_DESTROY        6

#define RS_IS_GOING_ACTIVE(x) (x == RS_CREATEANDGO || x == RS_ACTIVE)
#define RS_IS_ACTIVE(x) (x == RS_ACTIVE)
#define RS_IS_NOT_ACTIVE(x) (! RS_IS_GOING_ACTIVE(x))

    /*
     * StorageType
     */
#define ST_NONE 0
#define ST_OTHER    1
#define ST_VOLATILE    2
#define ST_NONVOLATILE    3
#define ST_PERMANENT    4
#define ST_READONLY    5

    char            check_rowstatus_transition(int old_val, int new_val);
    char            check_storage_transition(int old_val, int new_val);


#endif                          /* SNMP_TC_H */
