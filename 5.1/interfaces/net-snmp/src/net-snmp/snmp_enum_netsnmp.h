#ifndef SNMP_ENUM_H_NETSNMP
#define SNMP_ENUM_H_NETSNMP

     /* error codes
     */
#define SE_OK            0
#define SE_NOMEM         1
#define SE_ALREADY_THERE 2
#define SE_DNE           -2
#define SE_MAX_IDS 5
#define SE_MAX_SUBIDS 32        /* needs to be a multiple of 8 */

    struct snmp_enum_list {
        struct snmp_enum_list* next;
        int             value;
        char*           label;
    };


    struct snmp_enum_list_str {
    char*           name;
    struct snmp_enum_list* list;
    struct snmp_enum_list_str* next;
};

char*           se_find_label_in_list(struct snmp_enum_list* list,
                                          int value);



#endif /* SNMP_ENUM_H_NETSNMP*/


