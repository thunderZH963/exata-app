#ifndef MIB_MODULES_H_NETSNMP
#define MIB_MODULES_H_NETSNMP


#define DO_INITIALIZE   1
#define DONT_INITIALIZE 0

struct module_init_list {
    char*           module_name;
    struct module_init_list* next;
};

void            add_to_init_list(char* module_list);




#endif
