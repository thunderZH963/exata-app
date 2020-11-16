#ifndef PARSE_H_NETSNMP
#define PARSE_H_NETSNMP


#include "types_netsnmp.h"

class NetSnmpAgent;
    /*
     * non-aggregate types for tree end nodes
     */
#define TYPE_OTHER          0
#define TYPE_OBJID          1
#define TYPE_OCTETSTR       2
#define TYPE_INTEGER        3
#define TYPE_NETADDR        4
#define TYPE_IPADDR         5
#define TYPE_COUNTER        6
#define TYPE_GAUGE          7
#define TYPE_TIMETICKS      8
#define TYPE_OPAQUE         9
#define TYPE_NULL           10
#define TYPE_COUNTER64      11
#define TYPE_BITSTRING      12
#define TYPE_NSAPADDRESS    13
#define TYPE_UINTEGER       14
#define TYPE_UNSIGNED32     15
#define TYPE_INTEGER32      16

#define TYPE_SIMPLE_LAST    16

#define TYPE_TRAPTYPE        20
#define TYPE_NOTIFTYPE      21
#define TYPE_OBJGROUP        22
#define TYPE_NOTIFGROUP        23
#define TYPE_MODID        24
#define TYPE_AGENTCAP       25
#define TYPE_MODCOMP        26
#define TYPE_OBJIDENTITY    27

#define MIB_ACCESS_READONLY    18
#define MIB_ACCESS_READWRITE   19
#define    MIB_ACCESS_WRITEONLY   20
#define MIB_ACCESS_NOACCESS    21
#define MIB_ACCESS_NOTIFY      67
#define MIB_ACCESS_CREATE      48

#define MIB_STATUS_MANDATORY   23
#define MIB_STATUS_OPTIONAL    24
#define MIB_STATUS_OBSOLETE    25
#define MIB_STATUS_DEPRECATED  39
#define MIB_STATUS_CURRENT     57

#define    ANON    "anonymous#"
#define    ANON_LEN  strlen(ANON)


#define MAXLABEL        64      /* maximum characters in a label */
#define MAXTOKEN        128     /* maximum characters in a token */
#define MAXQUOTESTR     4096    /* maximum characters in a quoted string */

#define HASHSIZE        32

#define BUCKET(x)       (x & (HASHSIZE-1))

#define NHASHSIZE    128
#define NBUCKET(x)   (x & (NHASHSIZE-1))

#define    NUMBER_OF_ROOT_NODES    3

struct tok {
    const char*     name;       /* token name */
    int             len;        /* length not counting nul */
    int             token;      /* value */
    int             hash;       /* hash of name */
    struct tok*     next;       /* pointer to next in hash table */
};


    /*
     * A linked list of varbinds
     */
    struct varbind_list {
        struct varbind_list* next;
        char*           vblabel;
    };

    /*
     * Information held about each MIB module
     */
    struct module_import {
        char*           label;  /* The descriptor being imported */
        int             modid;  /* The module imported from */
    };

struct objgroup {
    char*           name;
    int             line;
    struct objgroup* next;
};
/*
 * A linked list of nodes.
 */
struct NetSnmpNode {
    struct NetSnmpNode*    next;
    char*           label;  /* This node's (unique) textual name */
    u_long          subid;  /* This node's integer subidentifier */
    int             modid;  /* The module containing this node */
    char*           parent; /* The parent's textual name */
    int             tc_index; /* index into tclist (-1 if NA) */
    int             type;   /* The type of object this represents */
    int             access;
    int             status;
    struct enum_list* enums; /* (optional) list of enumerated integers */
    struct range_list* ranges;
    struct index_list* indexes;
    char*           augments;
    struct varbind_list* varbinds;
    char*           hint;
    char*           units;
    char*           description; /* description (a quoted string) */
    char*           reference; /* references (a quoted string) */
    char*           defaultValue;
    char*           filename;
    int             lineno;
};


/*
 * This is one element of an object identifier with either an integer
 * subidentifier, or a textual string label, or both.
 * The subid is -1 if not present, and label is NULL if not present.
 */
struct subid_s {
    int             subid;
    int             modid;
    char*           label;
};
    /*
     * A linked list of ranges
     */
    struct range_list {
        struct range_list* next;
        int             low, high;
    };

/*
     * A tree in the format of the tree structure of the MIB.
     */
    struct tree {
        struct tree*    child_list;     /* list of children of this node */
        struct tree*    next_peer;      /* Next node in list of peers */
        struct tree*    next;   /* Next node in hashed list of names */
        struct tree*    parent;
        char*           label;  /* This node's textual name */
        u_long          subid;  /* This node's integer subidentifier */
        int             modid;  /* The module containing this node */
        int             number_modules;
        int*            module_list;    /* To handle multiple modules */
        int             tc_index;       /* index into tclist (-1 if NA) */
        int             type;   /* This node's object type */
        int             access; /* This nodes access */
        int             status; /* This nodes status */
        struct enum_list* enums;        /* (optional) list of enumerated integers */
        struct range_list* ranges;
        struct index_list* indexes;
        char*           augments;
        struct varbind_list* varbinds;
        char*           hint;
        char*           units;
        int             (NetSnmpAgent::*printomat) (u_char** , size_t* , size_t* , int,
                                      const netsnmp_variable_list* ,
                                      const struct enum_list* , const char* ,
                                      const char*);
        void            (*printer) (char* , const netsnmp_variable_list* , const struct enum_list* , const char* , const char*);   /* Value printing function */
        char*           description;    /* description (a quoted string) */
        char*           reference;    /* references (a quoted string) */
        int             reported;       /* 1=report started in print_subtree... */
        char*           defaultValue;
    };


        /*
     * A linked list of indexes
     */
    struct index_list {
        struct index_list* next;
        char*           ilabel;
        char            isimplied;
    };


    struct enum_list {
        struct enum_list* next;
        int             value;
        char*           label;
    };

    struct module {
        char*           name;   /* This module's name */
        char*           file;   /* The file containing the module */
        struct module_import* imports;  /* List of descriptors being imported */
        int             no_imports;     /* The number of such import descriptors */
        /*
         * -1 implies the module hasn't been read in yet
         */
        int             modid;  /* The index number of this module */
        struct module*  next;   /* Linked list pointer */
    };

    struct module_compatability {
        const char*     old_module;
        const char*     new_module;
        const char*     tag;    /* NULL implies unconditional replacement,
                                 * otherwise node identifier or prefix */
        size_t          tag_len;        /* 0 implies exact match (or unconditional) */
        struct module_compatability* next;      /* linked list */
    };

#define MAXTC   4096
struct tc {                     /* textual conventions */
    int             type;
    int             modid;
    char*           descriptor;
    char*           hint;
    struct enum_list* enums;
    struct range_list* ranges;
    char*           description;
};

const char*
get_tc_descriptor(int tc_index);

const char*
get_tc_description(int tc_index);



#endif /* _NETSNMP */


