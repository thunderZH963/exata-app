#include "parse_netsnmp.h"
#include "node.h"
#include "mib_netsnmp.h"
#include "default_store_netsnmp.h"
#include "tools_netsnmp.h"
#include "system_netsnmp.h"
#include "netSnmpAgent.h"
#include <errno.h>

#if !(defined(WIN32) || defined(cygwin))
#include <sys/stat.h>
#endif

#define    label_compare    strcmp

#define MODULE_NOT_FOUND    0
#define MODULE_LOADED_OK    1
#define MODULE_ALREADY_LOADED    2
#define MODULE_LOAD_FAILED    MODULE_NOT_FOUND

/*
 * types of tokens
 * Tokens wiht the SYNTAX_MASK bit set are syntax tokens
 */


#define SYNTAX_MASK     0x80

#define MAX_BAD 0xffffff
# define dirent direct


#define CONTINUE    -1
#define ENDOFFILE   0
#define LABEL       1
#define SUBTREE     2
#define SYNTAX      3
#define OBJID       (4 | SYNTAX_MASK)
#define OCTETSTR    (5 | SYNTAX_MASK)
#define INTEGER     (6 | SYNTAX_MASK)
#define NETADDR     (7 | SYNTAX_MASK)
#define IPADDR      (8 | SYNTAX_MASK)
#define COUNTER     (9 | SYNTAX_MASK)
#define GAUGE       (10 | SYNTAX_MASK)
#define TIMETICKS   (11 | SYNTAX_MASK)
#define KW_OPAQUE   (12 | SYNTAX_MASK)
#define NUL         (13 | SYNTAX_MASK)
#define SEQUENCE    14
#define OF          15          /* SEQUENCE OF */
#define OBJTYPE     16
#define READONLY    18
#define READWRITE   19
#define WRITEONLY   20
#ifdef NOACCESS
#undef NOACCESS                 /* agent 'NOACCESS' token */
#endif
#define NOACCESS    21
#define STATUS      22
#define MANDATORY   23
#define KW_OPTIONAL    24
#define OBSOLETE    25
/*
 * #define RECOMMENDED 26
 */
#define PUNCT       27
#define EQUALS      28
#define NUMBER      29
#define LEFTBRACKET 30
#define RIGHTBRACKET 31
#define LEFTPAREN   32
#define RIGHTPAREN  33
#define COMMA       34
#define DESCRIPTION 35
#define QUOTESTRING 36
//#define INDEX       37
#define DEFVAL      38
#define DEPRECATED  39
#define SIZE        40
#define BITSTRING   (41 | SYNTAX_MASK)
#define NSAPADDRESS (42 | SYNTAX_MASK)
#define COUNTER64   (43 | SYNTAX_MASK)
#define OBJGROUP    44
#define NOTIFTYPE   45
#define AUGMENTS    46
#define COMPLIANCE  47
#define READCREATE  48
#define UNITS       49
#define REFERENCE   50
#define NUM_ENTRIES 51
#define MODULEIDENTITY 52
#define LASTUPDATED 53
#define ORGANIZATION 54
#define CONTACTINFO 55
#define UINTEGER32 (56 | SYNTAX_MASK)
#define CURRENT     57
#define DEFINITIONS 58
#define END         59
#define SEMI        60
#define TRAPTYPE    61
#define ENTERPRISE  62
/*
 * #define DISPLAYSTR (63 | SYNTAX_MASK)
 */
#define BEGIN       64
#define IMPORTS     65
#define EXPORTS     66
#define ACCNOTIFY   67
#define BAR         68
#define RANGE       69
#define CONVENTION  70
#define DISPLAYHINT 71
#define FROM        72
#define AGENTCAP    73
#define MACRO       74
#define IMPLIED     75
#define SUPPORTS    76
#define INCLUDES    77
#define VARIATION   78
#define REVISION    79
#define NOTIMPL        80
#define OBJECTS        81
#define NOTIFICATIONS    82
#define MODULE        83
#define MINACCESS   84
#define PRODREL        85
#define WRSYNTAX    86
#define CREATEREQ   87
#define NOTIFGROUP  88
#define MANDATORYGROUPS    89
#define GROUP        90
#define OBJECT        91
#define IDENTIFIER  92
#define CHOICE        93
#define LEFTSQBRACK    95
#define RIGHTSQBRACK    96
#define IMPLICIT    97
#define APPSYNTAX    (98 | SYNTAX_MASK)
#define OBJSYNTAX    (99 | SYNTAX_MASK)
#define SIMPLESYNTAX    (100 | SYNTAX_MASK)
#define OBJNAME        (101 | SYNTAX_MASK)
#define NOTIFNAME    (102 | SYNTAX_MASK)
#define VARIABLES    103
#define UNSIGNED32    (104 | SYNTAX_MASK)
#define INTEGER32    (105 | SYNTAX_MASK)
#define OBJIDENTITY    106




static struct tok tokens[] = {
    {"obsolete", sizeof("obsolete") - 1, OBSOLETE}
    ,
    {"Opaque", sizeof("Opaque") - 1, KW_OPAQUE}
    ,
    {"optional", sizeof("optional") - 1, KW_OPTIONAL}
    ,
    {"LAST-UPDATED", sizeof("LAST-UPDATED") - 1, LASTUPDATED}
    ,
    {"ORGANIZATION", sizeof("ORGANIZATION") - 1, ORGANIZATION}
    ,
    {"CONTACT-INFO", sizeof("CONTACT-INFO") - 1, CONTACTINFO}
    ,
    {"MODULE-IDENTITY", sizeof("MODULE-IDENTITY") - 1, MODULEIDENTITY}
    ,
    {"MODULE-COMPLIANCE", sizeof("MODULE-COMPLIANCE") - 1, COMPLIANCE}
    ,
    {"DEFINITIONS", sizeof("DEFINITIONS") - 1, DEFINITIONS}
    ,
    {"END", sizeof("END") - 1, END}
    ,
    {"AUGMENTS", sizeof("AUGMENTS") - 1, AUGMENTS}
    ,
    {"not-accessible", sizeof("not-accessible") - 1, NOACCESS}
    ,
    {"write-only", sizeof("write-only") - 1, WRITEONLY}
    ,
    {"NsapAddress", sizeof("NsapAddress") - 1, NSAPADDRESS}
    ,
    {"UNITS", sizeof("Units") - 1, UNITS}
    ,
    {"REFERENCE", sizeof("REFERENCE") - 1, REFERENCE}
    ,
    {"NUM-ENTRIES", sizeof("NUM-ENTRIES") - 1, NUM_ENTRIES}
    ,
    {"BITSTRING", sizeof("BITSTRING") - 1, BITSTRING}
    ,
    {"BIT", sizeof("BIT") - 1, CONTINUE}
    ,
    {"BITS", sizeof("BITS") - 1, BITSTRING}
    ,
    {"Counter64", sizeof("Counter64") - 1, COUNTER64}
    ,
    {"TimeTicks", sizeof("TimeTicks") - 1, TIMETICKS}
    ,
    {"NOTIFICATION-TYPE", sizeof("NOTIFICATION-TYPE") - 1, NOTIFTYPE}
    ,
    {"OBJECT-GROUP", sizeof("OBJECT-GROUP") - 1, OBJGROUP}
    ,
    {"OBJECT-IDENTITY", sizeof("OBJECT-IDENTITY") - 1, OBJIDENTITY}
    ,
    {"IDENTIFIER", sizeof("IDENTIFIER") - 1, IDENTIFIER}
    ,
    {"OBJECT", sizeof("OBJECT") - 1, OBJECT}
    ,
    {"NetworkAddress", sizeof("NetworkAddress") - 1, NETADDR}
    ,
    {"Gauge", sizeof("Gauge") - 1, GAUGE}
    ,
    {"Gauge32", sizeof("Gauge32") - 1, GAUGE}
    ,
    {"Unsigned32", sizeof("Unsigned32") - 1, UNSIGNED32}
    ,
    {"read-write", sizeof("read-write") - 1, READWRITE}
    ,
    {"read-create", sizeof("read-create") - 1, READCREATE}
    ,
    {"OCTETSTRING", sizeof("OCTETSTRING") - 1, OCTETSTR}
    ,
    {"OCTET", sizeof("OCTET") - 1, CONTINUE}
    ,
    {"OF", sizeof("OF") - 1, OF}
    ,
    {"SEQUENCE", sizeof("SEQUENCE") - 1, SEQUENCE}
    ,
    {"NULL", sizeof("NULL") - 1, NUL}
    ,
    {"IpAddress", sizeof("IpAddress") - 1, IPADDR}
    ,
    {"UInteger32", sizeof("UInteger32") - 1, UINTEGER32}
    ,
    {"INTEGER", sizeof("INTEGER") - 1, INTEGER}
    ,
    {"Integer32", sizeof("Integer32") - 1, INTEGER32}
    ,
    {"Counter", sizeof("Counter") - 1, COUNTER}
    ,
    {"Counter32", sizeof("Counter32") - 1, COUNTER}
    ,
    {"read-only", sizeof("read-only") - 1, READONLY}
    ,
    {"DESCRIPTION", sizeof("DESCRIPTION") - 1, DESCRIPTION}
    ,
    {"INDEX", sizeof("INDEX") - 1, INDEX}
    ,
    {"DEFVAL", sizeof("DEFVAL") - 1, DEFVAL}
    ,
    {"deprecated", sizeof("deprecated") - 1, DEPRECATED}
    ,
    {"SIZE", sizeof("SIZE") - 1, SIZE}
    ,
    {"MAX-ACCESS", sizeof("MAX-ACCESS") - 1, ACCESS}
    ,
    {"ACCESS", sizeof("ACCESS") - 1, ACCESS}
    ,
    {"mandatory", sizeof("mandatory") - 1, MANDATORY}
    ,
    {"current", sizeof("current") - 1, CURRENT}
    ,
    {"STATUS", sizeof("STATUS") - 1, STATUS}
    ,
    {"SYNTAX", sizeof("SYNTAX") - 1, SYNTAX}
    ,
    {"OBJECT-TYPE", sizeof("OBJECT-TYPE") - 1, OBJTYPE}
    ,
    {"TRAP-TYPE", sizeof("TRAP-TYPE") - 1, TRAPTYPE}
    ,
    {"ENTERPRISE", sizeof("ENTERPRISE") - 1, ENTERPRISE}
    ,
    {"BEGIN", sizeof("BEGIN") - 1, BEGIN}
    ,
    {"IMPORTS", sizeof("IMPORTS") - 1, IMPORTS}
    ,
    {"EXPORTS", sizeof("EXPORTS") - 1, EXPORTS}
    ,
    {"accessible-for-notify", sizeof("accessible-for-notify") - 1,
     ACCNOTIFY}
    ,
    {"TEXTUAL-CONVENTION", sizeof("TEXTUAL-CONVENTION") - 1, CONVENTION}
    ,
    {"NOTIFICATION-GROUP", sizeof("NOTIFICATION-GROUP") - 1, NOTIFGROUP}
    ,
    {"DISPLAY-HINT", sizeof("DISPLAY-HINT") - 1, DISPLAYHINT}
    ,
    {"FROM", sizeof("FROM") - 1, FROM}
    ,
    {"AGENT-CAPABILITIES", sizeof("AGENT-CAPABILITIES") - 1, AGENTCAP}
    ,
    {"MACRO", sizeof("MACRO") - 1, MACRO}
    ,
    {"IMPLIED", sizeof("IMPLIED") - 1, IMPLIED}
    ,
    {"SUPPORTS", sizeof("SUPPORTS") - 1, SUPPORTS}
    ,
    {"INCLUDES", sizeof("INCLUDES") - 1, INCLUDES}
    ,
    {"VARIATION", sizeof("VARIATION") - 1, VARIATION}
    ,
    {"REVISION", sizeof("REVISION") - 1, REVISION}
    ,
    {"not-implemented", sizeof("not-implemented") - 1, NOTIMPL}
    ,
    {"OBJECTS", sizeof("OBJECTS") - 1, OBJECTS}
    ,
    {"NOTIFICATIONS", sizeof("NOTIFICATIONS") - 1, NOTIFICATIONS}
    ,
    {"MODULE", sizeof("MODULE") - 1, MODULE}
    ,
    {"MIN-ACCESS", sizeof("MIN-ACCESS") - 1, MINACCESS}
    ,
    {"PRODUCT-RELEASE", sizeof("PRODUCT-RELEASE") - 1, PRODREL}
    ,
    {"WRITE-SYNTAX", sizeof("WRITE-SYNTAX") - 1, WRSYNTAX}
    ,
    {"CREATION-REQUIRES", sizeof("CREATION-REQUIRES") - 1, CREATEREQ}
    ,
    {"MANDATORY-GROUPS", sizeof("MANDATORY-GROUPS") - 1, MANDATORYGROUPS}
    ,
    {"GROUP", sizeof("GROUP") - 1, GROUP}
    ,
    {"CHOICE", sizeof("CHOICE") - 1, CHOICE}
    ,
    {"IMPLICIT", sizeof("IMPLICIT") - 1, IMPLICIT}
    ,
    {"ObjectSyntax", sizeof("ObjectSyntax") - 1, OBJSYNTAX}
    ,
    {"SimpleSyntax", sizeof("SimpleSyntax") - 1, SIMPLESYNTAX}
    ,
    {"ApplicationSyntax", sizeof("ApplicationSyntax") - 1, APPSYNTAX}
    ,
    {"ObjectName", sizeof("ObjectName") - 1, OBJNAME}
    ,
    {"NotificationName", sizeof("NotificationName") - 1, NOTIFNAME}
    ,
    {"VARIABLES", sizeof("VARIABLES") - 1, VARIABLES}
    ,
    {NULL}
};



static struct module_compatability module_map[] = {
    {"RFC1065-SMI", "RFC1155-SMI", NULL, 0},
    {"RFC1066-MIB", "RFC1156-MIB", NULL, 0},
    /*
     * 'mib' -> 'mib-2'
     */
    {"RFC1156-MIB", "RFC1158-MIB", NULL, 0},
    /*
     * 'snmpEnableAuthTraps' -> 'snmpEnableAuthenTraps'
     */
    {"RFC1158-MIB", "RFC1213-MIB", NULL, 0},
    /*
     * 'nullOID' -> 'zeroDotZero'
     */
    {"RFC1155-SMI", "SNMPv2-SMI", NULL, 0},
    {"RFC1213-MIB", "SNMPv2-SMI", "mib-2", 0},
    {"RFC1213-MIB", "SNMPv2-MIB", "sys", 3},
    {"RFC1213-MIB", "IF-MIB", "if", 2},
    {"RFC1213-MIB", "IP-MIB", "ip", 2},
    {"RFC1213-MIB", "IP-MIB", "icmp", 4},
    {"RFC1213-MIB", "TCP-MIB", "tcp", 3},
    {"RFC1213-MIB", "UDP-MIB", "udp", 3},
    {"RFC1213-MIB", "SNMPv2-SMI", "transmission", 0},
    {"RFC1213-MIB", "SNMPv2-MIB", "snmp", 4},
    {"RFC1231-MIB", "TOKENRING-MIB", NULL, 0},
    {"RFC1271-MIB", "RMON-MIB", NULL, 0},
    {"RFC1286-MIB", "SOURCE-ROUTING-MIB", "dot1dSr", 7},
    {"RFC1286-MIB", "BRIDGE-MIB", NULL, 0},
    {"RFC1315-MIB", "FRAME-RELAY-DTE-MIB", NULL, 0},
    {"RFC1316-MIB", "CHARACTER-MIB", NULL, 0},
    {"RFC1406-MIB", "DS1-MIB", NULL, 0},
    {"RFC-1213", "RFC1213-MIB", NULL, 0},
};
static void
free_indexes(struct index_list** spp)
{
    if (spp && *spp) {
        struct index_list* pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->ilabel)
                free(pp->ilabel);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_varbinds(struct varbind_list** spp)
{
    if (spp && *spp) {
        struct varbind_list* pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->vblabel)
                free(pp->vblabel);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_ranges(struct range_list** spp)
{
    if (spp && *spp) {
        struct range_list* pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            free(pp);
            pp = npp;
        }
    }
}
static void
free_enums(struct enum_list** spp)
{
    if (spp && *spp) {
        struct enum_list* pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->label)
                free(pp->label);
            free(pp);
            pp = npp;
        }
    }
}

static void
free_node(struct NetSnmpNode* np)
{
    if (!np)
        return;

    free_enums(&np->enums);
    free_ranges(&np->ranges);
    free_indexes(&np->indexes);
    free_varbinds(&np->varbinds);
    if (np->label)
        free(np->label);
    if (np->hint)
        free(np->hint);
    if (np->units)
        free(np->units);
    if (np->description)
        free(np->description);
    if (np->reference)
        free(np->reference);
    if (np->defaultValue)
        free(np->defaultValue);
    if (np->parent)
        free(np->parent);
    if (np->augments)
        free(np->augments);
    if (np->filename)
    free(np->filename);
    free((char*) np);
}


static          u_int
compute_match(const char* search_base, const char* key)
{
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    int             rc;
    regex_t         parsetree;
    regmatch_t      pmatch;
    rc = regcomp(&parsetree, key, REG_ICASE | REG_EXTENDED);
    if (rc == 0)
        rc = regexec(&parsetree, search_base, 1, &pmatch, 0);
    regfree(&parsetree);
    if (rc == 0) {
        /*
         * found
         */
        return pmatch.rm_so;
    }
#else                           /* use our own wildcard matcher */
    /*
     * first find the longest matching substring (ick)
     */
    const char*           first = NULL, *result = NULL, *entry;
    const char*     position;
    char*           newkey = strdup(key);


    entry = strtok(newkey, "*");
    position = search_base;
    while (entry) {
        result = strcasestr(position, entry);

        if (result == NULL) {
            free(newkey);
            return MAX_BAD;
        }

        if (first == NULL)
            first = result;

        position = result + strlen(entry);
        entry = strtok(NULL, "*");
    }
    free(newkey);
    if (result)
        return (first - search_base);
#endif

    /*
     * not found
     */
    return MAX_BAD;
}
/*
 * return zero if character is not a label character.
 */
int
NetSnmpAgent::is_labelchar(int ich)
{
    if ((isalnum(ich)) || (ich == '-'))
        return 1;
    if (ich == '_' && netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                         NETSNMP_DS_LIB_MIB_PARSE_LABEL)) {
        return 1;
    }

    return 0;
}


int
NetSnmpAgent::parseQuoteString(FILE*  fp, char* token, int maxtlen)
{
    register int    ch;
    int             count = 0;
    int             too_long = 0;
    char*           token_start = token;

    for (ch = getc(fp); ch != EOF; ch = getc(fp)) {
        if (ch == '\r')
            continue;
        if (ch == '\n') {
            mibLine++;
        } else if (ch == '"') {
            *token = '\0';
            if (too_long && netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_WARNINGS) > 1) {
                /*
                 * show short form for brevity sake
                 */
                char            ch_save = *(token_start + 50);
                *(token_start + 50) = '\0';
                *(token_start + 50) = ch_save;
            }
            return QUOTESTRING;
        }
        /*
         * maximum description length check.  If greater, keep parsing
         * but truncate the string
         */
        if (++count < maxtlen)
            *token++ = ch;
        else
            too_long = 1;
    }

    return 0;
}

/*
 * Parses a token from the file.  The type of the token parsed is returned,
 * and the text is placed in the string pointed to by token.
 * Warning: this method may recurse.
 */
int
NetSnmpAgent::get_token(FILE*  fp, char* token, int maxtlen)
{
    register int    ch, ch_next;
    register char*  cp = token;
    register int    hash = 0;
    register struct tok* tp = NULL;
    int             too_long = 0;
    enum { bdigits, xdigits, other } seenSymbols;

    /*
     * skip all white space
     */
    do {
        ch = getc(fp);
        if (ch == '\n')
            mibLine++;
    }
    while (isspace(ch) && ch != EOF);
    *cp++ = ch;
    *cp = '\0';
    switch (ch) {
    case EOF:
        return ENDOFFILE;
    case '"':
        return parseQuoteString(fp, token, maxtlen);
    case '\'':                 /* binary or hex constant */
        seenSymbols = bdigits;
        while ((ch = getc(fp)) != EOF && ch != '\'') {
            switch (seenSymbols) {
            case bdigits:
                if (ch == '0' || ch == '1')
                    break;
                seenSymbols = xdigits;
            case xdigits:
                if (isxdigit(ch))
                    break;
                seenSymbols = other;
            case other:
                break;
            }
            if (cp - token < maxtlen - 2)
                *cp++ = ch;
        }
        if (ch == '\'') {
            unsigned long   val = 0;
            char*           run = token + 1;
            ch = getc(fp);
            switch (ch) {
            case EOF:
                return ENDOFFILE;
            case 'b':
            case 'B':
                if (seenSymbols > bdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp)
                    val = val * 2 + *run++ - '0';
                break;
            case 'h':
            case 'H':
                if (seenSymbols > xdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp) {
                    ch = *run++;
                    if ('0' <= ch && ch <= '9')
                        val = val * 16 + ch - '0';
                    else if ('a' <= ch && ch <= 'f')
                        val = val * 16 + ch - 'a' + 10;
                    else if ('A' <= ch && ch <= 'F')
                        val = val * 16 + ch - 'A' + 10;
                }
                break;
            default:
                *cp++ = '\'';
                *cp = 0;
                return LABEL;
            }
            sprintf(token, "%ld", val);
            return NUMBER;
        } else
            return LABEL;
    case '(':
        return LEFTPAREN;
    case ')':
        return RIGHTPAREN;
    case '{':
        return LEFTBRACKET;
    case '}':
        return RIGHTBRACKET;
    case '[':
        return LEFTSQBRACK;
    case ']':
        return RIGHTSQBRACK;
    case ';':
        return SEMI;
    case ',':
        return COMMA;
    case '|':
        return BAR;
    case '.':
        ch_next = getc(fp);
        if (ch_next == '.')
            return RANGE;
        ungetc(ch_next, fp);
        return LABEL;
    case ':':
        ch_next = getc(fp);
        if (ch_next != ':') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        ch_next = getc(fp);
        if (ch_next != '=') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        return EQUALS;
    case '-':
        ch_next = getc(fp);
        if (ch_next == '-') {
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_COMMENT_TERM)) {
                /*
                 * Treat the rest of this line as a comment.
                 */
                while ((ch_next != EOF) && (ch_next != '\n'))
                    ch_next = getc(fp);
            } else {
                /*
                 * Treat the rest of the line or until another '--' as a comment
                 */
                /*
                 * (this is the "technically" correct way to parse comments)
                 */
                ch = ' ';
                ch_next = getc(fp);
                while (ch_next != EOF && ch_next != '\n' &&
                       (ch != '-' || ch_next != '-')) {
                    ch = ch_next;
                    ch_next = getc(fp);
                }
            }
            if (ch_next == EOF)
                return ENDOFFILE;
            if (ch_next == '\n')
                mibLine++;
            return get_token(fp, token, maxtlen);
        }
        ungetc(ch_next, fp);
    default:
        /*
         * Accumulate characters until end of token is found.  Then attempt to
         * match this token as a reserved word.  If a match is found, return the
         * type.  Else it is a label.
         */
        if (!is_labelchar(ch))
            return LABEL;
        hash += tolower(ch);
      more:
        while (is_labelchar(ch_next = getc(fp))) {
            hash += tolower(ch_next);
            if (cp - token < maxtlen - 1)
                *cp++ = ch_next;
            else
                too_long = 1;
        }
        ungetc(ch_next, fp);
        *cp = '\0';

        if (too_long)
        for (tp = buckets[BUCKET(hash)]; tp; tp = tp->next) {
            if ((tp->hash == hash) && (!label_compare(tp->name, token)))
                break;
        }
        if (tp) {
            if (tp->token != CONTINUE)
                return (tp->token);
            while (isspace((ch_next = getc(fp))))
                if (ch_next == '\n')
                    mibLine++;
            if (ch_next == EOF)
                return ENDOFFILE;
            if (isalnum(ch_next)) {
                *cp++ = ch_next;
                hash += tolower(ch_next);
                goto more;
            }
        }
        if (token[0] == '-' || isdigit(token[0])) {
            for (cp = token + 1; *cp; cp++)
                if (!isdigit(*cp))
                    return LABEL;
            return NUMBER;
        }
        return LABEL;
    }
}


void
NetSnmpAgent::scan_objlist(struct NetSnmpNode* root, struct module* mp, struct objgroup* list, const char* error)
{
    int             oLine = mibLine;

    while (list) {
        struct objgroup* gp = list;
        struct NetSnmpNode*    np;
        list = list->next;
        np = (struct NetSnmpNode*) root;
        while (np)
            if (label_compare(np->label, gp->name))
                np = np->next;
            else
                break;
        if (!np) {
        int i;
        struct module_import* mip;
        /* if not local, check if it was IMPORTed */
        for (i = 0, mip = mp->imports; i < mp->no_imports; i++, mip++)
        if (strcmp(mip->label, gp->name) == 0)
            break;
        if (i == mp->no_imports) {
        mibLine = gp->line;
        }
        }
        free(gp->name);
        free(gp);
    }
    mibLine = oLine;
}
static int
name_hash(const char* name)
{
    int             hash = 0;
    const char*     cp;

    if (!name)
        return 0;
    for (cp = name; *cp; cp++)
        hash += tolower(*cp);
    return (hash);
}

 void
     NetSnmpAgent::do_linkup(struct module* mp, struct NetSnmpNode* np)
{
    struct module_import* mip;
    struct NetSnmpNode*    onp, *oldp, *newp;
    struct tree*    tp;
    int             i, more;
    /*
     * All modules implicitly import
     *   the roots of the tree
     */
    if (mp->no_imports == 0) {
        mp->no_imports = NUMBER_OF_ROOT_NODES;
        mp->imports = root_imports;
    }

    /*
     * Build the tree
     */
    init_node_hash(np);
    for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
        if (get_tc_index(mip->label, mip->modid) != -1)
            continue;
        tp = find_tree_node(mip->label, mip->modid);
        if (!tp) {
            continue;
        }
        do_subtree(tp, &np);
    }

    /*
     * If any nodes left over,
     *   check that they're not the result of a "fully qualified"
     *   name, and then add them to the list of orphans
     */

    if (!np)
        return;
    for (tp = tree_head; tp; tp = tp->next_peer)
        do_subtree(tp, &np);
    if (!np)
        return;

    /*
     * quietly move all internal references to the orphan list
     */
    oldp = orphan_nodes;
    do {
        for (i = 0; i < NHASHSIZE; i++)
            for (onp = nbuckets[i]; onp; onp = onp->next) {
                struct NetSnmpNode*    op = NULL;
                int             hash = NBUCKET(name_hash(onp->label));
                np = nbuckets[hash];
                while (np) {
                    if (label_compare(onp->label, np->parent)) {
                        op = np;
                        np = np->next;
                    } else {
                        if (op)
                            op->next = np->next;
                        else
                            nbuckets[hash] = np->next;
                        np->next = orphan_nodes;
                        orphan_nodes = np;
                        op = NULL;
                        np = nbuckets[hash];
                    }
                }
            }
        newp = orphan_nodes;
        more = 0;
        for (onp = orphan_nodes; onp != oldp; onp = onp->next) {
            struct NetSnmpNode*    op = NULL;
            int             hash = NBUCKET(name_hash(onp->label));
            np = nbuckets[hash];
            while (np) {
                if (label_compare(onp->label, np->parent)) {
                    op = np;
                    np = np->next;
                } else {
                    if (op)
                        op->next = np->next;
                    else
                        nbuckets[hash] = np->next;
                    np->next = orphan_nodes;
                    orphan_nodes = np;
                    op = NULL;
                    np = nbuckets[hash];
                    more = 1;
                }
            }
        }
        oldp = newp;
    } while (more);

    /*
     * complain about left over nodes
     */
    for (np = orphan_nodes; np && np->next; np = np->next);     /* find the end of the orphan list */
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else
                onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
        }
    return;
}


/*
 * Parses a mib file and returns a linked list of nodes found in the file.
 * Returns NULL on error.
 */
struct NetSnmpNode*
NetSnmpAgent::parse(FILE*  fp, struct NetSnmpNode* root)
{
    char            token[MAXTOKEN];
    char            name[MAXTOKEN];
    int             type = LABEL;
    int             lasttype = LABEL;

#define BETWEEN_MIBS          1
#define IN_MIB                2
    int             state = BETWEEN_MIBS;
    struct NetSnmpNode*    np, *nnp;
    struct objgroup* oldgroups = NULL, *oldobjects = NULL, *oldnotifs =
        NULL;

    if (last_err_module)
        free(last_err_module);
    last_err_module = NULL;

    np = root;
    if (np != NULL) {
        /*
         * now find end of chain
         */
        while (np->next)
            np = np->next;
    }

    while (type != ENDOFFILE) {
        if (lasttype == CONTINUE)
            lasttype = type;
        else
            type = lasttype = get_token(fp, token, MAXTOKEN);

        switch (type) {
        case END:
            if (state != IN_MIB) {
               /* print_error("Error, END before start of MIB", NULL, type);*/
                return NULL;
            } else {
                struct module*  mp;
                for (mp = module_head; mp; mp = mp->next)
                    if (mp->modid == current_module)
                        break;
                scan_objlist(root, mp, objgroups, "Undefined OBJECT-GROUP");
                scan_objlist(root, mp, objects, "Undefined OBJECT");
                scan_objlist(root, mp, notifs, "Undefined NOTIFICATION");
                objgroups = oldgroups;
                objects = oldobjects;
                notifs = oldnotifs;
                do_linkup(mp, root);
                np = root = NULL;
            }
            state = BETWEEN_MIBS;
            continue;
        case IMPORTS:
            continue;
        case EXPORTS:
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            continue;
        case LABEL:
        case INTEGER:
        case INTEGER32:
        case UINTEGER32:
        case UNSIGNED32:
        case COUNTER:
        case COUNTER64:
        case GAUGE:
        case IPADDR:
        case NETADDR:
        case NSAPADDRESS:
        case OBJSYNTAX:
        case APPSYNTAX:
        case SIMPLESYNTAX:
        case OBJNAME:
        case NOTIFNAME:
        case KW_OPAQUE:
        case TIMETICKS:
            break;
        case ENDOFFILE:
            continue;
        default:
            strcpy(name, token);
            type = get_token(fp, token, MAXTOKEN);
            nnp = NULL;
            if (type == MACRO) {
                free_node(nnp); /* IGNORE */
                nnp = NULL;
            }
            continue;           /* see if we can parse the rest of the file */
        }
        strcpy(name, token);
        type = get_token(fp, token, MAXTOKEN);
        nnp = NULL;

        /*
         * Handle obsolete method to assign an object identifier to a
         * module
         */
        if (lasttype == LABEL && type == LEFTBRACKET) {
            while (type != RIGHTBRACKET && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            if (type == ENDOFFILE) {
                /*print_error("Expected \"}\"", token, type);*/
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
        }

        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS) {
                return NULL;
            }
            state = IN_MIB;
            current_module = which_module(name);
            oldgroups = objgroups;
            objgroups = NULL;
            oldobjects = objects;
            objects = NULL;
            oldnotifs = notifs;
            notifs = NULL;
            if (current_module == -1) {
                new_module(name, File);
                current_module = which_module(name);
            }
            while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE)
                if (type == BEGIN)
                    break;
            break;
        case OBJTYPE:
            nnp = parse_objecttype(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case OBJGROUP:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case NOTIFGROUP:
            nnp = parse_objectgroup(fp, name, NOTIFICATIONS, &notifs);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case TRAPTYPE:
            nnp = parse_trapDefinition(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case NOTIFTYPE:
            nnp = parse_notificationDefinition(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case COMPLIANCE:
            nnp = parse_compliance(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case AGENTCAP:
            nnp = parse_capabilities(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case OBJIDENTITY:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case OBJECT:
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != EQUALS) {
                return NULL;
            }
            nnp = parse_objectid(fp, name);
            if (nnp == NULL) {
                return NULL;
            }
            break;
        case EQUALS:
            nnp = parse_asntype(fp, name, &type, token);
            lasttype = CONTINUE;
            break;
        case ENDOFFILE:
            break;
        default:
            return NULL;
        }
        if (nnp) {
            if (np)
                np->next = nnp;
            else
                np = root = nnp;
            while (np->next)
                np = np->next;
            if (np->type == TYPE_OTHER)
                np->type = type;
        }
    }
    return root;
}


static void
free_partial_tree(struct tree* tp, int keep_label)
{
    if (!tp)
        return;

    /*
     * remove the data from this tree node
     */
    free_enums(&tp->enums);
    free_ranges(&tp->ranges);
    free_indexes(&tp->indexes);
    free_varbinds(&tp->varbinds);
    if (!keep_label)
        SNMP_FREE(tp->label);
    SNMP_FREE(tp->hint);
    SNMP_FREE(tp->units);
    SNMP_FREE(tp->description);
    SNMP_FREE(tp->reference);
    SNMP_FREE(tp->augments);
    SNMP_FREE(tp->defaultValue);
}

/*
 * transfer data to tree from node
 *
 * move pointers for alloc'd data from np to tp.
 * this prevents them from being freed when np is released.
 * parent member is not moved.
 *
 * CAUTION: nodes may be repeats of existing tree nodes.
 * This can happen especially when resolving IMPORT clauses.
 *
 */
 void
     NetSnmpAgent::tree_from_node(struct tree* tp, struct NetSnmpNode* np)
{
    free_partial_tree(tp, FALSE);

    tp->label = np->label;
    np->label = NULL;
    tp->enums = np->enums;
    np->enums = NULL;
    tp->ranges = np->ranges;
    np->ranges = NULL;
    tp->indexes = np->indexes;
    np->indexes = NULL;
    tp->augments = np->augments;
    np->augments = NULL;
    tp->varbinds = np->varbinds;
    np->varbinds = NULL;
    tp->hint = np->hint;
    np->hint = NULL;
    tp->units = np->units;
    np->units = NULL;
    tp->description = np->description;
    np->description = NULL;
    tp->reference = np->reference;
    np->reference = NULL;
    tp->defaultValue = np->defaultValue;
    np->defaultValue = NULL;
    tp->subid = np->subid;
    tp->tc_index = np->tc_index;
    tp->type = translation_table[np->type];
    tp->access = np->access;
    tp->status = np->status;

    set_function(tp);
}


/*
 *  Read in the named module
 *      Returns the root of the whole tree
 *      (by analogy with 'read_mib')
 */
int
NetSnmpAgent::read_module_internal(const char* name)
{
    struct module*  mp;
    FILE*           fp;
    struct NetSnmpNode*    np;

    netsnmp_init_mib_internals();

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name)) {
            const char*     oldFile = File;
            int             oldLine = mibLine;
            int             oldModule = current_module;

            if (mp->no_imports != -1) {
                return MODULE_ALREADY_LOADED;
            }
            if ((fp = fopen(mp->file, "r")) == NULL) {
                return MODULE_LOAD_FAILED;
            }
            mp->no_imports = 0; /* Note that we've read the file */
            File = mp->file;
            mibLine = 1;
            current_module = mp->modid;
            /*
             * Parse the file
             */
            np = parse(fp, NULL);
            fclose(fp);
            File = oldFile;
            mibLine = oldLine;
            current_module = oldModule;
            return MODULE_LOADED_OK;
        }

    return MODULE_NOT_FOUND;
}
 int
     NetSnmpAgent::read_module_replacements(const char* name)
{
    struct module_compatability* mcp;

    for (mcp = module_map_head; mcp; mcp = mcp->next) {
        if (!label_compare(mcp->old_module, name)) {
            if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_MIB_WARNINGS)) {
        }
            (void) netsnmp_read_module(mcp->new_module);
            return 1;
        }
    }
    return 0;
}

void
NetSnmpAgent::print_module_not_found(const char* cp)
{
    if (last_err_module)
        free(last_err_module);
    last_err_module = strdup(cp);
}

int
NetSnmpAgent::which_module(const char* name)
{
    struct module*  mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name))
            return (mp->modid);

    return (-1);
}

struct tree*
NetSnmpAgent::find_tree_node(const char* name, int modid)
{
    struct tree*    tp, *headtp;
    int             count, *int_p;

    if (!name || !*name)
        return (NULL);

    headtp = tbuckets[NBUCKET(name_hash(name))];
    for (tp = headtp; tp; tp = tp->next) {
        if (tp->label && !label_compare(tp->label, name)) {

            if (modid == -1)    /* Any module */
                return (tp);

            for (int_p = tp->module_list, count = 0;
                 count < tp->number_modules; ++count, ++int_p)
                if (*int_p == modid)
                    return (tp);
        }
    }

    return (NULL);
}

/*
 * Find the tree node that best matches the pattern string.
 * Use the "reported" flag such that only one match
 * is attempted for every node.
 *
 * Warning! This function may recurse.
 *
 * Caller _must_ invoke clear_tree_flags before first call
 * to this function.  This function may be called multiple times
 * to ensure that the entire tree is traversed.
 */

struct tree*
NetSnmpAgent::find_best_tree_node(const char* pattrn, struct tree* tree_top,
                    u_int*  match)
{
    struct tree*    tp, *best_so_far = NULL, *retptr;
    u_int           old_match = MAX_BAD, new_match = MAX_BAD;

    if (!pattrn || !*pattrn)
        return (NULL);

    if (!tree_top)
        tree_top = tree_head;

    for (tp = tree_top; tp; tp = tp->next_peer) {
        if (!tp->reported && tp->label)
            new_match = compute_match(tp->label, pattrn);
        tp->reported = 1;

        if (new_match < old_match) {
            best_so_far = tp;
            old_match = new_match;
        }
        if (new_match == 0)
            break;              /* this is the best result we can get */
        if (tp->child_list) {
            retptr =
                find_best_tree_node(pattrn, tp->child_list, &new_match);
            if (new_match < old_match) {
                best_so_far = retptr;
                old_match = new_match;
            }
            if (new_match == 0)
                break;          /* this is the best result we can get */
        }
    }
    if (match)
        *match = old_match;
    return (best_so_far);
}


void
NetSnmpAgent::netsnmp_init_mib_internals(void)
{
    register struct tok* tp;
    register int    b, i;
    int             max_modc;

    if (tree_head)
        return;

    /*
     * Set up hash list of pre-defined tokens
     */
    memset(buckets, 0, sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        tp->hash = name_hash(tp->name);
        b = BUCKET(tp->hash);
        if (buckets[b])
            tp->next = buckets[b];      /* BUG ??? */
        buckets[b] = tp;
    }

    /*
     * Initialise other internal structures
     */

    max_modc = sizeof(module_map) / sizeof(module_map[0]) - 1;
    for (i = 0; i < max_modc; ++i)
        module_map[i].next = &(module_map[i + 1]);
    module_map[max_modc].next = NULL;
    module_map_head = module_map;

    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));
    memset(tclist, 0, MAXTC * sizeof(struct tc));
    build_translation_table();
    init_tree_roots();          /* Set up initial roots */
    /*
     * Relies on 'add_mibdir' having set up the modules
     */
}
 void
     NetSnmpAgent::init_node_hash(struct NetSnmpNode* nodes)
{
    struct NetSnmpNode*    np, *nextp;
    int             hash;

    memset(nbuckets, 0, sizeof(nbuckets));
    for (np = nodes; np;) {
        nextp = np->next;
        hash = NBUCKET(name_hash(np->parent));
        np->next = nbuckets[hash];
        nbuckets[hash] = np;
        np = nextp;
    }
}

 /*
 * return index into tclist of given TC descriptor
 * return -1 if not found
 */
int
NetSnmpAgent::get_tc_index(const char* descriptor, int modid)
{
    int             i;
    struct tc*      tcp;
    struct module*  mp;
    struct module_import* mip;

    /*
     * Check that the descriptor isn't imported
     *  by searching the import list
     */

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid)
            break;
    if (mp)
        for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
            if (!label_compare(mip->label, descriptor)) {
                /*
                 * Found it - so amend the module ID
                 */
                modid = mip->modid;
                break;
            }
        }


    for (i = 0, tcp = tclist; i < MAXTC; i++, tcp++) {
        if (tcp->type == 0)
            break;
        if (!label_compare(descriptor, tcp->descriptor) &&
            ((modid == tcp->modid) || (modid == -1))) {
            return i;
        }
    }
    return -1;
}


void
NetSnmpAgent::merge_anon_children(struct tree* tp1, struct tree* tp2)
                /*
                 * NB: tp1 is the 'anonymous' node
                 */
{
    struct tree*    child1, *child2, *previous;

    for (child1 = tp1->child_list; child1;) {

        for (child2 = tp2->child_list, previous = NULL;
             child2; previous = child2, child2 = child2->next_peer) {

            if (child1->subid == child2->subid) {
                /*
                 * Found 'matching' children,
                 *  so merge them
                 */
                if (!strncmp(child1->label, ANON, ANON_LEN)) {
                    merge_anon_children(child1, child2);

                    child1->child_list = NULL;
                    previous = child1;  /* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }

                else if (!strncmp(child2->label, ANON, ANON_LEN)) {
                    merge_anon_children(child2, child1);

                    if (previous)
                        previous->next_peer = child2->next_peer;
                    else
                        tp2->child_list = child2->next_peer;
                    free_tree(child2);

                    previous = child1;  /* Move 'child1' to 'tp2' */
                    child1 = child1->next_peer;
                    previous->next_peer = tp2->child_list;
                    tp2->child_list = previous;
                    for (previous = tp2->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = tp2;
                    goto next;
                } else if (!label_compare(child1->label, child2->label)) {
                    if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_WARNINGS)) {
            }
                    continue;
                } else {
                    /*
                     * Two copies of the same node.
                     * 'child2' adopts the children of 'child1'
                     */

                    if (child2->child_list) {
                        for (previous = child2->child_list; previous->next_peer; previous = previous->next_peer);       /* Find the end of the list */
                        previous->next_peer = child1->child_list;
                    } else
                        child2->child_list = child1->child_list;
                    for (previous = child1->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = child2;
                    child1->child_list = NULL;

                    previous = child1;  /* Finished with 'child1' */
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }
            }
        }
        /*
         * If no match, move 'child1' to 'tp2' child_list
         */
        if (child1) {
            previous = child1;
            child1 = child1->next_peer;
            previous->parent = tp2;
            previous->next_peer = tp2->child_list;
            tp2->child_list = previous;
        }
      next:;
    }
}




/*
 * Find all the children of root in the list of nodes.  Link them into the
 * tree and out of the nodes list.
 */
void
NetSnmpAgent::do_subtree(struct tree* root, struct NetSnmpNode** nodes)
{
    struct tree*    tp, *anon_tp = NULL;
    struct tree*    xroot = root;
    struct NetSnmpNode*    np, **headp;
    struct NetSnmpNode*    oldnp = NULL, *child_list = NULL, *childp = NULL;
    int             hash;
    int*            int_p;

    while (xroot->next_peer && xroot->next_peer->subid == root->subid) {
#if 0
        printf("xroot: %s.%s => %s\n", xroot->parent->label, xroot->label,
               xroot->next_peer->label);
#endif
        xroot = xroot->next_peer;
    }

    tp = root;
    headp = &nbuckets[NBUCKET(name_hash(tp->label))];
    /*
     * Search each of the nodes for one whose parent is root, and
     * move each into a separate list.
     */
    for (np = *headp; np; np = np->next) {
        if (!label_compare(tp->label, np->parent)) {
            /*
             * take this node out of the node list
             */
            if (oldnp == NULL) {
                *headp = np->next;      /* fix root of node list */
            } else {
                oldnp->next = np->next; /* link around this node */
            }
            if (child_list)
                childp->next = np;
            else
                child_list = np;
            childp = np;
        } else {
            oldnp = np;
        }

    }
    if (childp)
        childp->next = NULL;
    /*
     * Take each element in the child list and place it into the tree.
     */
    for (np = child_list; np; np = np->next) {
        struct tree*    otp = NULL;
        struct tree*    xxroot = xroot;
        anon_tp = NULL;
        tp = xroot->child_list;

        if (np->subid == (unsigned int)-1) {
            /*
             * name ::= { parent }
             */
            np->subid = xroot->subid;
            tp = xroot;
            xxroot = xroot->parent;
        }

        while (tp) {
            if (tp->subid == np->subid)
                break;
            else {
                otp = tp;
                tp = tp->next_peer;
            }
        }
        if (tp) {
            if (!label_compare(tp->label, np->label)) {
                /*
                 * Update list of modules
                 */
                int_p =
                    (int*) malloc((tp->number_modules + 1) * sizeof(int));
                if (int_p == NULL)
                    return;
                memcpy(int_p, tp->module_list,
                       tp->number_modules * sizeof(int));
                int_p[tp->number_modules] = np->modid;
                if (tp->number_modules > 1)
                    free((char*) tp->module_list);
                ++tp->number_modules;
                tp->module_list = int_p;

                if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_REPLACE)) {
                    /*
                     * Replace from node
                     */
                    tree_from_node(tp, np);
                }
                /*
                 * Handle children
                 */
                do_subtree(tp, nodes);
                continue;
            }
            if (!strncmp(np->label, ANON, ANON_LEN) ||
                !strncmp(tp->label, ANON, ANON_LEN)) {
                anon_tp = tp;   /* Need to merge these two trees later */
            }
        }

        tp = (struct tree*) calloc(1, sizeof(struct tree));
        if (tp == NULL)
            return;
        tp->parent = xxroot;
        tp->modid = np->modid;
        tp->number_modules = 1;
        tp->module_list = &(tp->modid);
        tree_from_node(tp, np);
        tp->next_peer = otp ? otp->next_peer : xxroot->child_list;
        if (otp)
            otp->next_peer = tp;
        else
            xxroot->child_list = tp;
        hash = NBUCKET(name_hash(tp->label));
        tp->next = tbuckets[hash];
        tbuckets[hash] = tp;
        do_subtree(tp, nodes);

        if (anon_tp) {
            if (!strncmp(tp->label, ANON, ANON_LEN)) {
                /*
                 * The new node is anonymous,
                 *  so merge it with the existing one.
                 */
                merge_anon_children(tp, anon_tp);

                /*
                 * unlink and destroy tp
                 */
                unlink_tree(tp);
                free_tree(tp);
            } else if (!strncmp(anon_tp->label, ANON, ANON_LEN)) {
                struct tree*    ntp;
                /*
                 * The old node was anonymous,
                 *  so merge it with the existing one,
                 *  and fill in the full information.
                 */
                merge_anon_children(anon_tp, tp);

                /*
                 * unlink anon_tp from the hash
                 */
                unlink_tbucket(anon_tp);

                /*
                 * get rid of old contents of anon_tp
                 */
                free_partial_tree(anon_tp, FALSE);

                /*
                 * put in the current information
                 */
                anon_tp->label = tp->label;
                anon_tp->child_list = tp->child_list;
                anon_tp->modid = tp->modid;
                anon_tp->tc_index = tp->tc_index;
                anon_tp->type = tp->type;
                anon_tp->enums = tp->enums;
                anon_tp->indexes = tp->indexes;
                anon_tp->augments = tp->augments;
                anon_tp->varbinds = tp->varbinds;
                anon_tp->ranges = tp->ranges;
                anon_tp->hint = tp->hint;
                anon_tp->units = tp->units;
                anon_tp->description = tp->description;
                anon_tp->reference = tp->reference;
                anon_tp->defaultValue = tp->defaultValue;
                anon_tp->parent = tp->parent;

                set_function(anon_tp);

                /*
                 * update parent pointer in moved children
                 */
                ntp = anon_tp->child_list;
                while (ntp) {
                    ntp->parent = anon_tp;
                    ntp = ntp->next_peer;
                }

                /*
                 * hash in anon_tp in its new place
                 */
                hash = NBUCKET(name_hash(anon_tp->label));
                anon_tp->next = tbuckets[hash];
                tbuckets[hash] = anon_tp;

                /*
                 * unlink and destroy tp
                 */
                unlink_tbucket(tp);
                unlink_tree(tp);
                free(tp);
            } else {
                /*
                 * Uh?  One of these two should have been anonymous!
                 */
                if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_MIB_WARNINGS)) {
        }
            }
            anon_tp = NULL;
        }
    }
    /*
     * free all nodes that were copied into tree
     */
    oldnp = NULL;
    for (np = child_list; np; np = np->next) {
        if (oldnp)
            free_node(oldnp);
        oldnp = np;
    }
    if (oldnp)
        free_node(oldnp);
}


void
NetSnmpAgent::new_module(const char* name, const char* file)
{
    struct module*  mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name)) {
            /*
             * Not the same file
             */
            if (label_compare(mp->file, file)) {
                /*
                 * Use the new one in preference
                 */
                free(mp->file);
                mp->file = strdup(file);
            }
            return;
        }

    /*
     * Add this module to the list
     */
    mp = (struct module*) calloc(1, sizeof(struct module));
    if (mp == NULL)
        return;
    mp->name = strdup(name);
    mp->file = strdup(file);
    mp->imports = NULL;
    mp->no_imports = -1;        /* Not yet loaded */
    mp->modid = max_module;
    ++max_module;

    mp->next = module_head;     /* Or add to the *end* of the list? */
    module_head = mp;
}

static struct enum_list*
copy_enums(struct enum_list* sp)
{
    struct enum_list* xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct enum_list*) calloc(1, sizeof(struct enum_list));
        if (!*spp)
            break;
        (*spp)->label = strdup(sp->label);
        (*spp)->value = sp->value;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}

static struct range_list*
copy_ranges(struct range_list* sp)
{
    struct range_list* xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct range_list*) calloc(1, sizeof(struct range_list));
        if (!*spp)
            break;
        (*spp)->low = sp->low;
        (*spp)->high = sp->high;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}


int
NetSnmpAgent::get_tc(const char* descriptor,
       int modid,
       int* tc_index,
       struct enum_list** ep, struct range_list** rp, char** hint)
{
    int             i;
    struct tc*      tcp;

    i = get_tc_index(descriptor, modid);
    if (tc_index)
        *tc_index = i;
    if (i != -1) {
        tcp = &tclist[i];
        if (ep) {
            free_enums(ep);
            *ep = copy_enums(tcp->enums);
        }
        if (rp) {
            free_ranges(rp);
            *rp = copy_ranges(tcp->ranges);
        }
        if (hint) {
            if (*hint)
                free(*hint);
            *hint = (tcp->hint ? strdup(tcp->hint) : NULL);
        }
        return tcp->type;
    }
    return LABEL;
}


/*
 * Parses an enumeration list of the form:
 *        { label(value) label(value) ... }
 * The initial { has already been parsed.
 * Returns NULL on error.
 */

struct enum_list*
NetSnmpAgent::parse_enumlist(FILE*  fp, struct enum_list** retp)
{
    register int    type;
    char            token[MAXTOKEN];
    struct enum_list* ep = NULL, **epp = &ep;

    free_enums(retp);

    while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
        if (type == RIGHTBRACKET)
            break;
        /* some enums use "deprecated" to indicate a no longer value label */
        /* (EG: IP-MIB's IpAddressStatusTC) */
        if (type == LABEL || type == DEPRECATED) {
            /*
             * this is an enumerated label
             */
            *epp =
                (struct enum_list*) calloc(1, sizeof(struct enum_list));
            if (*epp == NULL)
                return (NULL);
            /*
             * a reasonable approximation for the length
             */
            (*epp)->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTPAREN) {
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != NUMBER) {
                return NULL;
            }
            (*epp)->value = strtol(token, NULL, 10);
            type = get_token(fp, token, MAXTOKEN);
            if (type != RIGHTPAREN) {
                return NULL;
            }
            epp = &(*epp)->next;
        }
    }
    if (type == ENDOFFILE) {
        return NULL;
    }
    *retp = ep;
    return ep;
}

struct range_list*
NetSnmpAgent::parse_ranges(FILE*  fp, struct range_list** retp)
{
    int             low, high;
    char            nexttoken[MAXTOKEN];
    int             nexttype;
    struct range_list* rp = NULL, **rpp = &rp;
    int             size = 0, taken = 1;

    free_ranges(retp);

    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    if (nexttype == SIZE) {
        size = 1;
        taken = 0;
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
    }

    do {
        if (!taken)
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        else
            taken = 0;
        high = low = strtol(nexttoken, NULL, 10);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
        if (nexttype == RANGE) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            errno = 0;
            high = strtol(nexttoken, NULL, 10);

            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        *rpp = (struct range_list*) calloc(1, sizeof(struct range_list));
        if (*rpp == NULL)
            break;
        (*rpp)->low = low;
        (*rpp)->high = high;
        rpp = &(*rpp)->next;

    } while (nexttype == BAR);
    if (size) {
        nexttype = get_token(fp, nexttoken, nexttype);
    }
    *retp = rp;
    return rp;
}

/*
 * struct index_list*
 * getIndexes(FILE *fp):
 *   This routine parses a string like  { blah blah blah } and returns a
 *   list of the strings enclosed within it.
 *
 */
 struct index_list*
     NetSnmpAgent::getIndexes(FILE*  fp, struct index_list** retp)
{
    int             type;
    char            token[MAXTOKEN];
    char            nextIsImplied = 0;

    struct index_list* mylist = NULL;
    struct index_list** mypp = &mylist;

    free_indexes(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp =
                (struct index_list*) calloc(1, sizeof(struct index_list));
            if (*mypp) {
                (*mypp)->ilabel = strdup(token);
                (*mypp)->isimplied = nextIsImplied;
                mypp = &(*mypp)->next;
                nextIsImplied = 0;
            }
        } else if (type == IMPLIED) {
            nextIsImplied = 1;
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

/*
 * This routine parses a string like  { blah blah blah } and returns OBJID if
 * it is well formed, and NULL if not.
 */
int
NetSnmpAgent::tossObjectIdentifier(FILE*  fp)
{
    int             type;
    char            token[MAXTOKEN];
    int             bracketcount = 1;

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET)
        return 0;
    while ((type != RIGHTBRACKET || bracketcount > 0) && type != ENDOFFILE) {
        type = get_token(fp, token, MAXTOKEN);
        if (type == LEFTBRACKET)
            bracketcount++;
        else if (type == RIGHTBRACKET)
            bracketcount--;
    }

    if (type == RIGHTBRACKET)
        return OBJID;
    else
        return 0;
}

/*
 * Parses an OBJECT TYPE macro.
 * Returns 0 on error.
 */
struct NetSnmpNode*
NetSnmpAgent::parse_objecttype(FILE*  fp, char* name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            nexttoken[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    int             nexttype, tctype;
    register struct NetSnmpNode* np;

    type = get_token(fp, token, MAXTOKEN);
    if (type != SYNTAX) {
       /* print_error("Bad format for OBJECT-TYPE", token, type);*/
        return NULL;
    }
    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == OBJECT) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != IDENTIFIER) {
            free_node(np);
            return NULL;
        }
        type = OBJID;
    }
    if (type == LABEL) {
        int             tmp_index;
        tctype = get_tc(token, current_module, &tmp_index,
                        &np->enums, &np->ranges, &np->hint);
        if (tctype == LABEL &&
            netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_MIB_WARNINGS) > 1) {
        }
        type = tctype;
        np->tc_index = tmp_index;       /* store TC for later reference */
    }
    np->type = type;
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case SEQUENCE:
        if (nexttype == OF) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);

        }
        break;
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            /*
             * if there is a range list, parse it
             */
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        /*
         * parse any SIZE specification
         */
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      /*) */
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }
            free_node(np);
            return NULL;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:
        free_node(np);
        return NULL;
    }
    if (nexttype == UNITS) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            free_node(np);
            return NULL;
        }
        np->units = strdup(quoted_string_buffer);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
    }
    if (nexttype != ACCESS) {
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != READONLY && type != READWRITE && type != WRITEONLY
        && type != NOACCESS && type != READCREATE && type != ACCNOTIFY) {
        free_node(np);
        return NULL;
    }
    np->access = type;
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != MANDATORY && type != CURRENT && type != KW_OPTIONAL &&
        type != OBSOLETE && type != DEPRECATED) {
        free_node(np);
        return NULL;
    }
    np->status = type;
    /*
     * Optional parts of the OBJECT-TYPE macro
     */
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;

        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case INDEX:
            if (np->augments) {
                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {
                free_node(np);
                return NULL;
            }
            break;
        case AUGMENTS:
            if (np->indexes) {
                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {
                free_node(np);
                return NULL;
            }
            np->augments = strdup(np->indexes->ilabel);
            free_indexes(&np->indexes);
            break;
        case DEFVAL:
            /*
             * Mark's defVal section
             */
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != LEFTBRACKET) {
                free_node(np);
                return NULL;
            }

            {
                int             level = 1;
                char            defbuf[512];

                defbuf[0] = 0;
                while (1) {
                    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
                    if ((type == RIGHTBRACKET && --level == 0)
                        || type == ENDOFFILE)
                        break;
                    else if (type == LEFTBRACKET)
                        level++;
                    if (type == QUOTESTRING) {
                        if (strlen(defbuf)+2 < sizeof(defbuf)) {
                            defbuf[ strlen(defbuf)+2 ] = 0;
                            defbuf[ strlen(defbuf)+1 ] = '"';
                            defbuf[ strlen(defbuf)   ] = '\\';
                        }
                        defbuf[ sizeof(defbuf)-1 ] = 0;
                    }
                    strncat(defbuf, quoted_string_buffer,
                            sizeof(defbuf)-strlen(defbuf));
                    defbuf[ sizeof(defbuf)-1 ] = 0;
                    if (type == QUOTESTRING) {
                        if (strlen(defbuf)+2 < sizeof(defbuf)) {
                            defbuf[ strlen(defbuf)+2 ] = 0;
                            defbuf[ strlen(defbuf)+1 ] = '"';
                            defbuf[ strlen(defbuf)   ] = '\\';
                        }
                        defbuf[ sizeof(defbuf)-1 ] = 0;
                    }
                    if (strlen(defbuf)+1 < sizeof(defbuf)) {
                        defbuf[ strlen(defbuf)+1 ] = 0;
                        defbuf[ strlen(defbuf)   ] = ' ';
                    }
                }

                if (type != RIGHTBRACKET) {
                    free_node(np);
                    return NULL;
                }

                defbuf[strlen(defbuf) - 1] = 0;
                np->defaultValue = strdup(defbuf);
            }

            break;

        case NUM_ENTRIES:
            if (tossObjectIdentifier(fp) != OBJID) {
                free_node(np);
                return NULL;
            }
            break;

        default:
            free_node(np);
            return NULL;

        }
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS) {
        free_node(np);
        return NULL;
    }
    return merge_parse_objectid(np, fp, name);
}

/*
 * Parses an OBJECT GROUP macro.
 * Returns 0 on error.
 *
 * Also parses object-identity, since they are similar (ignore STATUS).
 *   - WJH 10/96
 */
struct NetSnmpNode*
NetSnmpAgent::parse_objectgroup(FILE*  fp, char* name, int what, struct objgroup** ol)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct NetSnmpNode*    np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == what) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {
            goto skip;
        }
        do {
            struct objgroup* o;
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                goto skip;
            }
            o = (struct objgroup*) malloc(sizeof(struct objgroup));
            if (!o) {
                goto skip;
            }
            o->line = mibLine;
            o->name = strdup(token);
            o->next = *ol;
            *ol = o;
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {
            goto skip;
        }
        type = get_token(fp, token, type);
    }
    if (type != STATUS) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        free_node(np);
        return NULL;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            free_node(np);
            return NULL;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, token, MAXTOKEN);

    return merge_parse_objectid(np, fp, name);
}


struct varbind_list*
    NetSnmpAgent::getVarbinds(FILE*  fp, struct varbind_list** retp)
{
    int             type;
    char            token[MAXTOKEN];

    struct varbind_list* mylist = NULL;
    struct varbind_list** mypp = &mylist;

    free_varbinds(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp =
                (struct varbind_list*) calloc(1,
                                               sizeof(struct
                                                      varbind_list));
            if (*mypp) {
                (*mypp)->vblabel = strdup(token);
                mypp = &(*mypp)->next;
            }
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

/*
 * Parses a TRAP-TYPE macro.
 * Returns 0 on error.
 */
struct NetSnmpNode*
NetSnmpAgent::parse_trapDefinition(FILE*  fp, char* name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    register struct NetSnmpNode* np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
               /* print_error("Bad DESCRIPTION", quoted_string_buffer, type);*/
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            /* I'm not sure REFERENCEs are legal in smiv1 traps??? */
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case ENTERPRISE:
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTBRACKET) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    free_node(np);
                    return NULL;
                }
                np->parent = strdup(token);
                /*
                 * Get right bracket
                 */
                type = get_token(fp, token, MAXTOKEN);
            } else if (type == LABEL) {
                np->parent = strdup(token);
            } else {
                free_node(np);
                return NULL;
            }
            break;
        case VARIABLES:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {
                free_node(np);
                return NULL;
            }
            break;
        default:
            /*
             * NOTHING
             */
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    type = get_token(fp, token, MAXTOKEN);

    np->label = strdup(name);

    if (type != NUMBER) {
        free_node(np);
        return NULL;
    }
    np->subid = strtoul(token, NULL, 10);
    np->next = alloc_node(current_module);
    if (np->next == NULL) {
        free_node(np);
        return (NULL);
    }
    np->next->parent = np->parent;
    np->parent = (char*) malloc(strlen(np->parent) + 2);
    if (np->parent == NULL) {
        free_node(np->next);
        free_node(np);
        return (NULL);
    }
    strcpy(np->parent, np->next->parent);
    strcat(np->parent, "#");
    np->next->label = strdup(np->parent);
    return np;
}
/*
 * Parses a NOTIFICATION-TYPE macro.
 * Returns 0 on error.
 */
struct NetSnmpNode*
NetSnmpAgent::parse_notificationDefinition(FILE*  fp, char* name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    register struct NetSnmpNode* np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case OBJECTS:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {
                free_node(np);
                return NULL;
            }
            break;
        default:
            /*
             * NOTHING
             */
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    return merge_parse_objectid(np, fp, name);
}
struct NetSnmpNode*
NetSnmpAgent::parse_compliance(FILE*  fp, char* name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct NetSnmpNode*    np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS))
        np->description = strdup(quoted_string_buffer);
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {
            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != MODULE) {
        goto skip;
    }
    while (type == MODULE) {
        int             modid = -1;
        char            modname[MAXTOKEN];
        type = get_token(fp, token, MAXTOKEN);
        if (type == LABEL
            && strcmp(token, module_name(current_module, modname))) {
            modid = read_module_internal(token);
            if (modid != MODULE_LOADED_OK
                && modid != MODULE_ALREADY_LOADED) {
                goto skip;
            }
            modid = which_module(token);
            type = get_token(fp, token, MAXTOKEN);
        }
        if (type == MANDATORYGROUPS) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTBRACKET) {
                goto skip;
            }
            do {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    goto skip;
                }
                if (!compliance_lookup(token, modid))
                type = get_token(fp, token, MAXTOKEN);
            } while (type == COMMA);
            if (type != RIGHTBRACKET) {
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
        while (type == GROUP || type == OBJECT) {
            if (type == GROUP) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    goto skip;
                }
                if (!compliance_lookup(token, modid))
                type = get_token(fp, token, MAXTOKEN);
            } else {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
                if (type == SYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == WRSYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == MINACCESS) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != NOACCESS && type != ACCNOTIFY
                        && type != READONLY && type != WRITEONLY
                        && type != READCREATE && type != READWRITE) {
                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                }
            }
            if (type != DESCRIPTION) {
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != QUOTESTRING) {
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

    return merge_parse_objectid(np, fp, name);
}


/*
 * Parses a capabilities macro
 * Returns 0 on error.
 */
struct NetSnmpNode*
    NetSnmpAgent::parse_capabilities(FILE*  fp, char* name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct NetSnmpNode*    np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != PRODREL) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != OBSOLETE) {
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
    if (type != QUOTESTRING) {
        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                   NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {
            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, type);
    }
    while (type == SUPPORTS) {
        int             modid;
        struct tree*    tp;

        type = get_token(fp, token, MAXTOKEN);
        if (type != LABEL) {
            goto skip;
        }
        modid = read_module_internal(token);
        if (modid != MODULE_LOADED_OK && modid != MODULE_ALREADY_LOADED) {
            goto skip;
        }
        modid = which_module(token);
        type = get_token(fp, token, MAXTOKEN);
        if (type != INCLUDES) {
            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {
            goto skip;
        }
        do {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                goto skip;
            }
            tp = find_tree_node(token, modid);
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {
            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        while (type == VARIATION) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                goto skip;
            }
            tp = find_tree_node(token, modid);
            type = get_token(fp, token, MAXTOKEN);
            if (type == SYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == WRSYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == ACCESS) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != ACCNOTIFY && type != READONLY
                    && type != READWRITE && type != READCREATE
                    && type != WRITEONLY && type != NOTIMPL) {
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == CREATEREQ) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {
                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != LABEL) {
                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                } while (type == COMMA);
                if (type != RIGHTBRACKET) {
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == DEFVAL) {
                int             level = 1;
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {
                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type == LEFTBRACKET)
                        level++;
                    else if (type == RIGHTBRACKET)
                        level--;
                } while (type != RIGHTBRACKET && type != ENDOFFILE
                         && level != 0);
                if (type != RIGHTBRACKET) {
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type != DESCRIPTION) {
                goto skip;
            }
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != QUOTESTRING) {
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    }
    return merge_parse_objectid(np, fp, name);
}
/*
 * Parse a sequence of object subidentifiers for the given name.
 * The "label OBJECT IDENTIFIER ::=" portion has already been parsed.
 *
 * The majority of cases take this form :
 * label OBJECT IDENTIFIER ::= { parent 2 }
 * where a parent label and a child subidentifier number are specified.
 *
 * Variations on the theme include cases where a number appears with
 * the parent, or intermediate subidentifiers are specified by label,
 * by number, or both.
 *
 * Here are some representative samples :
 * internet        OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }
 * mgmt            OBJECT IDENTIFIER ::= { internet 2 }
 * rptrInfoHealth  OBJECT IDENTIFIER ::= { snmpDot3RptrMgt 0 4 }
 *
 * Here is a very rare form :
 * iso             OBJECT IDENTIFIER ::= { 1 }
 *
 * Returns NULL on error.  When this happens, memory may be leaked.
 */
struct NetSnmpNode*
    NetSnmpAgent::parse_objectid(FILE*  fp, char* name)
{
    register int    count;
    register struct subid_s* op, *nop;
    int             length;
    struct subid_s  loid[32];
    struct NetSnmpNode*    np, *root = NULL, *oldnp = NULL;
    struct tree*    tp;

    if ((length = getoid(fp, loid, 32)) == 0) {
        return NULL;
    }

    /*
     * Handle numeric-only object identifiers,
     *  by labelling the first sub-identifier
     */
    op = loid;
    if (!op->label) {
        if (length == 1) {
            /*print_error("Attempt to define a root oid", name, OBJECT);*/
            return NULL;
        }
        for (tp = tree_head; tp; tp = tp->next_peer)
            if ((int) tp->subid == op->subid) {
                op->label = strdup(tp->label);
                break;
            }
    }

    /*
     * Handle  "label OBJECT-IDENTIFIER ::= { subid }"
     */
    if (length == 1) {
        op = loid;
        np = alloc_node(op->modid);
        if (np == NULL)
            return (NULL);
        np->subid = op->subid;
        np->label = strdup(name);
        np->parent = op->label;
        return np;
    }

    /*
     * For each parent-child subid pair in the subid array,
     * create a node and link it into the node list.
     */
    for (count = 0, op = loid, nop = loid + 1; count < (length - 1);
         count++, op++, nop++) {
        /*
         * every node must have parent's name and child's name or number
         */
        /*
         * XX the next statement is always true -- does it matter ??
         */
        if (op->label && (nop->label || (nop->subid != -1))) {
            np = alloc_node(nop->modid);
            if (np == NULL)
                return (NULL);
            if (root == NULL)
                root = np;

            np->parent = strdup(op->label);
            if (count == (length - 2)) {
                /*
                 * The name for this node is the label for this entry
                 */
                np->label = strdup(name);
            } else {
                if (!nop->label) {
                    nop->label = (char*) malloc(20 + ANON_LEN);
                    if (nop->label == NULL)
                        return (NULL);
                    sprintf(nop->label, "%s%d", ANON, anonymous++);
                }
                np->label = strdup(nop->label);
            }
            if (nop->subid != -1)
                np->subid = nop->subid;
            else
                /*print_error("Warning: This entry is pretty silly",
                            np->label, CONTINUE);*/

            /*
             * set up next entry
             */
            if (oldnp)
                oldnp->next = np;
            oldnp = np;
        }                       /* end if (op->label... */
    }

    /*
     * free the loid array
     */
    for (count = 0, op = loid; count < length; count++, op++) {
        if (op->label)
            free(op->label);
    }

    return root;
}

/*
 * Parses an asn type.  Structures are ignored by this parser.
 * Returns NULL on error.
 */
struct NetSnmpNode*
NetSnmpAgent::parse_asntype(FILE*  fp, char* name, int* ntype, char* ntoken)
{
    int             type, i;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    char*           hint = NULL;
    char*           descr = NULL;
    struct tc*      tcp;
    int             level;

    type = get_token(fp, token, MAXTOKEN);
    if (type == SEQUENCE || type == CHOICE) {
        level = 0;
        while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
            if (type == LEFTBRACKET) {
                level++;
            } else if (type == RIGHTBRACKET && --level == 0) {
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                return NULL;
            }
        }
        return NULL;
    } else if (type == LEFTBRACKET) {
        struct NetSnmpNode*    np;
        int             ch_next = '{';
        ungetc(ch_next, fp);
        np = parse_objectid(fp, name);
        if (np != NULL) {
            *ntype = get_token(fp, ntoken, MAXTOKEN);
            return np;
        }
        return NULL;
    } else if (type == LEFTSQBRACK) {
        int             size = 0;
        do {
            type = get_token(fp, token, MAXTOKEN);
        } while (type != ENDOFFILE && type != RIGHTSQBRACK);
        if (type != RIGHTSQBRACK) {
            return NULL;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type == IMPLICIT)
            type = get_token(fp, token, MAXTOKEN);
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            switch (type) {
            case OCTETSTR:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != SIZE) {
                    return NULL;
                }
                size = 1;
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != LEFTPAREN) {
                    return NULL;
                }
                /*
                 * fall through
                 */
            case INTEGER:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                do {
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                    if (*ntype == RANGE) {
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                        if (*ntype != NUMBER)
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                    }
                } while (*ntype == BAR);
                if (*ntype != RIGHTPAREN) {
                    return NULL;
                }
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (size) {
                    if (*ntype != RIGHTPAREN) {
                        return NULL;
                    }
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                }
            }
        }
        return NULL;
    } else {
        if (type == CONVENTION) {
            while (type != SYNTAX && type != ENDOFFILE) {
                if (type == DISPLAYHINT) {
                    type = get_token(fp, token, MAXTOKEN);
                        hint = strdup(token);
                } else if (type == DESCRIPTION &&
                           netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                                  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
                        descr = strdup(quoted_string_buffer);
                } else
                    type =
                        get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type == OBJECT) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != IDENTIFIER) {
                    SNMP_FREE(hint);
                    return NULL;
                }
                type = OBJID;
            }
        } else if (type == OBJECT) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {
                return NULL;
            }
            type = OBJID;
        }

        if (type == LABEL) {
            type = get_tc(token, current_module, NULL, NULL, NULL, NULL);
        }

        /*
         * textual convention
         */
        for (i = 0; i < MAXTC; i++) {
            if (tclist[i].type == 0)
                break;
        }

        if (i == MAXTC) {
            SNMP_FREE(hint);
            return NULL;
        }
        if (!(type & SYNTAX_MASK)) {
            SNMP_FREE(hint);
            return NULL;
        }
        tcp = &tclist[i];
        tcp->modid = current_module;
        tcp->descriptor = strdup(name);
        tcp->hint = hint;
        tcp->description = descr;
        tcp->type = type;
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            tcp->ranges = parse_ranges(fp, &tcp->ranges);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        } else if (*ntype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            tcp->enums = parse_enumlist(fp, &tcp->enums);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        }
        return NULL;
    }
}

 void
     NetSnmpAgent::build_translation_table(void)
{
    int             count;

    for (count = 0; count < 256; count++) {
        switch (count) {
        case OBJID:
            translation_table[count] = TYPE_OBJID;
            break;
        case OCTETSTR:
            translation_table[count] = TYPE_OCTETSTR;
            break;
        case INTEGER:
            translation_table[count] = TYPE_INTEGER;
            break;
        case NETADDR:
            translation_table[count] = TYPE_NETADDR;
            break;
        case IPADDR:
            translation_table[count] = TYPE_IPADDR;
            break;
        case COUNTER:
            translation_table[count] = TYPE_COUNTER;
            break;
        case GAUGE:
            translation_table[count] = TYPE_GAUGE;
            break;
        case TIMETICKS:
            translation_table[count] = TYPE_TIMETICKS;
            break;
        case KW_OPAQUE:
            translation_table[count] = TYPE_OPAQUE;
            break;
        case NUL:
            translation_table[count] = TYPE_NULL;
            break;
        case COUNTER64:
            translation_table[count] = TYPE_COUNTER64;
            break;
        case BITSTRING:
            translation_table[count] = TYPE_BITSTRING;
            break;
        case NSAPADDRESS:
            translation_table[count] = TYPE_NSAPADDRESS;
            break;
        case INTEGER32:
            translation_table[count] = TYPE_INTEGER32;
            break;
        case UINTEGER32:
            translation_table[count] = TYPE_UINTEGER;
            break;
        case UNSIGNED32:
            translation_table[count] = TYPE_UNSIGNED32;
            break;
        case TRAPTYPE:
            translation_table[count] = TYPE_TRAPTYPE;
            break;
        case NOTIFTYPE:
            translation_table[count] = TYPE_NOTIFTYPE;
            break;
        case NOTIFGROUP:
            translation_table[count] = TYPE_NOTIFGROUP;
            break;
        case OBJGROUP:
            translation_table[count] = TYPE_OBJGROUP;
            break;
        case MODULEIDENTITY:
            translation_table[count] = TYPE_MODID;
            break;
        case OBJIDENTITY:
            translation_table[count] = TYPE_OBJIDENTITY;
            break;
        case AGENTCAP:
            translation_table[count] = TYPE_AGENTCAP;
            break;
        case COMPLIANCE:
            translation_table[count] = TYPE_MODCOMP;
            break;
        default:
            translation_table[count] = TYPE_OTHER;
            break;
        }
    }
}
void
NetSnmpAgent::init_tree_roots(void)
{
    struct tree*    tp, *lasttp;
    int             base_modid;
    int             hash;

    base_modid = which_module("SNMPv2-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1155-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1213-MIB");

    /*
     * build root node
     */
    tp = (struct tree*) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->label = strdup("joint-iso-ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 2;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[0].label = strdup(tp->label);
    root_imports[0].modid = base_modid;

    /*
     * build root node
     */
    tp = (struct tree*) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 0;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[1].label = strdup(tp->label);
    root_imports[1].modid = base_modid;

    /*
     * build root node
     */
    tp = (struct tree*) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("iso");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 1;
    tp->tc_index = -1;
    set_function(tp);           /* from mib.c */
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[2].label = strdup(tp->label);
    root_imports[2].modid = base_modid;

    tree_head = tp;
}


/*
 * module_name - copy module name to user buffer, return ptr to same.
 */
char*
NetSnmpAgent::module_name(int modid, char* cp)
{
    struct module*  mp;

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid) {
            strcpy(cp, mp->name);
            return (cp);
        }

    sprintf(cp, "#%d", modid);
    return (cp);
}


/*
 * translate integer tc_index to string identifier from tclist
 * *
 * * Returns pointer to string in table (should not be modified) or NULL
 */
char*
NetSnmpAgent::get_tc_descriptor(int tc_index)
{
    if (tc_index < 0 || tc_index >= MAXTC)
        return NULL;
    return (tclist[tc_index].descriptor);
}

char*
NetSnmpAgent::get_tc_description(int tc_index)
{
    if (tc_index < 0 || tc_index >= MAXTC)
        return NULL;
    return (tclist[tc_index].description);
}

/*
 * free a tree node. Note: the node must already have been unlinked
 * from the tree when calling this routine
 */
 void
     NetSnmpAgent::free_tree(struct tree* Tree)
{
    if (!Tree)
        return;

    unlink_tbucket(Tree);
    free_partial_tree(Tree, FALSE);
    if (Tree->number_modules > 1)
        free((char*) Tree->module_list);
    free((char*) Tree);
}


void
NetSnmpAgent::unlink_tbucket(struct tree* tp)
{
    int             hash = NBUCKET(name_hash(tp->label));
    struct tree*    otp = NULL, *ntp = tbuckets[hash];

    while (ntp && ntp != tp) {
        otp = ntp;
        ntp = ntp->next;
    }
    if (otp)
        otp->next = ntp->next;
    else
        tbuckets[hash] = tp->next;
}

void
NetSnmpAgent::unlink_tree(struct tree* tp)
{
    struct tree*    otp = NULL, *ntp = tp->parent;

    if (!ntp) {                 /* this tree has no parent */
    } else {
        ntp = ntp->child_list;

        while (ntp && ntp != tp) {
            otp = ntp;
            ntp = ntp->next_peer;
        }
        if (otp)
            otp->next_peer = ntp->next_peer;
        else
            tp->parent->child_list = tp->next_peer;
    }

    if (tree_head == tp)
        tree_head = tp->next_peer;
}


struct NetSnmpNode*
    NetSnmpAgent::alloc_node(int modid)
{
    struct NetSnmpNode*    np;
    np = (struct NetSnmpNode*) calloc(1, sizeof(struct NetSnmpNode));
    if (np) {
        np->tc_index = -1;
        np->modid = modid;
    np->filename = strdup(File);
    np->lineno = mibLine;
    }
    return np;
}

/*
 * Merge the parsed object identifier with the existing node.
 * If there is a problem with the identifier, release the existing node.
 */
struct NetSnmpNode*
    NetSnmpAgent::merge_parse_objectid(struct NetSnmpNode* np, FILE*  fp, char* name)
{
    struct NetSnmpNode*    nnp;
    nnp = parse_objectid(fp, name);
    if (nnp) {

        /*
         * apply last OID sub-identifier data to the information
         */
        /*
         * already collected for this node.
         */
        struct NetSnmpNode*    headp, *nextp;
        int             ncount = 0;
        nextp = headp = nnp;
        while (nnp->next) {
            nextp = nnp;
            ncount++;
            nnp = nnp->next;
        }

        np->label = nnp->label;
        np->subid = nnp->subid;
        np->modid = nnp->modid;
        np->parent = nnp->parent;
    if (nnp->filename != NULL) {
      free(nnp->filename);
    }
        free(nnp);

        if (ncount) {
            nextp->next = np;
            np = headp;
        }
    } else {
        free_node(np);
        np = NULL;
    }

    return np;
}

int
NetSnmpAgent::compliance_lookup(const char* name, int modid)
{
    if (modid == -1) {
        struct objgroup* op =
            (struct objgroup*) malloc(sizeof(struct objgroup));
        if (!op)
            return 0;
        op->next = objgroups;
        op->name = strdup(name);
        op->line = mibLine;
        objgroups = op;
        return 1;
    } else
        return find_tree_node(name, modid) != NULL;
}


/*
 * Parses a compliance macro
 * Returns 0 on error.
 */
int
NetSnmpAgent::eat_syntax(FILE*  fp, char* token, int maxtoken)
{
    int             type, nexttype;
    struct NetSnmpNode*    np = alloc_node(current_module);
    char            nexttoken[MAXTOKEN];

    if (!np)
    return 0;

    type = get_token(fp, token, maxtoken);
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            /*
             * if there is an enumeration list, parse it
             */
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            /*
             * if there is a range list, parse it
             */
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        /*
         * parse any SIZE specification
         */
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      /*) */
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }
            free_node(np);
            return nexttype;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:
        free_node(np);
        return nexttype;
    }
    free_node(np);
    return nexttype;
}


/*
 * Takes a list of the form:
 * { iso org(3) dod(6) 1 }
 * and creates several nodes, one for each parent-child pair.
 * Returns 0 on error.
 */
int
NetSnmpAgent::getoid(FILE*  fp, struct subid_s* id,   /* an array of subids */
       int length)
{                               /* the length of the array */
    register int    count;
    int             type;
    char            token[MAXTOKEN];

    if ((type = get_token(fp, token, MAXTOKEN)) != LEFTBRACKET) {
        return 0;
    }
    type = get_token(fp, token, MAXTOKEN);
    for (count = 0; count < length; count++, id++) {
        id->label = NULL;
        id->modid = current_module;
        id->subid = -1;
        if (type == RIGHTBRACKET)
            return count;
        if (type == LABEL) {
            /*
             * this entry has a label
             */
            id->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTPAREN) {
                type = get_token(fp, token, MAXTOKEN);
                if (type == NUMBER) {
                    id->subid = strtoul(token, NULL, 10);
                    if ((type =
                         get_token(fp, token, MAXTOKEN)) != RIGHTPAREN) {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                continue;
            }
        } else if (type == NUMBER) {
            /*
             * this entry  has just an integer sub-identifier
             */
            id->subid = strtoul(token, NULL, 10);
        } else {
            return 0;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    return 0;
}


/*
 * Returns the root of the whole tree
 *   (for backwards compatability)
 */
struct tree*
    NetSnmpAgent::read_mib(const char* filename)
{
    FILE*           fp;
    char            token[MAXTOKEN];

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return NULL;
    }
    mibLine = 1;
    File = filename;
    get_token(fp, token, MAXTOKEN);
    fclose(fp);
    new_module(token, filename);
    (void) netsnmp_read_module(token);

    return tree_head;
}

/* For Win32 platforms, the directory does not maintain a last modification
 * date that we can compare with the modification date of the .index file.
 * Therefore there is no way to know whether any .index file is valid.
 * This is the reason for the #if !(defined(WIN32) || defined(cygwin))
 * in the add_mibdir function
 */
int
NetSnmpAgent::add_mibdir(const char* dirname)
{
    FILE*           ip;
    DIR_netsnmp*            dir=NULL, *dir2=NULL;
    const char*     oldFile = File;
    struct dirent*  file=NULL;
    char            tmpstr[300];
    int             count = 0;
    int             fname_len = 0;
#if !(defined(WIN32) || defined(cygwin))
    char*           token;
    char space;
    char newline;
    struct stat     dir_stat, idx_stat;
    char            tmpstr1[300];
#endif

#if !(defined(WIN32) || defined(cygwin))
    token = netsnmp_mibindex_lookup(dirname);
    if (token && stat(token, &idx_stat) == 0 && stat(dirname, &dir_stat) == 0) {
        if (dir_stat.st_mtime < idx_stat.st_mtime) {
            if ((ip = fopen(token, "r")) != NULL) {
                char* temp = NULL;
                temp = fgets(tmpstr, sizeof(tmpstr), ip); /* Skip dir line */
                while (fscanf(ip,
                            "%127s%c%299s%c",
                            token,
                            &space,
                            tmpstr,
                            &newline) == 4) {

            /*
             * If an overflow of the token or tmpstr buffers has been
             * found log a message and break out of the while loop,
             * thus the rest of the file tokens will be ignored.
             */
            if (space != ' ' || newline != '\n') {
                break;
            }

            snprintf(tmpstr1, sizeof(tmpstr1), "%s/%s", dirname, tmpstr);
                    tmpstr1[ sizeof(tmpstr1)-1 ] = 0;
                    new_module(token, tmpstr1);
                    count++;
                }
                fclose(ip);
                return count;
            }
        }
    }
#endif

    if ((dir /*= opendir(dirname)*/)) {
        ip = netsnmp_mibindex_new(dirname);
        while ((file /*= readdir(dir)*/)) {
            /*
             * Only parse file names that don't begin with a '.'
             * Also skip files ending in '~', or starting/ending
             * with '#' which are typically editor backup files.
             */
            if (file->d_name != NULL) {
              fname_len = strlen(file->d_name);
              if (fname_len > 0 && file->d_name[0] != '.'
                                && file->d_name[0] != '#'
                                && file->d_name[fname_len-1] != '#'
                                && file->d_name[fname_len-1] != '~') {
                snprintf(tmpstr, sizeof(tmpstr), "%s/%s", dirname, file->d_name);
                tmpstr[ sizeof(tmpstr)-1 ] = 0;
                if ((dir2/* = opendir(tmpstr)*/)) {
                    /*
                     * file is a directory, don't read it
                     */
                    /*closedir(dir2);*/
                } else {
                    if (!add_mibfile(tmpstr, file->d_name, ip))
                        count++;
                }
              }
            }
        }
        File = oldFile;
        if (ip)
            fclose(ip);
        return (count);
    }
    return (-1);
}

int
NetSnmpAgent::add_mibfile(const char* tmpstr, const char* d_name, FILE* ip)
{
    FILE*           fp;
    char            token[MAXTOKEN], token2[MAXTOKEN];

    /*
     * which module is this
     */
    if ((fp = fopen(tmpstr, "r")) == NULL) {
        return 1;
    }
    mibLine = 1;
    File = tmpstr;
    get_token(fp, token, MAXTOKEN);
    /*
     * simple test for this being a MIB
     */
    if (get_token(fp, token2, MAXTOKEN) == DEFINITIONS) {
        new_module(token, tmpstr);
        if (ip)
            fprintf(ip, "%s %s\n", token, d_name);
        fclose(fp);
        return 0;
    } else {
        fclose(fp);
        return 1;
    }
}

struct tree*
    NetSnmpAgent::read_all_mibs(void)
{
    struct module*  mp;

    for (mp = module_head; mp; mp = mp->next)
        if (mp->no_imports == -1)
            netsnmp_read_module(mp->name);
    adopt_orphans();

    return tree_head;
}

void
NetSnmpAgent::adopt_orphans(void)
{
    struct NetSnmpNode*    np, *onp;
    struct tree*    tp;
    int             i, adopted = 1;

    if (!orphan_nodes)
        return;
    init_node_hash(orphan_nodes);
    orphan_nodes = NULL;

    while (adopted) {
        adopted = 0;
        for (i = 0; i < NHASHSIZE; i++)
            if (nbuckets[i]) {
                for (np = nbuckets[i]; np != NULL; np = np->next) {
                    tp = find_tree_node(np->parent, -1);
            if (tp) {
            do_subtree(tp, &np);
            adopted = 1;
                        /*
                         * if do_subtree adopted the entire bucket, stop
                         */
                        if (NULL == nbuckets[i])
                            break;

                        /*
                         * do_subtree may modify nbuckets, and if np
                         * was adopted, np->next probably isn't an orphan
                         * anymore. if np is still in the bucket (do_subtree
                         * didn't adopt it) keep on plugging. otherwise
                         * start over, at the top of the bucket.
                         */
                        for (onp = nbuckets[i]; onp; onp = onp->next)
                            if (onp == np)
                                break;
                        if (NULL == onp) { /* not in the list */
                            np = nbuckets[i]; /* start over */
                        }
            }
        }
            }
    }

    /*
     * Report on outstanding orphans
     *    and link them back into the orphan list
     */
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else
                onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
            while (onp) {
                np = onp;
                onp = onp->next;
            }
        }
}

void
NetSnmpAgent::unload_module_by_ID(int modID, struct tree* tree_top)
{
    struct tree*    tp, *next;
    int             i;

    for (tp = tree_top; tp; tp = next) {
        /*
         * Essentially, this is equivalent to the code fragment:
         *      if (tp->modID == modID)
         *        tp->number_modules--;
         * but handles one tree node being part of several modules,
         * and possible multiple copies of the same module ID.
         */
        int             nmod = tp->number_modules;
        if (nmod > 0) {         /* in some module */
            /*
             * Remove all copies of this module ID
             */
            int             cnt = 0, *pi1, *pi2 = tp->module_list;
            for (i = 0, pi1 = pi2; i < nmod; i++, pi2++) {
                if (*pi2 == modID)
                    continue;
                cnt++;
                *pi1++ = *pi2;
            }
            if (nmod != cnt) {  /* in this module */
                /*
                 * if ((nmod - cnt) > 1)
                 * printf("Dup modid %d,  %d times, '%s'\n", tp->modid, (nmod-cnt), tp->label); fflush(stdout); ?* XXDEBUG
                 */
                tp->number_modules = cnt;
                switch (cnt) {
                case 0:
                    tp->module_list[0] = -1;    /* Mark unused, and FALL THROUGH */

                case 1:        /* save the remaining module */
                    if (&(tp->modid) != tp->module_list) {
                        tp->modid = tp->module_list[0];
                        free(tp->module_list);
                        tp->module_list = &(tp->modid);
                    }
                    break;

                default:
                    break;
                }
            }                   /* if tree node is in this module */
        }
        /*
         * if tree node is in some module
         */
        next = tp->next_peer;


        /*
         *  OK - that's dealt with *this* node.
         *    Now let's look at the children.
         *    (Isn't recursion wonderful!)
         */
        if (tp->child_list)
            unload_module_by_ID(modID, tp->child_list);


        if (tp->number_modules == 0) {
            /*
             * This node isn't needed any more (except perhaps
             * for the sake of the children)
             */
            if (tp->child_list == NULL) {
                unlink_tree(tp);
                free_tree(tp);
            } else {
                free_partial_tree(tp, TRUE);
            }
        }
    }
}

/*
 * Clear module map, tree nodes, textual convention table.
 */
void
NetSnmpAgent::unload_all_mibs(void)
{
    struct module*  mp;
    struct module_compatability* mcp;
    struct tc*      ptc;
    int             i;

    for (mcp = module_map_head; mcp; mcp = module_map_head) {
        if (mcp == module_map)
            break;
        module_map_head = mcp->next;
        if (mcp->tag) free((char*) mcp->tag);
        free((char*) mcp->old_module);
        free((char*) mcp->new_module);
        free(mcp);
    }

    for (mp = module_head; mp; mp = module_head) {
        struct module_import* mi = mp->imports;
        if (mi) {
            for (i = 0; i < mp->no_imports; ++i) {
                SNMP_FREE((mi + i)->label);
            }
            mp->no_imports = 0;
            if (mi == root_imports)
                memset(mi, 0, sizeof(*mi));
            else
                free(mi);
        }

        unload_module_by_ID(mp->modid, tree_head);
        module_head = mp->next;
        free(mp->name);
        free(mp->file);
        free(mp);
    }
    unload_module_by_ID(-1, tree_head);
    /*
     * tree nodes are cleared
     */

    for (i = 0, ptc = tclist; i < MAXTC; i++, ptc++) {
        if (ptc->type == 0)
            continue;
        free_enums(&ptc->enums);
        free_ranges(&ptc->ranges);
        free(ptc->descriptor);
        if (ptc->hint)
            free(ptc->hint);
    }
    memset(tclist, 0, MAXTC * sizeof(struct tc));

    memset(buckets, 0, sizeof(buckets));
    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));

    for (i = 0;
        (unsigned int)i < sizeof(root_imports) / sizeof(root_imports[0]);
        i++) {
        SNMP_FREE(root_imports[i].label);
    }

    max_module = 0;
    current_module = 0;
    module_map_head = NULL;
    SNMP_FREE(last_err_module);
}
