#include "netSnmpAgent.h"
#include "read_config_netsnmp.h"
#include "tools_netsnmp.h"

static char**
create_word_array_helper(const char* cptr, size_t idx, char* tmp, size_t tmplen)
{
    char* item;
    char** res;
    cptr = copy_nword((char*)cptr, tmp, tmplen);
    item = strdup(tmp);
    if (cptr)
        res = create_word_array_helper(cptr, idx + 1, tmp, tmplen);
    else {
        res = (char**)malloc(sizeof(char*) * (idx + 2));
        res[idx + 1] = NULL;
    }
    res[idx] = item;
    return res;
}

static char**
create_word_array(const char* cptr)
{
    size_t tmplen = strlen(cptr);
    char* tmp = (char*)malloc(tmplen + 1);
    char** res = create_word_array_helper(cptr, 0, tmp, tmplen);
    free(tmp);
    return res;
}

static void
destroy_word_array(char** arr)
{
    if (arr) {
        char** run = arr;
        while (*run) {
            free(*run);
            ++run;
        }
        free(arr);
    }
}

struct netsnmp_lookup_domain {
    char* application;
    char** userDomain;
    char** domain;
    struct netsnmp_lookup_domain* next;
};

int
NetSnmpAgent::netsnmp_register_default_domain(const char* application, const char* domain)
{
    struct netsnmp_lookup_domain* run = domains, *prev = NULL;
    int res = 0;

    while (run != NULL && strcmp(run->application, application) < 0) {
    prev = run;
    run = run->next;
    }
    if (run && strcmp(run->application, application) == 0) {
      if (run->domain != NULL) {
          destroy_word_array(run->domain);
      run->domain = NULL;
      res = 1;
      }
    } else {
    run = SNMP_MALLOC_STRUCT(netsnmp_lookup_domain);
    run->application = strdup(application);
    run->userDomain = NULL;
    if (prev) {
        run->next = prev->next;
        prev->next = run;
    } else {
        run->next = domains;
        domains = run;
    }
    }
    if (domain) {
        run->domain = create_word_array(domain);
    } else if (run->userDomain == NULL) {
    if (prev)
        prev->next = run->next;
    else
        domains = run->next;
    free(run->application);
    free(run);
    }
    return res;
}

void
NetSnmpAgent::netsnmp_clear_default_domain(void)
{
    while (domains) {
    struct netsnmp_lookup_domain* tmp = domains;
    domains = domains->next;
    free(tmp->application);
        destroy_word_array(tmp->userDomain);
        destroy_word_array(tmp->domain);
    free(tmp);
    }
}

void
NetSnmpAgent::netsnmp_register_user_domain(const char* token, char* cptr)
{
    struct netsnmp_lookup_domain* run = domains, *prev = NULL;
    size_t len = strlen(cptr) + 1;
    char* application = (char*)malloc(len);
    char** domain;

    {
        char* cp = copy_nword(cptr, application, len);
        domain = create_word_array(cp);
    }

    while (run != NULL && strcmp(run->application, application) < 0) {
    prev = run;
    run = run->next;
    }
    if (run && strcmp(run->application, application) == 0) {
    if (run->userDomain != NULL) {
            destroy_word_array(domain);
            free(application);
        return;
    }
    } else {
    run = SNMP_MALLOC_STRUCT(netsnmp_lookup_domain);
    run->application = strdup(application);
    run->domain = NULL;
    if (prev) {
        run->next = prev->next;
        prev->next = run;
    } else {
        run->next = domains;
        domains = run;
    }
    }
    run->userDomain = domain;
    free(application);
}

void
NetSnmpAgent::netsnmp_clear_user_domain(void)
{
    struct netsnmp_lookup_domain* run = domains, *prev = NULL;

    while (run) {
    if (run->userDomain != NULL) {
            destroy_word_array(run->userDomain);
        run->userDomain = NULL;
    }
    if (run->domain == NULL) {
        struct netsnmp_lookup_domain* tmp = run;
        if (prev)
        run = prev->next = run->next;
        else
        run = domains = run->next;
        free(tmp->application);
        free(tmp);
    } else {
        prev = run;
        run = run->next;
    }
    }
}

const char* const*
NetSnmpAgent::netsnmp_lookup_default_domains(const char* application)
{
    const char*  const*  res;

    if (application == NULL)
    res = NULL;
    else {
        struct netsnmp_lookup_domain* run = domains;

    while (run && strcmp(run->application, application) < 0)
        run = run->next;
    if (run && strcmp(run->application, application) == 0)
        if (run->userDomain)
                res = (const char*  const*)run->userDomain;
        else
                res = (const char*  const*)run->domain;
    else
        res = NULL;
    }
    if (res) {
        const char*  const*  r = res;
        while (*r) {
            ++r;
        }
    }
    return res;
}

const char*
NetSnmpAgent::netsnmp_lookup_default_domain(const char* application)
{
    const char*  const*  res = netsnmp_lookup_default_domains(application);
    return (res ? *res : NULL);
}

struct netsnmp_lookup_target {
    char* application;
    char* domain;
    char* userTarget;
    char* target;
    struct netsnmp_lookup_target* next;
};



int
NetSnmpAgent::netsnmp_register_default_target(const char* application, const char* domain,
                const char* target)
{
    struct netsnmp_lookup_target* run = targets, *prev = NULL;
    int i = 0, res = 0;
    while (run && ((i = strcmp(run->application, application)) < 0 ||
           (i == 0 && strcmp(run->domain, domain) < 0))) {
    prev = run;
    run = run->next;
    }
    if (run && i == 0 && strcmp(run->domain, domain) == 0) {
      if (run->target != NULL) {
        free(run->target);
        run->target = NULL;
        res = 1;
      }
    } else {
    run = SNMP_MALLOC_STRUCT(netsnmp_lookup_target);
    run->application = strdup(application);
    run->domain = strdup(domain);
    run->userTarget = NULL;
    if (prev) {
        run->next = prev->next;
        prev->next = run;
    } else {
        run->next = targets;
        targets = run;
    }
    }
    if (target) {
    run->target = strdup(target);
    } else if (run->userTarget == NULL) {
    if (prev)
        prev->next = run->next;
    else
        targets = run->next;
    free(run->domain);
    free(run->application);
    free(run);
    }
    return res;
}

void
NetSnmpAgent::netsnmp_clear_default_target(void)
{
    while (targets) {
    struct netsnmp_lookup_target* tmp = targets;
    targets = targets->next;
    free(tmp->application);
    free(tmp->domain);
    free(tmp->userTarget);
    free(tmp->target);
    free(tmp);
    }
}

void
NetSnmpAgent::netsnmp_register_user_target(const char* token, char* cptr)
{
    struct netsnmp_lookup_target* run = targets, *prev = NULL;
    size_t len = strlen(cptr) + 1;
    char* application = (char*)malloc(len);
    char* domain = (char*)malloc(len);
    char* target = (char*)malloc(len);
    int i = 0;

    {
    char* cp = copy_nword(cptr, application, len);
    cp = copy_nword(cp, domain, len);
    cp = copy_nword(cp, target, len);
    }

    while (run && ((i = strcmp(run->application, application)) < 0 ||
           (i == 0 && strcmp(run->domain, domain) < 0))) {
    prev = run;
    run = run->next;
    }
    if (run && i == 0 && strcmp(run->domain, domain) == 0) {
    if (run->userTarget != NULL) {
        goto done;
    }
    } else {
    run = SNMP_MALLOC_STRUCT(netsnmp_lookup_target);
    run->application = strdup(application);
    run->domain = strdup(domain);
    run->target = NULL;
    if (prev) {
        run->next = prev->next;
        prev->next = run;
    } else {
        run->next = targets;
        targets = run;
    }
    }
    run->userTarget = strdup(target);
 done:
    free(target);
    free(domain);
    free(application);
}

void
NetSnmpAgent::netsnmp_clear_user_target(void)
{
    struct netsnmp_lookup_target* run = targets, *prev = NULL;

    while (run) {
    if (run->userTarget != NULL) {
        free(run->userTarget);
        run->userTarget = NULL;
    }
    if (run->target == NULL) {
        struct netsnmp_lookup_target* tmp = run;
        if (prev)
        run = prev->next = run->next;
        else
        run = targets = run->next;
        free(tmp->application);
        free(tmp->domain);
        free(tmp);
    } else {
        prev = run;
        run = run->next;
    }
    }
}

const char*
NetSnmpAgent::netsnmp_lookup_default_target(const char* application, const char* domain)
{
    int i = 0;
    struct netsnmp_lookup_target* run = targets;
    const char* res;

    if (application == NULL || domain == NULL)
    res = NULL;
    else {
    while (run && ((i = strcmp(run->application, application)) < 0 ||
               (i == 0 && strcmp(run->domain, domain) < 0)))
        run = run->next;
    if (run && i == 0 && strcmp(run->domain, domain) == 0)
        if (run->userTarget != NULL)
        res = run->userTarget;
        else
        res = run->target;
    else
        res = NULL;
    }
    return res;
}

void
NetSnmpAgent::netsnmp_register_service_handlers(void)
{
    register_config_handler("snmp:", "defDomain",
                &NetSnmpAgent::netsnmp_register_user_domain,
                &NetSnmpAgent::netsnmp_clear_user_domain,
                "application domain");
    register_config_handler("snmp:", "defTarget",
                &NetSnmpAgent::netsnmp_register_user_target,
                &NetSnmpAgent::netsnmp_clear_user_target,
                "application domain target");
}
