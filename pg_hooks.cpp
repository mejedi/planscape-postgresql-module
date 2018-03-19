extern "C" {

#include "postgres.h"
#include "lib/stringinfo.h"
#include "nodes/relation.h"
#include "nodes/plannodes.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "commands/explain.h"

}

#include "pg_hooks.h"
#include "hook_engine.h"

HOOK_DEFINE_TRAMPOLINE(__real__pfree);
HOOK_DEFINE_TRAMPOLINE(__real__outNode);
HOOK_DEFINE_TRAMPOLINE(__real__add_path);
HOOK_DEFINE_TRAMPOLINE(__real__add_partial_path);
HOOK_DEFINE_TRAMPOLINE(__real__build_simple_rel);
HOOK_DEFINE_TRAMPOLINE(__real__build_empty_join_rel);
HOOK_DEFINE_TRAMPOLINE(__real__create_plan);
HOOK_DEFINE_TRAMPOLINE(__real__ExplainPrintPlan);

static bool do_install_hooks()
{
    if (hook_begin() != 0) return false;

    int rc;

    rc = hook_install(pfree, __wrap__pfree, __real__pfree);

    if (rc == 0)
        rc = hook_install(outNode, __wrap__outNode, __real__outNode);

    if (rc == 0)
        rc = hook_install(add_path, __wrap__add_path, __real__add_path);

    if (rc == 0)
        rc = hook_install(add_partial_path, __wrap__add_partial_path,
                                            __real__add_partial_path);

    if (rc == 0)
        rc = hook_install(build_simple_rel, __wrap__build_simple_rel,
                                            __real__build_simple_rel);

    if (rc == 0)
        rc = hook_install(build_empty_join_rel, __wrap__build_empty_join_rel,
                                                __real__build_empty_join_rel);

    if (rc == 0)
        rc = hook_install(create_plan, __wrap__create_plan,
                                       __real__create_plan);

    if (rc == 0)
        rc = hook_install(ExplainPrintPlan, __wrap__ExplainPrintPlan,
                                            __real__ExplainPrintPlan);

    hook_end();

    return rc == 0;
}

bool install_hooks()
{
    // Install hooks once. Doing it multiple times is not just
    // inefficient, but harmfull.
    static bool res = do_install_hooks();

    return res;
}
