extern "C" {

#include "postgres.h"
#include "foreign/fdwapi.h"
#include "utils/rel.h"
#include "utils/lsyscache.h"
#include "commands/explain.h"
#include "tcop/utility.h"
#include "commands/defrem.h"

#pragma GCC visibility push(default)

PG_MODULE_MAGIC;

void _PG_init();

#pragma GCC visibility pop
}

#include "pg_hooks.h"
#include "instrumentation_context.h"
#include <sys/stat.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>
#include <execinfo.h>
#include <sstream>

// Postgres ProcessUtility hook bookkeeping.
static ProcessUtility_hook_type process_utility_hook_next = nullptr;

// Activates certain additional functionality implemented by outNode
// hook, used by capture_object().
static const void *inCaptureObject = nullptr;

// Current instrumentation context, nullptr means instrumentation
// inactive.
static InstrumentationContext *ic;

void __wrap__pfree(void *pointer)
{
    // Using pointers for identity checks hence if the object was
    // captured and later memory is reused we run into troubles.
    if (ic && ic->samples_index.find(pointer) != ic->samples_index.end())
        return;

    __real__pfree(pointer);
}

// Record various Oid-s we've spotted so that when a report is produced
// we could include info on these Oid-s.
static void sniff_object(const Node *obj)
{
    assert(ic);
    assert(obj);

    switch (nodeTag(obj)) {
    case T_Var: {
        auto *var = reinterpret_cast<const Var *>(obj);
        ic->types.insert(var->vartype);
        break;
    }
    case T_Const: {
        auto *konst = reinterpret_cast<const Const *>(obj);
        ic->types.insert(konst->consttype);
        break;
    }
    case T_OpExpr: {
        auto *opexpr = reinterpret_cast<const OpExpr *>(obj);
        ic->types.insert(opexpr->opresulttype);
        ic->operators.insert(opexpr->opno);
        ic->functions.insert(opexpr->opfuncid);
        break;
    }
    case T_FuncExpr: {
        auto *funcexpr = reinterpret_cast<const FuncExpr *>(obj);
        ic->types.insert(funcexpr->funcresulttype);
        ic->functions.insert(funcexpr->funcid);
        break;
    }
    default:
        break;
    }
}

// Abusing outNode() for capture_object().
// We extend the output with a few additional attributes.
// We are also recording various Oid-s objects are referencing to
// resolve them later when we produce a report. 
void __wrap__outNode(StringInfo str, const void *obj)
{
    if (!inCaptureObject) return __real__outNode(str, obj);

    auto it = ic->samples_index.find(obj);
    if (it != ic->samples_index.end()) {
        // Do NOT output things twice.
        appendStringInfo(str, "{X-REF :x-id %p}", ic->samples[it->second].id);
        return;
    }

    const size_t len = str->len;

    __real__outNode(str, obj);

    if (str->data[str->len - 1] == '}' && str->data[str->len - 2] != '{') {
        // An object: append id attribute (pointer) 
        str->data[--str->len] = '\0';

        if (nodeTag(obj) >= T_Path && nodeTag(obj) <= T_LimitPath) {

            // Path stock output function omits some crucial bits.
            auto *p = reinterpret_cast<const Path *>(obj);
            appendStringInfo(str, " :x-param_info ");
            outNode(str, p->param_info);

        } else if (IsA(obj, Const)) {

            // Print value as human readable string.
            auto *c = reinterpret_cast<const Const *>(obj);
            Oid   typeoutput;
            bool  typeIsVarlena;
            char *result;

            getTypeOutputInfo(c->consttype, &typeoutput, &typeIsVarlena);
            result = OidOutputFunctionCall(typeoutput, c->constvalue);

            appendStringInfo(str, " :x-constvalue ");
            outDatum(str, PointerGetDatum(result), -2, false);

            pfree(result);
        }
        appendStringInfo(str, " :x-id %p}", obj);

        // If object's string representation is large enough, store it
        // in a separate sample and emit reference instead. Results in
        // output compression for repeated objects.
        if (str->len - len > 150 && inCaptureObject != obj) {
            ic->samples.push_back(PgObject(obj, str->data + len));
            ic->samples_index[obj] = ic->samples.size() - 1;
            str->data[str->len = len] = '\0';
            appendStringInfo(str, "{X-REF :x-id %p}", obj);
        }
    }

    if (obj) sniff_object(reinterpret_cast<const Node *>(obj));
}

static size_t do_capture_object(const void *p, PgObject **desc)
{
    inCaptureObject = p;

    auto repr = nodeToString(p);

    inCaptureObject = nullptr;

    ic->samples.push_back(PgObject(p, repr));

    pfree(repr);

    *desc = &ic->samples.back();
    return ic->samples.size() - 1;
}

static PgObject &capture_object(const void *p)
{
    auto it = ic->samples_index.find(p);
    if (it != ic->samples_index.end())
        return ic->samples[it->second];

    PgObject *desc;
    size_t idx = do_capture_object(p, &desc);
    ic->samples_index[p] = idx;
    return *desc;
}

// This is to support add_path() quirks: a path may be added to multiple
// RelOptInfo-s, actually happens in grouping planner. Though invoked
// multiple times, capture_object() creates a single PgObject, meaning
// that there's a single set of attributes, like 'backtrace' and
// 'parent' (tracks RelOptInfo the path belongs to.)
//
// Proxies to the resque: if the object wasn't captured yet,
// capture_proxy() is equivalent to capture_object(). If it was, the
// function records a new 'proxy' object referencing the real object.
// This gives us a distinct set of attributes to record backtrace and
// the parent. All references to the original object encountered
// while capturing further objects are automaticaly replaced with a
// reference to the proxy. Proxies could be chained.
static PgObject &capture_proxy(const void *p)
{
    PgObject *desc;
    size_t idx = do_capture_object(p, &desc);
    auto &index_cell = ic->samples_index[p];
    // Object already captured?
    if (index_cell || (idx && ic->samples.front().id == p))
        desc->id = &index_cell;
    index_cell = idx;
    return *desc;
}

static PgObject &capture_backtrace(PgObject &desc, int level)
    __attribute__((noinline));

static PgObject &capture_backtrace(PgObject &desc, int level)
{
    constexpr size_t FRAMES_MAX = 32;
    const void * bt[FRAMES_MAX];

    desc.backtrace.assign(bt + level + 1,
            bt+backtrace(const_cast<void**>(bt), FRAMES_MAX));
    return desc;
}

void __wrap__add_path(RelOptInfo *parent_rel, Path *new_path)
{
    if (ic) {
        capture_object(parent_rel);
        capture_backtrace(capture_proxy(new_path), 1).parent = parent_rel;
    }

    return __real__add_path(parent_rel, new_path);
}

void __wrap__add_partial_path(RelOptInfo *parent_rel, Path *new_path)
{
    if (ic) {
        capture_object(parent_rel);
        capture_backtrace(capture_proxy(new_path), 1).parent = parent_rel;
    }

    return __real__add_partial_path(parent_rel, new_path);
}

RelOptInfo *__wrap__build_simple_rel(PlannerInfo *root,
                                     int relid,
                                     BuildSimpleRelParam3 param3)
{
    if (!ic)
        return __real__build_simple_rel(root, relid, param3);

    auto p = __real__build_simple_rel(root, relid, param3);
    capture_object(root);
    auto &relinfo = capture_object(p);
    relinfo.parent = root;
    relinfo.oid = root->simple_rte_array[relid]->relid;
    return p;
}

// For a certain class of queries, like SELECT 42, we aren't referencing
// any relations, hence build_simple_rel() is not called and PlannerInfo
// isn't captured, unless we hook build_empty_join_rel() as well.
RelOptInfo * __wrap__build_empty_join_rel(PlannerInfo *root)
{
    if (!ic)
        return __real__build_empty_join_rel(root);

    auto p = __real__build_empty_join_rel(root);
    capture_object(root);
    capture_object(p).parent = root;
    return p;
}

Plan *__wrap__create_plan(PlannerInfo *root, Path *best_path)
{
    if (ic)
        capture_object(best_path).isChosen = true;

    return __real__create_plan(root, best_path);
}

static std::string submit_report()
{
    char path_buf[] = "/tmp/XXXXXX";
    std::ostringstream os;
    make_report(os, *ic);
    auto report_data = os.str();
    int fd = mkstemp(path_buf);
    write(fd, report_data.c_str(), report_data.size()); 
    fchmod(fd, 0604);
    close(fd);
    return path_buf;
}

void __wrap__ExplainPrintPlan(ExplainState *es, QueryDesc *queryDesc)
{
    if (!ic)
        return __real__ExplainPrintPlan(es, queryDesc);

    __real__ExplainPrintPlan(es, queryDesc);

    std::string url = submit_report();
    clear_instrumentation_context(*ic);

    if (es->format == EXPLAIN_FORMAT_TEXT)
        appendStringInfo(es->str, "Planscape URL: %s\n", url.c_str());
    else
        ExplainPropertyText("Planscape URL", url.c_str(), es);;
}

static Node *remove_planscape_options_from_explain_stmt(Node *parsetree,
                                                        bool *enable_planscape)
{
    assert(IsA(parsetree, ExplainStmt));
    *enable_planscape = false;

    auto *explain = reinterpret_cast<ExplainStmt *>(parsetree);
    auto *explain_copy = makeNode(ExplainStmt);

    // Scan list for 'planscape' option.
    // Produce a copy of options list, removing 'planscape' options.
    ListCell *lc;
    foreach(lc, explain->options) {
        assert(IsA(lfirst(lc), DefElem));
        auto *opt = reinterpret_cast<DefElem *>(lfirst(lc));
        if (strcmp(opt->defname, "planscape") == 0) {
            *enable_planscape = defGetBoolean(opt);
        } else {
            explain_copy->options = lappend(explain_copy->options, opt);
        }
    }

    explain_copy->query = explain->query;
    return reinterpret_cast<Node *>(explain_copy);
}

#if PG_VERSION_NUM >= 100000
#define QUERY_ENVIRONMENT_PARAM(arg, _) arg,
#else
#define QUERY_ENVIRONMENT_PARAM(arg, _)
#endif

static void process_utility(
#if PG_VERSION_NUM >= 100000
                            PlannedStmt *parsetree,
#else
                            Node *parsetree,
#endif
                            const char *queryString,
                            ProcessUtilityContext context,
                            ParamListInfo paramListInfo,
    QUERY_ENVIRONMENT_PARAM(QueryEnvironment *queryEnvironment,)
                            DestReceiver *destReceiver,
                            char *completionTag)
{
    bool enable_planscape;

#if PG_VERSION_NUM >= 100000
    if (IsA(parsetree->utilityStmt, ExplainStmt)) {

        parsetree->utilityStmt = remove_planscape_options_from_explain_stmt(
                parsetree->utilityStmt, &enable_planscape);
#else
    if (IsA(parsetree, ExplainStmt)) {

        parsetree = remove_planscape_options_from_explain_stmt(
                parsetree, &enable_planscape);

#endif
        // Create new IC
        std::unique_ptr<InstrumentationContext> icontext;

        if (enable_planscape) {

            if (!install_hooks()) {
                ereport(ERROR,
                        (errcode(ERRCODE_SYSTEM_ERROR),
                errmsg("failed to install PLANSCAPE hooks"),
                errhint("a possible cause may be a debugger attached")));
            }

            icontext = create_instrumentation_context(queryString);
        }

        auto * const ic_prev = ic;

        PG_TRY();
        {
            ic = icontext.get();

            process_utility_hook_next(parsetree,
                                      queryString,
                                      context,
                                      paramListInfo,
              QUERY_ENVIRONMENT_PARAM(queryEnvironment,)
                                      destReceiver,
                                      completionTag);

            ic = ic_prev;
        }
        PG_CATCH();
        {
            ic = ic_prev;

            // NB: explicit destruction needed; PG_RE_THROW() is a
            // longjump in disguise.
            icontext.reset();

            PG_RE_THROW();
        }
        PG_END_TRY();

    } else {
        process_utility_hook_next(parsetree,
                                  queryString,
                                  context,
                                  paramListInfo,
          QUERY_ENVIRONMENT_PARAM(queryEnvironment,)
                                  destReceiver,
                                  completionTag);
    }
}

#undef QUERY_ENVIRONMENT_PARAM

void _PG_init()
{
    process_utility_hook_next = 
        ProcessUtility_hook ? ProcessUtility_hook : standard_ProcessUtility;
    ProcessUtility_hook = process_utility;
}
