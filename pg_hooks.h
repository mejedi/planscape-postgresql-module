#pragma once

extern "C" {

void __wrap__pfree(void *pointer);
void __real__pfree(void *pointer);

void __wrap__outNode(StringInfo str, const void *obj);
void __real__outNode(StringInfo str, const void *obj);

void __wrap__add_path(RelOptInfo *parent_rel, Path *new_path);
void __real__add_path(RelOptInfo *parent_rel, Path *new_path);

void __wrap__add_partial_path(RelOptInfo *parent_rel, Path *new_path);
void __real__add_partial_path(RelOptInfo *parent_rel, Path *new_path);

#if PG_VERSION_NUM >= 100000
typedef RelOptInfo *BuildSimpleRelParam3;
#else
typedef RelOptKind BuildSimpleRelParam3;
#endif

RelOptInfo * __wrap__build_simple_rel(PlannerInfo *root,
                                      int relid,
                                      BuildSimpleRelParam3 param3);

RelOptInfo * __real__build_simple_rel(PlannerInfo *root,
                                      int relid,
                                      BuildSimpleRelParam3 param3);

RelOptInfo * __wrap__build_empty_join_rel(PlannerInfo *root);
RelOptInfo * __real__build_empty_join_rel(PlannerInfo *root);

// Not hooking
//   build_join_rel,
//   fetch_upper_rel.
// As of 9.6, there are only 4 functions producing RelOptInfo-s, and we
// only care about simple rels. We can't get underliing relation ID from
// RelOptInfo alone.

Plan *__wrap__create_plan(PlannerInfo *root, Path *best_path);
Plan *__real__create_plan(PlannerInfo *root, Path *best_path);

void __wrap__ExplainPrintPlan(ExplainState *es, QueryDesc *queryDesc);
void __real__ExplainPrintPlan(ExplainState *es, QueryDesc *queryDesc);

}

bool install_hooks();

