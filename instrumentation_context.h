#pragma once

extern "C" {
#include "postgres.h"
}

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <iostream>

struct PgObject
{
    const void               *id;
    std::string               data; // Serialized object data
    const void               *parent = nullptr; // Logical parent:
                              // Path -> RelOptInfo -> PlannerInfo
    Oid                       oid = InvalidOid; // (RelOptInfo) relation's OID
    bool                      isChosen = false; // (Path) was used to build a plan
    std::vector<const void *> backtrace;

    PgObject(const void *id_, const char *data_): id(id_), data(data_) {}
};

struct InstrumentationContext
{
    std::string                                query;
    std::unordered_map<const void *, size_t>   samples_index;
    std::vector<PgObject>                      samples;
    std::unordered_set<Oid>                    types;
    std::unordered_set<Oid>                    functions;
    std::unordered_set<Oid>                    operators;
};

void clear_instrumentation_context(InstrumentationContext &ic);

std::unique_ptr<InstrumentationContext>
create_instrumentation_context(const char *query);

void make_report(std::ostream &os, const InstrumentationContext &ic);

std::string submit_report(const InstrumentationContext &ic, const char *url);

inline void clear_instrumentation_context(InstrumentationContext &ic)
{
    // Don't reset .query!
    ic.samples_index.clear();
    ic.samples.clear();
    ic.types.clear();
    ic.functions.clear();
    ic.operators.clear();
}

inline std::unique_ptr<InstrumentationContext>
create_instrumentation_context(const char *query)
{
    auto ic = std::make_unique<InstrumentationContext>();
    ic->query = query;
    return ic;
}
