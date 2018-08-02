#include "instrumentation_context.h"
#include "json.h"
#include "symboliser.h"
#include <dlfcn.h>

extern "C" {
#include "access/heapam.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_operator.h"
#include "utils/rel.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"
#include "miscadmin.h"
}

static void
report_samples(std::ostream &os, const InstrumentationContext &ic)
{
    const char *sep = "";
    os << '[';
    for (const auto &object: ic.samples) {

        os << sep; sep = ",";
        os << "{\"id\":\"" << object.id <<'"';
        os << ",\"data\":\"" << json_escape_string(object.data) << '\"';

        if (object.oid != InvalidOid)
            os << ",\"oid\":" << object.oid;

        if (object.isChosen)
            os << ",\"isChosen\":true";

        if (object.parent)
            os << ",\"parent\":\"" << object.parent << '"';

        if (!object.backtrace.empty()) {

            os << ",\"backtrace\":[";

            for (auto frame: object.backtrace) {
                if (frame != object.backtrace[0]) os << ',';
                os << '"' << frame << '"';
            }

            os << ']';
        }

        os << '}';
    }

    os << ']';
}

static void
report_relations(std::ostream &os, const InstrumentationContext &ic)
{
    std::unordered_set<Oid> relations;

    for (const auto &object: ic.samples)
        relations.insert(object.oid);

    os << '[';
    const char *sep = "";
    for (auto oid: relations) {

        if (oid == InvalidOid) continue;

        os << sep << "{\"oid\":" << oid; sep = ",";

        Relation rel = heap_open(oid, NoLock);

        os << ",\"name\":\"" << json_escape_string(RelationGetRelationName(rel));
        os << "\",\"ns\":\"" << json_escape_string(get_namespace_name(
                                                     RelationGetNamespace(rel)));
        os << "\",\"attrs\":[";

        const int n = RelationGetDescr(rel)->natts;
        for (int i = 1; i <= n; i++) {

            if (i != 1) os << ",";
            os << '"' << json_escape_string(get_relid_attribute_name(oid, i)) << '"';
        }
        os << "]}";

        heap_close(rel, NoLock);
    }
    os << ']';
}

struct ModuleInfo
{
    std::string               name;
    std::vector<const void *> stack_frames;
};

static void
report_modules(std::ostream &os, const InstrumentationContext &ic)
{
    std::unordered_set<const void *> stack_frames;
    std::unordered_map<const void *, ModuleInfo> modules;

    // Build a set of addresses spotted in backtraces
    for (const auto &object: ic.samples)
        for (const auto frame: object.backtrace)
            stack_frames.insert(frame);

    // Group by module
    for (const auto *frame: stack_frames) {

        Dl_info dlinfo;

        if (dladdr(const_cast<void *>(frame), &dlinfo) == 0) continue;

        auto &mi = modules[dlinfo.dli_fbase];

        if (mi.name.empty()) {
            // Postgres clobbers argv, hence a funny path for the main
            // executable
            if (strncmp(dlinfo.dli_fname, "postgres: ", 10) == 0)
                mi.name = my_exec_path;
            else
                mi.name = dlinfo.dli_fname;
        }

        mi.stack_frames.push_back(frame);
    }

    // Report modules
    const char *sep = "";
    os << '[';
    for (const auto &mitem: modules) {

        const auto &mi = mitem.second;
        Symboliser symboliser(mi.name, mitem.first);

        os << sep; sep = ",";

        os << "{\"name\":\"" << json_escape_string(mi.name) << '"';
        for (auto *frame: mi.stack_frames) {

            symboliser.symbolise(frame);

            os << ",\"" << frame << "\":[";
            while (true) {

                os << '"';
                os << json_escape_string(symboliser.get_fn_name());
                os << "\",\"";
                os << json_escape_string(symboliser.get_src_file_name());
                os << "\"," << symboliser.get_line_number();

                if (!symboliser.next())
                    break;
                else
                    os << ',';
            }
            os << "]";
        }
        os << '}';
    }
    os << ']';
}

template<SysCacheIdentifier EntityId,
         typename Entity,
         typename Callback>
static void
report_entities(std::ostream &os,
                const std::unordered_set<Oid> &oids,
                const Callback &callback)
{
    os << '[';
    const char *sep = "";
    for (auto oid: oids) {

        os << sep << "{\"oid\":" << oid; sep = ",";

        HeapTuple tuple = SearchSysCache1(EntityId, ObjectIdGetDatum(oid));

        if (HeapTupleIsValid(tuple)) {
            callback(*reinterpret_cast<const Entity>(GETSTRUCT(tuple)));
            ReleaseSysCache(tuple);
        }

        os << '}';
    }
    os << ']';
}

static void
report_types(std::ostream &os, const InstrumentationContext &ic)
{
    report_entities<TYPEOID, Form_pg_type>(os, ic.types, [&] (auto &type) {
        os << ",\"name\":\"" << json_escape_string(NameStr(type.typname)) << '"';
    });
}

static void
report_functions(std::ostream &os, const InstrumentationContext &ic)
{
    report_entities<PROCOID, Form_pg_proc>(os, ic.functions, [&] (auto &proc) {
        os << ",\"name\":\"" << json_escape_string(NameStr(proc.proname)) << '"';
    });
}

static void
report_operators(std::ostream &os, const InstrumentationContext &ic)
{
    report_entities<OPEROID, Form_pg_operator>(os, ic.operators, [&] (auto &oper) {
        os << ",\"name\":\"" << json_escape_string(NameStr(oper.oprname)) << '"';
    });
}

void make_report(std::ostream &os, const InstrumentationContext &ic)
{
    os << "{\"samples\":";
    report_samples(os, ic);

    os << ",\"relations\":";
    report_relations(os, ic);

    os << ",\"modules\":";
    report_modules(os, ic);

    os << ",\"types\":";
    report_types(os, ic);

    os << ",\"functions\":";
    report_functions(os, ic);

    os << ",\"operators\":";
    report_operators(os, ic);

    os << '}';
}
