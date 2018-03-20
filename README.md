# PG PLANSCAPE

PostgreSQL extension finally providing visibility into the planning process.

Records all the execution strategies considered by the planner and dumps the data in JSON file.

Usage (do `make && make install` first):

```
LOAD 'planscape';
EXPLAIN (PLANSCAPE) SELECT avg(a) FROM test;
```
