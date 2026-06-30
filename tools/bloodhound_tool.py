import json
import os
from typing import Any

from crewai.tools import BaseTool
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    GraphDatabase = None


DEFAULT_QUERIES = {
    "high_value_targets": (
        "MATCH (n) "
        "WHERE coalesce(n.highvalue, false) = true "
        "RETURN labels(n) AS labels, n.name AS name, n.objectid AS objectid "
        "ORDER BY n.name LIMIT $limit"
    ),
    "domain_admin_paths": (
        "MATCH (u:User), (g:Group) "
        "WHERE toUpper(g.name) CONTAINS 'DOMAIN ADMINS' "
        "MATCH p = shortestPath((u)-[*1..6]->(g)) "
        "RETURN u.name AS source, g.name AS target, "
        "[node IN nodes(p) | coalesce(node.name, node.objectid, labels(node)[0])] AS nodes, "
        "[rel IN relationships(p) | type(rel)] AS relationships, length(p) AS length "
        "ORDER BY length ASC LIMIT $limit"
    ),
    "kerberoastable_users": (
        "MATCH (u:User) "
        "WHERE u.hasspn = true OR u.serviceprincipalnames IS NOT NULL "
        "RETURN u.name AS name, u.enabled AS enabled, u.admincount AS admincount, "
        "u.serviceprincipalnames AS serviceprincipalnames "
        "ORDER BY u.name LIMIT $limit"
    ),
}


class BloodHoundToolInput(BaseModel):
    query_type: str = Field(
        default="summary",
        description=(
            "Query mode: summary, high_value_targets, shortest_paths, "
            "domain_admin_paths, kerberoastable_users, or custom."
        ),
    )
    source: str | None = Field(
        default=None,
        description="Source node name for shortest_paths query.",
    )
    target: str | None = Field(
        default=None,
        description="Target node name for shortest_paths query.",
    )
    cypher: str | None = Field(
        default=None,
        description="Read-only custom Cypher query. Must start with MATCH, WITH, or CALL.",
    )
    limit: int = Field(default=25, description="Maximum number of rows to return.")


def _json_default(value: Any) -> str:
    return str(value)


def _record_to_dict(record: Any) -> dict[str, Any]:
    return {key: record[key] for key in record.keys()}


def _is_read_only_cypher(cypher: str) -> bool:
    stripped = cypher.strip().lower()
    if not stripped.startswith(("match ", "with ", "call ")):
        return False
    blocked = (
        " create ",
        " merge ",
        " delete ",
        " detach ",
        " set ",
        " remove ",
        " drop ",
        " load csv",
    )
    padded = f" {stripped} "
    return not any(token in padded for token in blocked)


@ToolRegistry.register("bloodhound_tool")
class BloodHoundTool(BaseTool):
    name: str = "BloodHoundTool"
    description: str = (
        "Connect to a Neo4j BloodHound database, execute read-only Cypher queries, "
        "and return structured JSON for high value targets, shortest paths, Domain Admin paths, "
        "and Kerberoastable users."
    )
    args_schema: type[BaseModel] = BloodHoundToolInput

    def _run(
        self,
        query_type: str = "summary",
        source: str | None = None,
        target: str | None = None,
        cypher: str | None = None,
        limit: int = 25,
    ) -> str:
        load_dotenv(".env")
        if GraphDatabase is None:
            return json.dumps(
                {
                    "error": "neo4j_driver_missing",
                    "message": "Install the neo4j Python package to use BloodHoundTool.",
                },
                indent=2,
            )

        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "neo4j")
        database = os.getenv("NEO4J_DATABASE", "neo4j")
        safe_limit = max(1, min(int(limit), 200))

        try:
            logger.info("Running BloodHound query: query_type=%s limit=%s", query_type, safe_limit)
            with GraphDatabase.driver(uri, auth=(user, password)) as driver:
                driver.verify_connectivity()
                with driver.session(database=database) as session:
                    result = self._execute_query(
                        session=session,
                        query_type=query_type,
                        source=source,
                        target=target,
                        cypher=cypher,
                        limit=safe_limit,
                    )
            logger.info("Completed BloodHound query: query_type=%s", query_type)
            return json.dumps(result, indent=2, default=_json_default)
        except Exception as exc:
            logger.error("BloodHoundTool query failed: %s", exc)
            return json.dumps(
                {
                    "error": "bloodhound_query_failed",
                    "query_type": query_type,
                    "message": str(exc),
                },
                indent=2,
            )

    def _execute_query(
        self,
        session: Any,
        query_type: str,
        source: str | None,
        target: str | None,
        cypher: str | None,
        limit: int,
    ) -> dict[str, Any]:
        if query_type == "summary":
            return {
                "query_type": "summary",
                "high_value_targets": self._run_cypher(session, DEFAULT_QUERIES["high_value_targets"], {"limit": limit}),
                "domain_admin_paths": self._run_cypher(session, DEFAULT_QUERIES["domain_admin_paths"], {"limit": limit}),
                "kerberoastable_users": self._run_cypher(session, DEFAULT_QUERIES["kerberoastable_users"], {"limit": limit}),
            }

        if query_type in DEFAULT_QUERIES:
            return {
                "query_type": query_type,
                "results": self._run_cypher(session, DEFAULT_QUERIES[query_type], {"limit": limit}),
            }

        if query_type == "shortest_paths":
            if not source or not target:
                raise ValueError("source and target are required for shortest_paths.")
            query = (
                "MATCH (s {name: $source}), (t {name: $target}) "
                "MATCH p = shortestPath((s)-[*1..8]->(t)) "
                "RETURN s.name AS source, t.name AS target, "
                "[node IN nodes(p) | coalesce(node.name, node.objectid, labels(node)[0])] AS nodes, "
                "[rel IN relationships(p) | type(rel)] AS relationships, length(p) AS length "
                "LIMIT $limit"
            )
            return {
                "query_type": "shortest_paths",
                "source": source,
                "target": target,
                "results": self._run_cypher(
                    session,
                    query,
                    {"source": source, "target": target, "limit": limit},
                ),
            }

        if query_type == "custom":
            if not cypher or not _is_read_only_cypher(cypher):
                raise ValueError("custom cypher must be read-only and start with MATCH, WITH, or CALL.")
            return {
                "query_type": "custom",
                "results": self._run_cypher(session, cypher, {"limit": limit}),
            }

        raise ValueError(
            "Unsupported query_type. Use summary, high_value_targets, shortest_paths, "
            "domain_admin_paths, kerberoastable_users, or custom."
        )

    def _run_cypher(self, session: Any, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        return [_record_to_dict(record) for record in session.run(query, **params)]
