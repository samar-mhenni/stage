import json
import os
import re
from typing import Any

from crewai.tools import BaseTool
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from config.logging import logger
from tools.registry import ToolRegistry

try:
    from neo4j import GraphDatabase
    from neo4j.graph import Node, Path, Relationship
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    GraphDatabase = None
    Node = None
    Path = None
    Relationship = None


ENTITY_LABELS = {
    "asset": "Asset",
    "user": "User",
    "threatactor": "ThreatActor",
    "threat_actor": "ThreatActor",
    "cve": "CVE",
    "attacktechnique": "AttackTechnique",
    "attack_technique": "AttackTechnique",
    "technique": "AttackTechnique",
    "campaign": "Campaign",
    "detection": "Detection",
}

ALLOWED_RELATIONSHIPS = {
    "TARGETS",
    "USES",
    "EXPLOITS",
    "AFFECTS",
    "MEMBER_OF",
    "HAS_ACCESS_TO",
    "ATTRIBUTED_TO",
    "DETECTS",
    "OBSERVED_IN",
    "RELATED_TO",
}

CONSTRAINT_LABELS = ("Asset", "User", "ThreatActor", "CVE", "AttackTechnique", "Campaign", "Detection")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Neo4jToolInput(BaseModel):
    action: str = Field(
        default="search",
        description="Action to run: init_schema, create_node, create_relationship, query, search, or schema.",
    )
    entity_type: str | None = Field(
        default=None,
        description="Entity type for node creation/search: Asset, User, ThreatActor, CVE, AttackTechnique, Campaign, Detection.",
    )
    properties_json: str | None = Field(
        default=None,
        description="JSON object of node properties. Include id or name when possible.",
    )
    source_type: str | None = Field(default=None, description="Source entity type for relationship creation.")
    source_id: str | None = Field(default=None, description="Source entity id for relationship creation.")
    target_type: str | None = Field(default=None, description="Target entity type for relationship creation.")
    target_id: str | None = Field(default=None, description="Target entity id for relationship creation.")
    relationship_type: str | None = Field(
        default=None,
        description="Relationship type, for example USES, TARGETS, EXPLOITS, DETECTS, or RELATED_TO.",
    )
    relationship_properties_json: str | None = Field(
        default=None,
        description="Optional JSON object of relationship properties.",
    )
    cypher: str | None = Field(default=None, description="Cypher query for action='query'.")
    parameters_json: str | None = Field(default=None, description="Optional JSON object of Cypher parameters.")
    search_text: str | None = Field(default=None, description="Text to search across entity ids, names, descriptions, and aliases.")
    depth: int = Field(default=2, description="Graph search traversal depth.")
    limit: int = Field(default=25, description="Maximum number of rows to return.")
    allow_write_query: bool = Field(
        default=False,
        description="Set true only when action='query' should allow write Cypher. Prefer create_node/create_relationship.",
    )


def _parse_json_object(value: str | None, field_name: str) -> dict[str, Any]:
    if not value:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object.")
    return parsed


def _canonical_label(entity_type: str | None) -> str:
    if not entity_type:
        raise ValueError("entity_type is required.")
    key = entity_type.replace(" ", "_").replace("-", "_").lower()
    label = ENTITY_LABELS.get(key)
    if not label:
        raise ValueError(f"Unsupported entity_type: {entity_type}")
    return label


def _relationship_type(value: str | None) -> str:
    if not value:
        raise ValueError("relationship_type is required.")
    rel_type = value.strip().upper().replace(" ", "_").replace("-", "_")
    if rel_type not in ALLOWED_RELATIONSHIPS:
        raise ValueError(f"Unsupported relationship_type: {value}")
    return rel_type


def _safe_identifier(value: str) -> str:
    if not IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"Unsafe Cypher identifier: {value}")
    return value


def _derive_id(properties: dict[str, Any]) -> str:
    value = properties.get("id") or properties.get("name")
    if not value:
        raise ValueError("properties_json must include id or name.")
    return str(value)


def _is_read_only_cypher(cypher: str) -> bool:
    stripped = cypher.strip().lower()
    if not stripped.startswith(("match ", "with ", "call ", "return ", "show ")):
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
        " apoc.create",
        " apoc.merge",
        " dbms.",
    )
    padded = f" {stripped} "
    return not any(token in padded for token in blocked)


def _json_default(value: Any) -> Any:
    if Node is not None and isinstance(value, Node):
        return {"labels": list(value.labels), "properties": dict(value)}
    if Relationship is not None and isinstance(value, Relationship):
        return {"type": value.type, "properties": dict(value)}
    if Path is not None and isinstance(value, Path):
        return {
            "nodes": [{"labels": list(node.labels), "properties": dict(node)} for node in value.nodes],
            "relationships": [{"type": rel.type, "properties": dict(rel)} for rel in value.relationships],
        }
    return str(value)


def _record_to_dict(record: Any) -> dict[str, Any]:
    return {key: record[key] for key in record.keys()}


@ToolRegistry.register("neo4j_tool")
class Neo4jTool(BaseTool):
    name: str = "Neo4jTool"
    description: str = (
        "Access a Neo4j cyber knowledge graph. Supports schema initialization, node creation, "
        "relationship creation, Cypher query execution, and graph search across Assets, Users, "
        "Threat Actors, CVEs, ATT&CK Techniques, Campaigns, and Detections."
    )
    args_schema: type[BaseModel] = Neo4jToolInput

    def _run(
        self,
        action: str = "search",
        entity_type: str | None = None,
        properties_json: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        relationship_type: str | None = None,
        relationship_properties_json: str | None = None,
        cypher: str | None = None,
        parameters_json: str | None = None,
        search_text: str | None = None,
        depth: int = 2,
        limit: int = 25,
        allow_write_query: bool = False,
    ) -> str:
        if GraphDatabase is None:
            return json.dumps(
                {"error": "neo4j_driver_missing", "message": "Install the neo4j Python package to use Neo4jTool."},
                indent=2,
            )

        safe_limit = max(1, min(int(limit), 200))
        safe_depth = max(1, min(int(depth), 5))
        try:
            with _Neo4jClient() as client:
                if action == "schema":
                    return json.dumps(client.schema(), indent=2)
                if action == "init_schema":
                    return json.dumps(client.init_schema(), indent=2)
                if action == "create_node":
                    label = _canonical_label(entity_type)
                    properties = _parse_json_object(properties_json, "properties_json")
                    result = client.create_node(label, properties)
                    return json.dumps(result, indent=2, default=_json_default)
                if action == "create_relationship":
                    result = client.create_relationship(
                        source_label=_canonical_label(source_type),
                        source_id=source_id,
                        target_label=_canonical_label(target_type),
                        target_id=target_id,
                        rel_type=_relationship_type(relationship_type),
                        properties=_parse_json_object(relationship_properties_json, "relationship_properties_json"),
                    )
                    return json.dumps(result, indent=2, default=_json_default)
                if action == "query":
                    if not cypher:
                        raise ValueError("cypher is required for query action.")
                    if not allow_write_query and not _is_read_only_cypher(cypher):
                        raise ValueError("Custom write Cypher is blocked. Use create_node/create_relationship or set allow_write_query=true.")
                    params = _parse_json_object(parameters_json, "parameters_json")
                    return json.dumps(client.query(cypher, params, safe_limit), indent=2, default=_json_default)
                if action == "search":
                    return json.dumps(
                        client.search(search_text=search_text, entity_type=entity_type, depth=safe_depth, limit=safe_limit),
                        indent=2,
                        default=_json_default,
                    )
                raise ValueError("Unsupported action. Use init_schema, create_node, create_relationship, query, search, or schema.")
        except Exception as exc:
            logger.exception("Neo4jTool failed.")
            return json.dumps({"error": "neo4j_tool_error", "message": str(exc)}, indent=2)


class _Neo4jClient:
    def __init__(self) -> None:
        load_dotenv(".env")
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "neo4j")
        self.database = os.getenv("NEO4J_DATABASE", "neo4j")
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.driver.verify_connectivity()

    def __enter__(self) -> "_Neo4jClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.driver.close()

    def init_schema(self) -> dict[str, Any]:
        statements = [
            f"CREATE CONSTRAINT {label.lower()}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE"
            for label in CONSTRAINT_LABELS
        ]
        with self.driver.session(database=self.database) as session:
            for statement in statements:
                session.run(statement)
        return {"created_constraints": statements}

    def schema(self) -> dict[str, Any]:
        return {
            "labels": list(CONSTRAINT_LABELS),
            "relationships": sorted(ALLOWED_RELATIONSHIPS),
            "identity_property": "id",
        }

    def create_node(self, label: str, properties: dict[str, Any]) -> dict[str, Any]:
        safe_label = _safe_identifier(label)
        properties = dict(properties)
        properties["id"] = _derive_id(properties)
        query = (
            f"MERGE (n:{safe_label} {{id: $id}}) "
            "SET n += $properties "
            "RETURN labels(n) AS labels, properties(n) AS properties"
        )
        with self.driver.session(database=self.database) as session:
            record = session.run(query, id=properties["id"], properties=properties).single()
        return _record_to_dict(record) if record else {}

    def create_relationship(
        self,
        source_label: str,
        source_id: str | None,
        target_label: str,
        target_id: str | None,
        rel_type: str,
        properties: dict[str, Any],
    ) -> dict[str, Any]:
        if not source_id or not target_id:
            raise ValueError("source_id and target_id are required.")
        safe_source = _safe_identifier(source_label)
        safe_target = _safe_identifier(target_label)
        safe_rel = _safe_identifier(rel_type)
        query = (
            f"MATCH (source:{safe_source} {{id: $source_id}}), (target:{safe_target} {{id: $target_id}}) "
            f"MERGE (source)-[relationship:{safe_rel}]->(target) "
            "SET relationship += $properties "
            "RETURN labels(source) AS source_labels, properties(source) AS source, "
            "type(relationship) AS relationship, properties(relationship) AS relationship_properties, "
            "labels(target) AS target_labels, properties(target) AS target"
        )
        with self.driver.session(database=self.database) as session:
            record = session.run(
                query,
                source_id=source_id,
                target_id=target_id,
                properties=properties,
            ).single()
        if not record:
            raise ValueError("Source or target node was not found.")
        return _record_to_dict(record)

    def query(self, cypher: str, parameters: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        with self.driver.session(database=self.database) as session:
            result = session.run(cypher, **parameters)
            return [_record_to_dict(record) for record in result.fetch(limit)]

    def search(
        self,
        search_text: str | None,
        entity_type: str | None,
        depth: int,
        limit: int,
    ) -> dict[str, Any]:
        label_filter = ""
        if entity_type:
            label_filter = f":{_safe_identifier(_canonical_label(entity_type))}"

        if search_text:
            query = (
                f"MATCH (n{label_filter}) "
                "WHERE any(value IN [n.id, n.name, n.description, n.info, n.aliases] "
                "WHERE value IS NOT NULL AND toLower(toString(value)) CONTAINS toLower($search_text)) "
                f"OPTIONAL MATCH path = (n)-[*1..{depth}]-(neighbor) "
                "RETURN labels(n) AS labels, properties(n) AS node, "
                "collect(DISTINCT {labels: labels(neighbor), properties: properties(neighbor)})[0..$limit] AS neighbors "
                "LIMIT $limit"
            )
            params = {"search_text": search_text, "limit": limit}
        else:
            query = (
                f"MATCH (n{label_filter}) "
                "OPTIONAL MATCH (n)-[relationship]-(neighbor) "
                "RETURN labels(n) AS labels, properties(n) AS node, "
                "collect(DISTINCT {relationship: type(relationship), labels: labels(neighbor), properties: properties(neighbor)})[0..$limit] AS neighbors "
                "LIMIT $limit"
            )
            params = {"limit": limit}

        with self.driver.session(database=self.database) as session:
            rows = [_record_to_dict(record) for record in session.run(query, **params)]
        return {"results": rows}
