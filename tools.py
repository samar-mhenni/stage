"""
Custom CrewAI tools that interface with the existing ChromaDB vector databases.
This allows agents to autonomously search MITRE ATT&CK knowledge without altering the underlying RAG system.
"""
from crewai.tools import BaseTool
import chromadb
from sentence_transformers import SentenceTransformer
import logging
import re

# Suppress sentence_transformers logging if needed
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

# Load embedding model once
_embedding_model = SentenceTransformer("BAAI/bge-base-en-v1.5")
_db_client = chromadb.PersistentClient(path="./chroma_db")
MAX_CONTEXT_CHARS = 700


def _extract_mitre_id(text: str) -> str:
    match = re.search(r"\[(T\d{4}(?:\.\d{3})?)\]", text)
    return match.group(1) if match else ""


def _normalize_doc(doc: str) -> str:
    doc_text = str(doc)
    if len(doc_text) > MAX_CONTEXT_CHARS:
        return f"{doc_text[:MAX_CONTEXT_CHARS].rstrip()}..."
    return doc_text


def _format_record(record: dict) -> str:
    header = (
        f"[Source: {record['source']} | Type: {record['type']} | "
        f"Name: {record['name']} | Match: {record['match']:.4f}]"
    )
    return f"{header}\n{record['text']}"


def _distance_to_match_score(distance: float) -> float:
    """Convert Chroma distance to a high-is-better match score for reporting."""
    return 1 / (1 + (distance / 2))


def search_records(
    query: str,
    collections: list,
    top_k: int = 3,
    type_filters: dict[str, set[str]] | None = None,
) -> list[dict]:
    """Return structured vector search records for deterministic filtering."""
    query_embedding = _embedding_model.encode(query, show_progress_bar=False).tolist()
    records = []

    for coll_name in collections:
        try:
            coll = _db_client.get_collection(coll_name)
            results = coll.query(query_embeddings=[query_embedding], n_results=top_k)
            for idx, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][idx]
                obj_type = meta.get("type", "unknown")
                if type_filters and coll_name in type_filters and obj_type not in type_filters[coll_name]:
                    continue
                name = meta.get("name", "unknown")
                doc_text = _normalize_doc(doc)
                
                # Exploit-DB Specific Fields
                cve = meta.get("cve", "")
                cve_str = f" | CVE: {cve}" if cve else ""
                
                records.append(
                    {
                        "source": coll_name,
                        "type": obj_type,
                        "name": name,
                        "match": _distance_to_match_score(float(results["distances"][0][idx])),
                        "distance": float(results["distances"][0][idx]),
                        "text": doc_text,
                        "mitre_id": _extract_mitre_id(doc_text),
                        "cve_str": cve_str
                    }
                )
        except Exception:
            pass

    return records

def _format_record(record: dict) -> str:
    header = (
        f"[Source: {record['source']} | Type: {record['type']} | "
        f"Name: {record['name']}{record.get('cve_str', '')} | Match: {record['match']:.4f}]"
    )
    return f"{header}\n{record['text']}"

def _search_collections(
    query: str,
    collections: list,
    top_k: int = 3,
    type_filters: dict[str, set[str]] | None = None,
) -> str:
    """Internal helper to search specific collections and format output."""
    records = search_records(query, collections, top_k, type_filters)
    if not records:
        return "No relevant context found in the database."
    
    # Sort globally by match score descending to prioritize best hits across all requested collections
    records.sort(key=lambda r: r['match'], reverse=True)
    return "\n\n---\n\n".join(_format_record(record) for record in records)


def _prioritize_exploit_db(query: str) -> list[str]:
    """Return ordered collections based on query keywords."""
    exploit_keywords = ["cve", "vulnerability", "exploit", "rce", "privilege escalation", "sql injection"]
    query_lower = query.lower()
    
    # Check for exact CVE regex or keyword matches
    is_exploit_heavy = re.search(r"cve-\d{4}-\d+", query_lower) or any(k in query_lower for k in exploit_keywords)
    
    if is_exploit_heavy:
        return ["exploit_db", "redteam_db", "attack_db", "actor_db"]
    return ["redteam_db", "attack_db", "actor_db", "exploit_db"]


def red_team_database_search(query: str) -> str:
    """Search red-team relevant collections, prioritizing Exploit-DB if exploit-related keywords exist."""
    collections = _prioritize_exploit_db(query)
    return _search_collections(query, collections)


def threat_intel_database_search(query: str) -> str:
    """Search threat-intel relevant collections."""
    return _search_collections(
        query,
        ["detection_db", "attack_db"],
        type_filters={"attack_db": {"attack-pattern"}},
    )


class RedTeamSearchTool(BaseTool):
    name: str = "Red Team Database Search"
    description: str = (
        "Search the Red Team, Exploit, Attack, and Actor databases for operational red team knowledge, "
        "adversary simulation procedures, exploits, vulnerabilities, CVEs, and MITRE ATT&CK techniques. "
        "Input should be a specific search query like 'Credential Dumping', 'Ryuk ransomware', or 'CVE-2021-44228'."
    )

    def _run(self, query: str) -> str:
        return red_team_database_search(query)


class ThreatIntelSearchTool(BaseTool):
    name: str = "threat_intel_database_search"
    description: str = (
        "Search the Detection, Attack, and Actor databases for defensive CTI analysis, "
        "detection guidance, mitigations, attribution scoring, and SIEM rules. "
        "Input should be a specific search query like 'MFA fatigue detection' or 'APT29 mitigations'. "
        "Returns source collection, object type, name, match score, and matching source text."
    )

    def _run(self, query: str) -> str:
        return threat_intel_database_search(query)
