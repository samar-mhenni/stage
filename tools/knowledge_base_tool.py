from crewai.tools import BaseTool
from tools.registry import ToolRegistry
import chromadb
import json
from sentence_transformers import SentenceTransformer
import logging
import re
from config.settings import settings
import tools.exploitdb_tool  # Ensure tool is registered
from tools.exploitdb_tool import search_exploit_db

# Suppress sentence_transformers logging if needed
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

# Load embedding model once per module load
_embedding_model = SentenceTransformer("BAAI/bge-base-en-v1.5")
_db_client = chromadb.PersistentClient(path=settings.CHROMADB_PATH)
MAX_CONTEXT_CHARS = 700

def _extract_mitre_id(text: str) -> str:
    match = re.search(r"\[(T\d{4}(?:\.\d{3})?)\]", text)
    return match.group(1) if match else ""

def _normalize_doc(doc: str) -> str:
    doc_text = str(doc)
    if len(doc_text) > MAX_CONTEXT_CHARS:
        return f"{doc_text[:MAX_CONTEXT_CHARS].rstrip()}..."
    return doc_text

def _distance_to_match_score(distance: float) -> float:
    """Convert Chroma distance to a high-is-better match score for reporting."""
    return 1 / (1 + (distance / 2))

def _format_record(record: dict) -> str:
    header = (
        f"[Source: {record['source']} | Type: {record['type']} | "
        f"Name: {record['name']}{record.get('cve_str', '')} | Match: {record['match']:.4f}]"
    )
    return f"{header}\n{record['text']}"

def _is_exploit_query(query: str) -> bool:
    return bool(re.search(r"CVE-\d{4}-\d{4,}", query, flags=re.IGNORECASE)) or any(
        keyword in query.lower()
        for keyword in ("exploit", "vulnerability", "rce", "remote code execution", "privilege escalation")
    )

@ToolRegistry.register("knowledge_base_tool")
class KnowledgeBaseTool(BaseTool):
    name: str = "Universal Knowledge Base Search"
    description: str = (
        "Search the entire Cybersecurity Knowledge Base (Attack, Actor, Detection, and Exploit databases). "
        "Receives a query, generates embeddings, and retrieves ranked context and metadata. "
        "Input should be a specific search query like 'Credential Dumping', 'Ryuk ransomware', or 'CVE-2021-44228'."
    )

    def _run(self, query: str) -> str:
        """Execute the search across all collections."""
        collections = ["attack_db", "actor_db", "detection_db", "exploit_db"]
        top_k = 3
        
        query_embedding = _embedding_model.encode(query, show_progress_bar=False).tolist()
        records = []

        for coll_name in collections:
            try:
                coll = _db_client.get_collection(coll_name)
                results = coll.query(query_embeddings=[query_embedding], n_results=top_k)
                for idx, doc in enumerate(results["documents"][0]):
                    meta = results["metadatas"][0][idx]
                    obj_type = meta.get("type", "unknown")
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
                # Collection might not exist or be empty
                pass

        if not records:
            return "No relevant context found in the knowledge base."
        
        # Sort globally by match score descending to rank results
        records.sort(key=lambda r: r['match'], reverse=True)

        formatted_records = [_format_record(record) for record in records]

        if _is_exploit_query(query):
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", query, flags=re.IGNORECASE)
            exploit_results = search_exploit_db(
                cve=cve_match.group(0) if cve_match else None,
                query=query,
                limit=5,
            )
            if exploit_results:
                formatted_records.append(
                    "[Source: exploit_db | Type: structured_exploit_results]\n"
                    + json.dumps(exploit_results, indent=2)
                )

        return "\n\n---\n\n".join(formatted_records)
