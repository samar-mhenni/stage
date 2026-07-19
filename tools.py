"""Reusable local tool functions for search and authorized hash cracking."""
import chromadb
from sentence_transformers import SentenceTransformer
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# Suppress sentence_transformers logging if needed
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

_embedding_model = None
_db_client = None
MAX_CONTEXT_CHARS = 1800


def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        _embedding_model = SentenceTransformer("BAAI/bge-base-en-v1.5")
    return _embedding_model


def _get_db_client():
    global _db_client
    if _db_client is None:
        _db_client = chromadb.PersistentClient(path="./chroma_db")
    return _db_client


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


def _record_from_doc(coll_name: str, doc: str, meta: dict, match: float = 1.0, distance: float = 0.0) -> dict:
    obj_type = meta.get("type", "unknown")
    name = meta.get("name", "unknown")
    doc_text = _normalize_doc(doc)
    cve = meta.get("cve", "")
    cve_str = f" | CVE: {cve}" if cve else ""
    return {
        "source": coll_name,
        "type": obj_type,
        "name": name,
        "match": match,
        "distance": distance,
        "text": doc_text,
        "mitre_id": meta.get("mitre_id") or _extract_mitre_id(doc_text),
        "cve_str": cve_str,
    }


def get_records_by_metadata(collection: str, field: str, values: set[str] | list[str]) -> list[dict]:
    """Return exact metadata matches without embedding search."""
    records = []
    try:
        coll = _get_db_client().get_collection(collection)
    except Exception:
        return records
    for value in values:
        try:
            results = coll.get(where={field: str(value)}, include=["documents", "metadatas"])
        except Exception:
            continue
        for doc, meta in zip(results.get("documents", []), results.get("metadatas", [])):
            records.append(_record_from_doc(collection, doc, meta, match=1.0, distance=0.0))
    return records


def search_records(
    query: str,
    collections: list,
    top_k: int = 3,
    type_filters: dict[str, set[str]] | None = None,
) -> list[dict]:
    """Return structured vector search records for deterministic filtering."""
    query_embedding = _get_embedding_model().encode(query, show_progress_bar=False).tolist()
    records = []
    client = _get_db_client()

    for coll_name in collections:
        try:
            coll = client.get_collection(coll_name)
            results = coll.query(query_embeddings=[query_embedding], n_results=top_k)
            for idx, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][idx]
                obj_type = meta.get("type", "unknown")
                if type_filters and coll_name in type_filters and obj_type not in type_filters[coll_name]:
                    continue
                distance = float(results["distances"][0][idx])
                records.append(
                    _record_from_doc(
                        coll_name,
                        doc,
                        meta,
                        match=_distance_to_match_score(distance),
                        distance=distance,
                    )
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
        return ["exploit_db", "threat_intel_db", "redteam_db", "attack_db", "actor_db"]
    return ["redteam_db", "threat_intel_db", "attack_db", "actor_db", "exploit_db"]


def red_team_database_search(query: str) -> str:
    """Search red-team relevant collections, prioritizing Exploit-DB if exploit-related keywords exist."""
    collections = _prioritize_exploit_db(query)
    return _search_collections(query, collections)


def threat_intel_database_search(query: str) -> str:
    """Search threat-intel relevant collections."""
    return _search_collections(
        query,
        ["threat_intel_db", "detection_db", "attack_db", "actor_db"],
        type_filters={"attack_db": {"attack-pattern"}},
    )


HASH_FORMAT_ALIASES = {
    "md5": "raw-md5",
    "raw-md5": "raw-md5",
    "sha1": "raw-sha1",
    "raw-sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "raw-sha256": "raw-sha256",
    "sha512": "raw-sha512",
    "raw-sha512": "raw-sha512",
    "ntlm": "nt",
    "nt": "nt",
    "bcrypt": "bcrypt",
    "md5crypt": "md5crypt",
}


def john_the_ripper_hash_crack(query: str) -> str:
    """Attempt to crack authorized hashes with local John the Ripper."""
    john = shutil.which("john")
    if not john:
        return "John the Ripper is not installed or is not on PATH."

    hashes, options = _parse_hash_crack_query(query)
    if not hashes:
        return "No hashes were provided."

    hash_format = _normalize_hash_format(options.get("format", "raw-md5"))
    if not hash_format:
        return "Unsupported hash format. Use one of: " + ", ".join(sorted(set(HASH_FORMAT_ALIASES.values())))

    timeout = _parse_hash_crack_timeout(options.get("timeout", "300"))
    wordlist = options.get("wordlist")
    if wordlist and not Path(wordlist).is_file():
        return f"Wordlist not found: {wordlist}"

    with tempfile.TemporaryDirectory(prefix="john_hash_crack_") as tmpdir:
        tmp = Path(tmpdir)
        hash_file = tmp / "hashes.txt"
        pot_file = tmp / "john.pot"
        labeled_hashes = {f"hash{idx}": hash_value for idx, hash_value in enumerate(hashes, start=1)}
        hash_file.write_text(
            "\n".join(f"{label}:{hash_value}" for label, hash_value in labeled_hashes.items()) + "\n",
            encoding="utf-8",
        )

        cmd = [john, f"--format={hash_format}", f"--pot={pot_file}"]
        if wordlist:
            cmd.append(f"--wordlist={wordlist}")
        cmd.append(str(hash_file))

        try:
            run = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return f"John timed out after {timeout} seconds before completing."

        show = subprocess.run(
            [john, "--show", f"--format={hash_format}", f"--pot={pot_file}", str(hash_file)],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    shown = _format_cracked_hashes(show.stdout, labeled_hashes)
    if shown:
        return shown

    details = (run.stderr or run.stdout or "").strip()
    if details:
        return f"No hashes cracked.\n\nJohn output:\n{details[-1200:]}"
    return "No hashes cracked."


def _parse_hash_crack_query(query: str) -> tuple[list[str], dict[str, str]]:
    hashes: list[str] = []
    options: dict[str, str] = {}
    for raw_line in str(query).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() in {"format", "wordlist", "timeout"}:
            options[key.strip().lower()] = value.strip()
        else:
            hashes.append(line)
    return hashes, options


def _normalize_hash_format(value: str) -> str:
    return HASH_FORMAT_ALIASES.get(value.strip().lower(), "")


def _parse_hash_crack_timeout(value: str) -> int:
    try:
        return max(1, min(int(value), 3600))
    except ValueError:
        return 300


def _format_cracked_hashes(john_show_output: str, labeled_hashes: dict[str, str]) -> str:
    cracked: list[str] = []
    for raw_line in john_show_output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "0 password", "1 password")):
            continue
        label, sep, plaintext = line.partition(":")
        if not sep or label not in labeled_hashes:
            continue
        cracked.append(f"{labeled_hashes[label]}: {plaintext}")
    return "\n".join(cracked)
