"""
Ingest MITRE ATT&CK STIX data into ChromaDB vector collections for Qwen 3 32B.

Creates 4 databases: attack_db, redteam_db, actor_db, detection_db.
"""
import json
import os
from tqdm import tqdm
import chromadb
from sentence_transformers import SentenceTransformer
import pandas as pd

import requests
import io
import argparse

# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------
print("Loading Embedding Model (BAAI/bge-base-en-v1.5)...")
model = SentenceTransformer("BAAI/bge-base-en-v1.5")

print("Initializing ChromaDB...")
client = chromadb.PersistentClient(path="./chroma_db")

def ingest_mitre():
    print("\n--- Starting MITRE ATT&CK Ingestion ---")
    COLLECTIONS = ["attack_db", "redteam_db", "actor_db", "detection_db"]
    for name in COLLECTIONS:
        try:
            client.delete_collection(name)
        except Exception:
            pass

    attack_db = client.create_collection("attack_db")
    redteam_db = client.create_collection("redteam_db")
    actor_db = client.create_collection("actor_db")
    detection_db = client.create_collection("detection_db")

    # 2. Load the consolidated STIX bundle
    BUNDLE_PATH = "cti/enterprise-attack/enterprise-attack.json"
    print(f"Loading STIX bundle from {BUNDLE_PATH}...")
    with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])
    print(f"Total STIX objects in bundle: {len(objects)}")

    # Build lookup tables so we can enrich documents with relationship context
    obj_by_id = {}
    relationships = []
    for obj in objects:
        obj_by_id[obj.get("id", "")] = obj
        if obj.get("type") == "relationship":
            relationships.append(obj)

    # Build a mapping: object_id -> list of related descriptions
    related_context = {}
    for rel in relationships:
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        rel_type = rel.get("relationship_type", "related-to")
        desc = rel.get("description", "")

        src_obj = obj_by_id.get(src, {})
        tgt_obj = obj_by_id.get(tgt, {})
        src_name = src_obj.get("name", src)
        tgt_name = tgt_obj.get("name", tgt)

        if desc:
            rel_text = f"[Relationship] {src_name} {rel_type} {tgt_name}: {desc[:500]}"
        else:
            rel_text = f"[Relationship] {src_name} {rel_type} {tgt_name}"

        related_context.setdefault(src, []).append(rel_text)
        related_context.setdefault(tgt, []).append(rel_text)

    # 3. Build enriched documents for each object type
    docs_map = {
        "attack_db": {"docs": [], "ids": [], "metas": []},
        "redteam_db": {"docs": [], "ids": [], "metas": []},
        "actor_db": {"docs": [], "ids": [], "metas": []},
        "detection_db": {"docs": [], "ids": [], "metas": []},
    }

    seen_ids = set()

    def build_document(obj, max_rels=10):
        name = obj.get("name", "Unknown")
        desc = obj.get("description", "")
        obj_id = obj.get("id", "")
        obj_type = obj.get("type", "")

        aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])
        alias_str = f"\nAliases: {', '.join(aliases)}" if aliases else ""

        phases = obj.get("kill_chain_phases", [])
        phase_str = ""
        if phases:
            phase_names = [f"{p.get('kill_chain_name', 'mitre-attack')}:{p.get('phase_name', '')}" for p in phases]
            phase_str = f"\nKill Chain Phases: {', '.join(phase_names)}"

        ext_refs = obj.get("external_references", [])
        mitre_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                break
        id_str = f" [{mitre_id}]" if mitre_id else ""

        platforms = obj.get("x_mitre_platforms", [])
        platform_str = f"\nPlatforms: {', '.join(platforms)}" if platforms else ""

        text = f"Name: {name}{id_str}\nType: {obj_type}{alias_str}\nDescription: {desc}{phase_str}{platform_str}"

        rels = related_context.get(obj_id, [])
        if rels:
            text += "\n\nRelated context:\n" + "\n".join(rels[:max_rels])

        return text[:4000]

    def add_to_db(db_name, obj_id, obj_type, text, mitre_id, name):
        docs_map[db_name]["docs"].append(text)
        docs_map[db_name]["ids"].append(f"{db_name}_{obj_id}")
        docs_map[db_name]["metas"].append({
            "source": "mitre",
            "type": obj_type,
            "mitre_id": mitre_id,
            "name": name,
        })

    for obj in tqdm(objects, desc="Categorizing objects"):
        obj_id = obj.get("id", "")
        obj_type = obj.get("type", "")

        if obj_id in seen_ids:
            continue

        if "name" not in obj and "description" not in obj:
            continue

        mitre_id = next((r.get("external_id", "") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), "")
        name = obj.get("name", "")

        if obj_type == "attack-pattern":
            text = build_document(obj, max_rels=10)
            add_to_db("attack_db", obj_id, obj_type, text, mitre_id, name)
            text_red = build_document(obj, max_rels=20)
            add_to_db("redteam_db", obj_id, obj_type, text_red, mitre_id, name)
            seen_ids.add(obj_id)

        elif obj_type in ("malware", "tool"):
            text = build_document(obj, max_rels=15)
            add_to_db("actor_db", obj_id, obj_type, text, mitre_id, name)
            add_to_db("redteam_db", obj_id, obj_type, text, mitre_id, name)
            seen_ids.add(obj_id)
            
        elif obj_type in ("intrusion-set", "campaign"):
            text = build_document(obj, max_rels=15)
            add_to_db("actor_db", obj_id, obj_type, text, mitre_id, name)
            seen_ids.add(obj_id)

        elif obj_type in ("course-of-action", "x-mitre-analytic", "x-mitre-detection-strategy"):
            text = build_document(obj, max_rels=5)
            add_to_db("detection_db", obj_id, obj_type, text, mitre_id, name)
            seen_ids.add(obj_id)

    # 4. Batch embed and index MITRE
    BATCH_SIZE = 64

    def embed_and_store(collection, label, db_name):
        docs = docs_map[db_name]["docs"]
        ids = docs_map[db_name]["ids"]
        metas = docs_map[db_name]["metas"]
        
        if not docs:
            return
            
        print(f"\nEmbedding and indexing {label} ({len(docs)} docs)...")
        for i in tqdm(range(0, len(docs), BATCH_SIZE), desc=label):
            batch_docs = docs[i:i + BATCH_SIZE]
            batch_ids = ids[i:i + BATCH_SIZE]
            batch_metas = metas[i:i + BATCH_SIZE]
            embeddings = model.encode(batch_docs, show_progress_bar=False).tolist()
            collection.add(
                documents=batch_docs,
                embeddings=embeddings,
                ids=batch_ids,
                metadatas=batch_metas,
            )

    embed_and_store(attack_db, "Attack DB", "attack_db")
    embed_and_store(redteam_db, "Red Team DB", "redteam_db")
    embed_and_store(actor_db, "Actor DB", "actor_db")
    embed_and_store(detection_db, "Detection DB", "detection_db")
    print("✅ MITRE Ingestion complete!")


def ingest_exploit_db(limit=None):
    print("\n--- Starting Exploit-DB Ingestion ---")
    URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    
    try:
        client.delete_collection("exploit_db")
    except Exception:
        pass
    
    exploit_db = client.create_collection("exploit_db")

    print(f"Downloading Exploit-DB dataset from {URL}...")
    response = requests.get(URL)
    response.raise_for_status()
    
    df = pd.read_csv(io.StringIO(response.text))
    
    # Drop duplicates to prevent ChromaDB DuplicateIDError
    df = df.drop_duplicates(subset=['id'], keep='first')
    
    # We will format docs:
    # Exploit ID: XXXXX
    # Description: XXXXX
    # Platform: XXXXX
    # Type: XXXXX
    # Author: XXXXX
    # Published: XXXXX
    # Related CVE: XXXXX
    # File Path: XXXXX

    docs = []
    ids = []
    metas = []

    print(f"Total exploits found: {len(df)}")
    
    # Optional limit for faster testing
    if limit:
        df = df.tail(limit).reset_index(drop=True)
        print(f"Limiting ingestion to the {limit} most recent exploits.")

    for _, row in tqdm(df.iterrows(), total=len(df), desc="Parsing Exploit-DB"):
        ex_id = str(row.get("id", ""))
        desc = str(row.get("description", ""))
        platform = str(row.get("platform", ""))
        ex_type = str(row.get("type", ""))
        author = str(row.get("author", ""))
        cve = str(row.get("codes", "")) # ExploitDB stores CVEs in 'codes'
        published = str(row.get("date_published", ""))
        file_path = str(row.get("file", ""))

        # Clean NaN values
        cve = cve if cve.lower() != "nan" else "None"
        
        doc = (
            f"Exploit ID: {ex_id}\n"
            f"Description: {desc}\n"
            f"Platform: {platform}\n"
            f"Type: {ex_type}\n"
            f"Author: {author}\n"
            f"Published: {published}\n"
            f"Related CVE: {cve}\n"
            f"File Path: {file_path}"
        )
        
        docs.append(doc)
        ids.append(f"exploit_{ex_id}")
        metas.append({
            "source": "exploitdb",
            "type": "exploit",
            "exploit_id": ex_id,
            "platform": platform,
            "cve": cve,
            "name": desc[:50] # truncated name for display
        })

    BATCH_SIZE = 64
    print(f"\nEmbedding and indexing Exploit DB ({len(docs)} docs)...")
    for i in tqdm(range(0, len(docs), BATCH_SIZE), desc="Exploit DB"):
        batch_docs = docs[i:i + BATCH_SIZE]
        batch_ids = ids[i:i + BATCH_SIZE]
        batch_metas = metas[i:i + BATCH_SIZE]
        embeddings = model.encode(batch_docs, show_progress_bar=False).tolist()
        exploit_db.add(
            documents=batch_docs,
            embeddings=embeddings,
            ids=batch_ids,
            metadatas=batch_metas,
        )

    print("✅ Exploit-DB Ingestion complete!")


def ingest_web_attack_signatures(path: str = "threat_data/web_attack_signatures.json"):
    print("\n--- Starting Web Attack Signature Ingestion ---")
    if not os.path.isfile(path):
        print(f"Skipping missing file: {path}")
        return

    try:
        redteam_db = client.get_collection("redteam_db")
    except Exception:
        redteam_db = client.create_collection("redteam_db")

    with open(path, "r", encoding="utf-8") as handle:
        signatures = json.load(handle)

    docs = []
    ids = []
    metas = []
    for index, signature in enumerate(signatures):
        name = str(signature.get("name", f"web_signature_{index}"))
        terms = signature.get("terms", [])
        markers = signature.get("markers", [])
        version_patterns = signature.get("version_patterns", [])
        attack_notes = str(signature.get("attack_notes", ""))
        doc = (
            f"Name: {name}\n"
            "Type: web_app_signature\n"
            f"Terms: {', '.join(terms)}\n"
            f"Fingerprint markers: {', '.join(markers)}\n"
            f"Version extraction patterns: {', '.join(version_patterns)}\n"
            f"Validation guidance: {attack_notes}"
        )
        docs.append(doc[:4000])
        ids.append(f"web_app_signature_{index}_{name.lower().replace(' ', '_').replace('/', '_')}")
        metas.append(
            {
                "source": path,
                "type": "web_app_signature",
                "name": name,
                "terms_json": json.dumps(terms),
                "markers_json": json.dumps(markers),
                "version_patterns_json": json.dumps(version_patterns),
            }
        )

    if not docs:
        print("No web attack signatures found.")
        return

    embeddings = model.encode(docs, show_progress_bar=False).tolist()
    redteam_db.upsert(documents=docs, embeddings=embeddings, ids=ids, metadatas=metas)
    print(f"✅ Web Attack Signature Ingestion complete! ({len(docs)} signatures)")


def ingest_local_threat_data():
    print("\n--- Starting Local Threat Data Ingestion ---")
    data_files = [
        ("threat_data/1_otx_threat_intel.csv", "otx_pulse"),
        ("threat_data/2_cve_vulnerabilities.csv", "cve_vulnerability"),
        ("threat_data/3_malicious_domains.csv", "malicious_domain"),
        ("threat_data/4_malicious_ips.csv", "malicious_ip"),
        ("threat_data/5_validation_guidance.csv", "validation_guidance"),
    ]

    try:
        client.delete_collection("threat_intel_db")
    except Exception:
        pass
    threat_intel_db = client.create_collection("threat_intel_db")
    docs = []
    ids = []
    metas = []

    def clean_value(value) -> str:
        text = str(value)
        return "" if text.lower() == "nan" else text.strip()

    for csv_path, record_type in data_files:
        if not os.path.isfile(csv_path):
            print(f"Skipping missing file: {csv_path}")
            continue

        df = pd.read_csv(csv_path).fillna("")
        print(f"Parsing {csv_path} ({len(df)} rows)...")
        for index, row in df.iterrows():
            fields = {column: clean_value(row.get(column, "")) for column in df.columns}
            title = (
                fields.get("Title")
                or fields.get("cveID")
                or fields.get("Domain")
                or fields.get("IP")
                or f"{record_type}_{index}"
            )
            doc = "\n".join(f"{key}: {value}" for key, value in fields.items() if value)
            doc_id = f"{record_type}_{index}"
            docs.append(doc[:4000])
            ids.append(doc_id)
            metas.append(
                {
                    "source": csv_path,
                    "type": record_type,
                    "name": str(title)[:120],
                }
            )

    if not docs:
        print("No new local threat data rows found.")
        return

    BATCH_SIZE = 256
    print(f"\nEmbedding and indexing Local Threat Data ({len(docs)} docs)...")
    for i in tqdm(range(0, len(docs), BATCH_SIZE), desc="Local Threat Data"):
        batch_docs = docs[i:i + BATCH_SIZE]
        batch_ids = ids[i:i + BATCH_SIZE]
        batch_metas = metas[i:i + BATCH_SIZE]
        embeddings = model.encode(batch_docs, show_progress_bar=False).tolist()
        threat_intel_db.add(
            documents=batch_docs,
            embeddings=embeddings,
            ids=batch_ids,
            metadatas=batch_metas,
        )

    print("✅ Local Threat Data Ingestion complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest threat intelligence data into ChromaDB")
    parser.add_argument("--mitre", action="store_true", help="Ingest MITRE ATT&CK data")
    parser.add_argument("--exploitdb", action="store_true", help="Ingest Exploit-DB data")
    parser.add_argument("--local-threat-data", action="store_true", help="Ingest local CSVs from threat_data/")
    parser.add_argument("--web-signatures", action="store_true", help="Ingest web attack fingerprint signatures into redteam_db")
    parser.add_argument("--limit-exploits", type=int, default=None, help="Limit number of exploits ingested (for testing)")
    parser.add_argument("--all", action="store_true", help="Ingest all available datasets")
    
    args = parser.parse_args()
    
    if args.all or args.mitre:
        ingest_mitre()
        
    if args.all or args.exploitdb:
        ingest_exploit_db(limit=args.limit_exploits)

    if args.all or args.local_threat_data:
        ingest_local_threat_data()

    if args.all or args.mitre or args.web_signatures:
        ingest_web_attack_signatures()
        
    if not (args.all or args.mitre or args.exploitdb or args.local_threat_data or args.web_signatures):
        print("Please specify a dataset to ingest: --mitre, --exploitdb, --local-threat-data, --web-signatures, or --all")
