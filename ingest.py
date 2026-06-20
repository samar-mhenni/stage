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

# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------
print("Loading Embedding Model (BAAI/bge-base-en-v1.5)...")
model = SentenceTransformer("BAAI/bge-base-en-v1.5")

print("Initializing ChromaDB...")
client = chromadb.PersistentClient(path="./chroma_db")

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

# ---------------------------------------------------------------------------
# 2. Load the consolidated STIX bundle
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 3. Build enriched documents for each object type
# ---------------------------------------------------------------------------
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
    # Using a composite ID so we can put the same object in multiple DBs if needed
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
        # Red team also needs operational procedures (techniques)
        text_red = build_document(obj, max_rels=20) # More relationship context for procedures
        add_to_db("redteam_db", obj_id, obj_type, text_red, mitre_id, name)
        seen_ids.add(obj_id)

    elif obj_type in ("malware", "tool"):
        text = build_document(obj, max_rels=15)
        add_to_db("actor_db", obj_id, obj_type, text, mitre_id, name)
        # Red team also needs tools and malware
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


# ---------------------------------------------------------------------------
# 4. Batch embed and index
# ---------------------------------------------------------------------------
BATCH_SIZE = 64

def embed_and_store(collection, label, db_name):
    docs = docs_map[db_name]["docs"]
    ids = docs_map[db_name]["ids"]
    metas = docs_map[db_name]["metas"]
    
    if not docs:
        print(f"No documents for {label}")
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

print("\n✅ Ingestion complete!")
