"""
Direct vector similarity search across MITRE ATT&CK ChromaDB collections.
Bypasses LLM entirely to prove retrieval capabilities.
"""
import sys
import chromadb
from sentence_transformers import SentenceTransformer

# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------
print("Loading Embedding Model (BAAI/bge-base-en-v1.5)...")
model = SentenceTransformer("BAAI/bge-base-en-v1.5")

print("Connecting to local ChromaDB...")
client = chromadb.PersistentClient(path="./chroma_db")

collections_map = {
    "attack": "attack_db",
    "redteam": "redteam_db",
    "actor": "actor_db",
    "detect": "detection_db",
}

def print_help():
    print("\nAvailable commands:")
    print("  search <query>       → search all collections")
    print("  attack <query>       → search attack_db")
    print("  redteam <query>      → search redteam_db")
    print("  actor <query>        → search actor_db")
    print("  detect <query>       → search detection_db")
    print("  help                 → show commands")
    print("  exit                 → quit\n")

def do_search(targets, query_text):
    query_embedding = model.encode(query_text, show_progress_bar=False).tolist()
    
    results_found = False
    
    for name in targets:
        try:
            coll = client.get_collection(name)
            results = coll.query(
                query_embeddings=[query_embedding],
                n_results=3
            )
            
            docs = results['documents'][0]
            metas = results['metadatas'][0]
            distances = results['distances'][0]
            
            if docs:
                results_found = True
                print(f"\n{'=' * 20} Results from {coll.name} {'=' * 20}")
                for i in range(len(docs)):
                    meta = metas[i]
                    obj_type = meta.get("type", "unknown")
                    name_meta = meta.get("name", "unknown")
                    mitre_id = meta.get("mitre_id", "")
                    
                    id_str = f" [{mitre_id}]" if mitre_id else ""
                    print(f"\n[{i+1}] Distance Score: {distances[i]:.4f}")
                    print(f"    Type: {obj_type}")
                    print(f"    Name: {name_meta}{id_str}")
                    
                    doc_snippet = docs[i].strip()
                    if len(doc_snippet) > 800:
                        doc_snippet = doc_snippet[:800] + "...\n[TRUNCATED]"
                        
                    print(f"\n{doc_snippet}")
                    print("-" * 60)
                    
        except Exception as e:
            print(f"⚠ Could not query {name}: {e}. (Did you run ingest.py?)")
            
    if not results_found:
        print("\nNo results found.")

def main():
    print("\n🛡️  NeuralSec Direct DB Search (No LLM)")
    print_help()
    
    while True:
        try:
            user_input = input("\nquery> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
            
        if not user_input:
            continue
            
        parts = user_input.split(" ", 1)
        cmd = parts[0].lower()
        query = parts[1] if len(parts) > 1 else ""
        
        if cmd == "exit" or cmd == "quit":
            break
        elif cmd == "help":
            print_help()
        elif cmd == "search":
            if not query:
                print("Usage: search <query>")
                continue
            do_search(list(collections_map.values()), query)
        elif cmd in collections_map:
            if not query:
                print(f"Usage: {cmd} <query>")
                continue
            do_search([collections_map[cmd]], query)
        else:
            print(f"Unknown command: {cmd}")
            print_help()

if __name__ == "__main__":
    main()
