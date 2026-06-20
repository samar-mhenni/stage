"""
RAG-based agents using Qwen 3 32B via OpenAI-compatible API.
"""
import os
import chromadb
from sentence_transformers import SentenceTransformer
from openai import OpenAI

# ---------------------------------------------------------------------------
# OpenAI (OpenRouter) configuration
# ---------------------------------------------------------------------------
api_key = os.getenv("OPENROUTER_API_KEY", "EMPTY")
base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
model_name = os.getenv("QWEN_MODEL", "qwen/qwen3.5-flash")

# ---------------------------------------------------------------------------
# Shared embedding model
# ---------------------------------------------------------------------------
print("Loading embedding model...")
_embedding_model = SentenceTransformer("BAAI/bge-base-en-v1.5")
print("Embedding model ready.")


class BaseAgent:
    """RAG agent that retrieves context from ChromaDB and generates answers
    with Qwen 3 32B via OpenAI client."""

    def __init__(self, top_k: int = 10):
        self.embed_model = _embedding_model
        self.top_k = top_k
        self.db_client = chromadb.PersistentClient(path="./chroma_db")
        self.llm_client = OpenAI(api_key=api_key, base_url=base_url)

    def retrieve_context(self, query: str, collections: list, top_k: int | None = None):
        """Retrieve relevant context from ChromaDB collections."""
        top_k = top_k or self.top_k
        query_embedding = self.embed_model.encode(query).tolist()

        context_blocks = []
        sources_used = []
        
        for coll_name in collections:
            try:
                coll = self.db_client.get_collection(coll_name)
                results = coll.query(query_embeddings=[query_embedding], n_results=top_k)
                for idx, doc in enumerate(results["documents"][0]):
                    meta = results["metadatas"][0][idx]
                    dist = results["distances"][0][idx]
                    
                    obj_type = meta.get("type", "")
                    name = meta.get("name", "")
                    
                    header = f"[Collection: {coll_name} | Type: {obj_type} | Name: {name} | Distance: {dist:.4f}]"
                    context_blocks.append(f"{header}\n{doc}")
                    
                    sources_used.append({
                        "collection": coll_name,
                        "distance": dist,
                        "name": name
                    })
            except Exception as e:
                print(f"⚠ Could not query {coll_name}: {e}")

        context_text = "\n\n---\n\n".join(context_blocks) if context_blocks else "No relevant context found."
        return context_text, sources_used

    def generate(self, user_prompt: str, context: str, system_prompt: str) -> str:
        full_prompt = (
            f"### Retrieved Context from Local Knowledge Base\n{context}\n\n"
            f"### User Question\n{user_prompt}\n\n"
            f"### Instructions\n"
            f"Answer the user's question based ONLY on the provided context."
        )
        try:
            response = self.llm_client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating response: {e}"


class RedTeamAgent(BaseAgent):
    """Red Team Agent: adversary simulation and operational procedures."""

    SYSTEM_PROMPT = (
        "You are an expert red-team adversary simulation specialist based on MITRE ATT&CK. "
        "Your role is to explain operational red team knowledge. "
        "You answer questions about adversary simulation, sub-technique lookup, tool mapping, "
        "kill chain generation, procedure examples, and how attackers perform actions from a high-level educational perspective. "
        "\n\nSafety rules:\n"
        "- Keep everything educational and defensive.\n"
        "- Do not provide real exploit code.\n"
        "- Do not provide credential theft instructions.\n"
        "- Do not provide destructive commands.\n"
        "- Do not provide malware deployment steps.\n"
        "- Explain attacker behavior at a conceptual MITRE ATT&CK level.\n"
        "- Always include defender observations when possible.\n"
        "Generate answers grounded ONLY in the retrieved context."
    )

    def analyze(self, query: str):
        collections = ["redteam_db", "attack_db", "actor_db"]
        context, sources = self.retrieve_context(query, collections=collections, top_k=5)
        response = self.generate(query, context, self.SYSTEM_PROMPT)
        return response, sources


class ThreatIntelAgent(BaseAgent):
    """Threat Intelligence Agent: defensive CTI analysis."""

    SYSTEM_PROMPT = (
        "You are an expert Threat Intelligence Agent focusing on defensive CTI analysis based on MITRE ATT&CK. "
        "You answer questions about technique definition, tactic mapping, detection guidance, "
        "mitigation overview, healthcare context framing, attribution scoring, TTP overlap matching, "
        "tool fingerprinting, campaign correlation, healthcare sector filtering, SIEM query guidance, "
        "data source recommendations, detection logic per technique, mitigation mapping, and response action recommendations. "
        "\n\nHallucination control:\n"
        "- If the retrieved context does not contain enough information, you MUST say exactly: "
        "'I could not find enough reliable information in the local knowledge base.'\n"
        "- If the user asks about a fake MITRE ID like T9999, do not invent an answer.\n"
        "- Clearly separate confirmed information from assumptions.\n"
        "Generate answers grounded ONLY in the retrieved context."
    )

    def analyze(self, query: str):
        collections = ["detection_db", "attack_db", "actor_db"]
        context, sources = self.retrieve_context(query, collections=collections, top_k=5)
        response = self.generate(query, context, self.SYSTEM_PROMPT)
        return response, sources
