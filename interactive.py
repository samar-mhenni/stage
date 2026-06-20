"""
Interactive CLI for the Qwen 3 32B Healthcare AI CTI Platform.
"""
import sys
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

from agents import RedTeamAgent, ThreatIntelAgent
from search_db import do_search, collections_map, print_help as search_help

def print_help():
    print("\nAvailable commands:")
    print("  red <question>       → Ask the Red Team Agent")
    print("  intel <question>     → Ask the Threat Intelligence Agent")
    print("  search <query>       → Run direct search across all collections")
    print("  attack <query>       → Search attack_db only")
    print("  redteam <query>      → Search redteam_db only")
    print("  actor <query>        → Search actor_db only")
    print("  detect <query>       → Search detection_db only")
    print("  help                 → Show commands")
    print("  exit                 → Quit\n")

def print_agent_response(question, response, sources):
    print("\n" + "="*60)
    print(f"QUESTION: {question}")
    print("="*60)
    print("\n[Thinking... generating response grounded in MITRE ATT&CK]\n")
    print(response)
    print("\n" + "-"*60)
    print("SOURCES USED:")
    if sources:
        # Sort by distance
        sources = sorted(sources, key=lambda x: x["distance"])
        # Deduplicate names for cleaner output
        seen_names = set()
        for src in sources:
            name = src["name"]
            if name not in seen_names:
                print(f"  - [{src['collection']}] {name} (distance: {src['distance']:.4f})")
                seen_names.add(name)
    else:
        print("  None")
    print("="*60 + "\n")

def main():
    print("Initializing Agents...")
    red_agent = RedTeamAgent()
    intel_agent = ThreatIntelAgent()
    
    print("\n🛡️  NeuralSec Qwen 3 32B Interactive CLI")
    print_help()
    
    while True:
        try:
            user_input = input("\nneural> ").strip()
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
            
        elif cmd == "red":
            if not query:
                print("Usage: red <question>")
                continue
            response, sources = red_agent.analyze(query)
            print_agent_response(query, response, sources)
            
        elif cmd == "intel":
            if not query:
                print("Usage: intel <question>")
                continue
            response, sources = intel_agent.analyze(query)
            print_agent_response(query, response, sources)
            
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


# ---------------------------------------------------------------------------
# Healthcare Test Scenarios for Validation
# ---------------------------------------------------------------------------
"""
Test 1 (Red Team Agent):
red Give me a full kill chain for a Ryuk attack on a hospital.

Test 2 (Threat Intelligence Agent):
intel What SIEM rules detect MFA fatigue attacks against hospital portals?

Test 3 (Hallucination Test):
intel What is T9999?

Test 4 (Complex Correlation):
intel A hospital SOC observed spearphishing emails, suspicious PowerShell commands, credential dumping attempts, and unusual SMB traffic between internal machines. Based on MITRE ATT&CK, identify the possible techniques involved, possible threat actors or malware families, and recommend detection and mitigation strategies.
"""
