# AI Threat Intelligence & Red Team Platform

A pure CLI-based, local AI cybersecurity assistant using Qwen (via OpenRouter), ChromaDB, and MITRE ATT&CK STIX data.

## Setup Instructions

1. **Create virtual environment:**
   ```bash
   python -m venv venv
   ```

2. **Activate it on Windows:**
   ```cmd
   venv\Scripts\activate
   ```
   **Activate it on Linux/macOS:**
   ```bash
   source venv/bin/activate
   ```

3. **Install packages:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create `.env` file:**
   Create a `.env` file in the root directory and add your OpenRouter configuration:
   ```text
   OPENROUTER_API_KEY=PASTE_YOUR_NEW_OPENROUTER_KEY_HERE
   OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
   QWEN_MODEL=qwen/qwen3.5-flash
   ```

5. **Test Qwen API Connection:**
   ```bash
   python test_qwen.py
   ```

6. **Ingest MITRE ATT&CK Data:**
   *(Ensure you have cloned `https://github.com/mitre/cti.git` into the `cti/` folder first)*
   ```bash
   python ingest.py
   ```

7. **Test Direct Vector Search (No LLM):**
   ```bash
   python search_db.py
   ```

8. **Run AI Agents (CLI):**
   ```bash
   python interactive.py
   ```
