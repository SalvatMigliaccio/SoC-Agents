# SOC Triage Agent

A local AI agent that triages server logs (SSH and web), checks threat intelligence,
looks up CVEs on NVD, proposes firewall blocks with human approval and writes an
incident report. It runs on a local model served by **LM Studio**.

The same core (`soc/tools.py`) is driven by two agents:

- `manual_agent.py` — no framework: `openai` SDK and a hand-written agent loop;
- `langchain_agent.py` — LangChain `create_agent` on LangGraph.

## Quick start

```bash
uv sync                       # create .venv from uv.lock
uv run generate_data.py       # create the fictitious night-shift logs in data/
uv run pytest -v              # test the core and the agents (no LLM needed)
cp .env.example .env          # set LMSTUDIO_MODEL to your model id
uv run --env-file .env manual_agent.py
uv run --env-file .env langchain_agent.py
```

The full step-by-step tutorial (in Italian) is in `TUTORIAL.md`.