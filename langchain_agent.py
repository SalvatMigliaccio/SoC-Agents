"""PART B — SOC agent with LangChain (create_agent running on LangGraph)."""
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import InMemorySaver

from soc import tools
from soc.config import LMSTUDIO_URL, MAX_STEPS, MODEL_NAME
from soc.prompts import SYSTEM_PROMPT

# 1. Same core functions, wrapped as LangChain tools
TOOLS = [tool(f) for f in tools.TOOLS]

# 2. The model: LM Studio through its OpenAI-compatible API
model = ChatOpenAI(
    base_url=LMSTUDIO_URL,
    api_key="lm-studio",
    model=MODEL_NAME,
    temperature=0,
)

# 3. The agent: model <-> tools loop + memory
agent = create_agent(
    model=model,
    tools=TOOLS,
    system_prompt=SYSTEM_PROMPT,
    checkpointer=InMemorySaver(),
)


# 4. Print each step
def print_message(msg):
    if msg.type == "ai":
        for call in msg.tool_calls:
            print(f"  🔧 {call['name']}({call['args']})")
        if msg.content and not msg.tool_calls:
            print(f"\n🤖 Agent:\n{msg.content}\n")
    elif msg.type == "tool":
        print(f"  ↳ {str(msg.content)[:150]}")


# 5. Terminal interface
def main():
    run_config = {
        "configurable": {"thread_id": "night-shift-1"},
        "recursion_limit": MAX_STEPS * 2,
    }
    print(f"SOC Agent [LangChain] — model: {MODEL_NAME}")
    print("Try: 'Fai il triage dei log di stanotte'. ('exit' to quit)\n")

    while True:
        question = input("👤 Analyst: ").strip()
        if question.lower() in ("exit", "quit", "esci"):
            break
        if not question:
            continue
        for event in agent.stream(
            {"messages": [{"role": "user", "content": question}]},
            run_config,
            stream_mode="updates",
        ):
            for update in event.values():
                if isinstance(update, dict):
                    for msg in update.get("messages", []):
                        print_message(msg)


if __name__ == "__main__":
    main()