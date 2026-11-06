"""PART A — SOC agent without a framework: openai SDK + hand-written agent loop."""
import inspect
import json

from openai import OpenAI

from soc import tools
from soc.config import LMSTUDIO_URL, MAX_STEPS, MODEL_NAME
from soc.prompts import SYSTEM_PROMPT

client = OpenAI(base_url=LMSTUDIO_URL, api_key="lm-studio")


# ------------------------------------------------------------------------
# 1. Build the JSON schemas automatically from the core functions
# ------------------------------------------------------------------------
JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def schema_from_function(fn) -> dict:
    signature = inspect.signature(fn)
    properties, required = {}, []
    for name, param in signature.parameters.items():
        properties[name] = {"type": JSON_TYPES.get(param.annotation, "string")}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return {
        "type": "function",
        "function": {
            "name": fn.__name__,
            "description": inspect.getdoc(fn) or "",
            "parameters": {"type": "object", "properties": properties, "required": required},
        },
    }


SCHEMAS = [schema_from_function(f) for f in tools.TOOLS]     # what the model SEES
FUNCTIONS = {f.__name__: f for f in tools.TOOLS}             # what the code EXECUTES


# ------------------------------------------------------------------------
# 2. Execute a single tool call
# ------------------------------------------------------------------------
def run_tool(name: str, arguments_json: str) -> str:
    function = FUNCTIONS.get(name)
    if function is None:
        return f"Error: tool '{name}' does not exist."
    try:
        arguments = json.loads(arguments_json or "{}")
        return str(function(**arguments))
    except Exception as e:
        return f"Error while running '{name}': {e}"


# ------------------------------------------------------------------------
# 3. The agent loop
# ------------------------------------------------------------------------
def run_agent(messages: list) -> str:
    for _ in range(MAX_STEPS):
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            tools=SCHEMAS,
            temperature=0,
        )
        msg = response.choices[0].message
        messages.append(msg.model_dump(exclude_none=True))

        if not msg.tool_calls:
            return msg.content or ""

        for call in msg.tool_calls:
            name = call.function.name
            arguments = call.function.arguments
            print(f"  🔧 {name}({arguments})")
            result = run_tool(name, arguments)
            print(f"  ↳ {result[:150]}")
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": result,
            })

    return "Stopped: maximum number of steps reached."


# ------------------------------------------------------------------------
# 4. Terminal interface
# ------------------------------------------------------------------------
def main():
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    print(f"SOC Agent [no framework] — model: {MODEL_NAME}")
    print("Try: 'Fai il triage dei log di stanotte'. ('exit' to quit)\n")

    while True:
        question = input("👤 Analyst: ").strip()
        if question.lower() in ("exit", "quit", "esci"):
            break
        if not question:
            continue
        messages.append({"role": "user", "content": question})
        print(f"\n🤖 Agent:\n{run_agent(messages)}\n")


if __name__ == "__main__":
    main()