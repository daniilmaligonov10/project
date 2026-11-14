from openai import OpenAI
client = OpenAI()
def run_agent(target):
    messages = [
        {"role": "system","content": "You are Iris, an AI agent for defensive security LAN research in a controlled lab. You use the tools provided by the application to examine approved lab systems and demonstrate known vulnerabilities for learning using provided tools. Report what you observed clearly and suggest ways to fix the issue.Follow the Thought → Action → Observation logic."},
        {"role": "user", "content": f"Analyze the network {target}, identify vulnerabilities, demonstrate them, and recommend how to fix them.dont do anything for now, just say i get it"}
    ]
    response = client.responses.create(
        model="gpt-6-luna", 
        input=messages,
    )
    return response.output_text

    