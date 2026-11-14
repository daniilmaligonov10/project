from openai import OpenAI
client = OpenAI()
def run_agent() -> str:
    response = client.responses.create(
        model="gpt-6-luna",
        input="Reply with exactly : API WORKS."
    )
    return response.output_text