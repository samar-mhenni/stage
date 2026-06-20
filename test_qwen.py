from openai import OpenAI
from dotenv import load_dotenv
import os

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENROUTER_API_KEY"),
    base_url=os.getenv("OPENROUTER_BASE_URL")
)

response = client.chat.completions.create(
    model=os.getenv("QWEN_MODEL"),
    messages=[
        {"role": "user", "content": "Say hello and confirm you are working."}
    ]
)

print(response.choices[0].message.content)
