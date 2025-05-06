import openai
import os
from dotenv import load_dotenv
# Hard-coded API key (pre dev/testing)
load_dotenv()
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a Pomodoro productivity assistant. Your role is to:

Offer concise, practical time management tips

Help users analyze and reflect on their Pomodoro session data

Encourage focus and consistency without being overbearing
Maintain a calm, confident, and professional tone. Be helpful and respectful of the user’s attention span — no filler, no pressure.

"""

def ask_openai(user_message: str, context: list[str] = None) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if context:
        messages += [{"role": "assistant", "content": c} for c in context]
    messages.append({"role": "user", "content": user_message})

    # --- NOVÉ volanie ---
    response = client.chat.completions.create(
        model="gpt-4",
        messages=messages,
        max_tokens=200,
        temperature=0.7,
    )
    return response.choices[0].message.content.strip()

def get_last_sessions(user_id: int) -> list[str]:
    from models import Session
    sessions = (
        Session.query
        .filter(Session.user_id == user_id, Session.ended_at.isnot(None))
        .order_by(Session.ended_at.desc())
        .limit(3)
        .all()
    )
    return [
        f"Session {s.id}: Note: {s.note}, Duration: {s.ended_at - s.started_at}"
        for s in sessions
    ]
