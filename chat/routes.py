from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from openai import OpenAI
from .service import ask_openai, get_last_sessions


chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

@chat_bp.route('/message', methods=['POST'])
@login_required
def chat_message():
    data = request.get_json() or {}
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'response': "🤖 Please say something."}), 200

    client = OpenAI(api_key=current_app.config.get('OPENAI_API_KEY'))
    resp = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are Pomodoro Bot."},
            {"role": "user",   "content": user_message}
        ]
    )
    return jsonify({'response': resp.choices[0].message.content}), 200

@chat_bp.route('/analyze', methods=['POST'])
@login_required
def analyze_sessions():
    sessions = get_last_sessions(current_user.id)
    if not sessions:
        return jsonify({"response": "No completed sessions to analyze."})

    prompt = ("Please analyze the following Pomodoro sessions and give me feedback on what I might be doing wrong or how to improve:\n\n" +
              "\n".join(sessions))
    feedback = ask_openai(prompt)
    return jsonify({"response": feedback}), 200
