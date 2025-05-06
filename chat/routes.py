from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from .service import ask_openai, get_last_sessions

chat_bp = Blueprint('chat', __name__)

@chat_bp.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json() or {}
    msg = data.get("message", "").strip()
    if not msg:
        return jsonify({"error": "No message"}), 400

    context = get_last_sessions(current_user.id)
    answer = ask_openai(msg, context=context)
    return jsonify({"response": answer})

@chat_bp.route("/chat/analyze", methods=["POST"])
@login_required
def analyze_sessions():
    sessions = get_last_sessions(current_user.id)
    if not sessions:
        return jsonify({"response": "No completed sessions to analyze."})
    prompt = "Please analyze the following Pomodoro sessions and give me feedback on what I might be doing wrong or how to improve:\n\n"
    prompt += "\n".join(sessions)
    feedback = ask_openai(prompt)
    return jsonify({"response": feedback})
