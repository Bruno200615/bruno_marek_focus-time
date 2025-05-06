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
