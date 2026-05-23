from flask import Flask, request, jsonify
from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
api_key = os.environ.get("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini AI Assistant</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0e1117; color: #fff; }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; padding: 20px 0; }
        .header h1 { font-size: 34px; margin-bottom: 8px; }
        .header p { color: #9ca3af; font-size: 15px; }
        .chat-box { background: #1f2937; border-radius: 12px; padding: 20px; height: 500px; overflow-y: auto; margin: 20px 0; }
        .message { margin: 15px 0; padding: 12px 16px; border-radius: 12px; }
        .user { background: #1f2937; text-align: right; }
        .bot { background: #111827; }
        .input-area { display: flex; gap: 10px; }
        input { flex: 1; padding: 12px; border-radius: 8px; border: 1px solid #374151; background: #1f2937; color: #fff; font-size: 16px; }
        button { padding: 12px 24px; border-radius: 8px; border: none; background: #3b82f6; color: #fff; cursor: pointer; font-size: 16px; }
        button:hover { background: #2563eb; }
        .footer { text-align: center; color: #9ca3af; font-size: 14px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 Gemini AI Assistant</h1>
            <p>Your calm, reliable AI companion for questions and ideas</p>
        </div>
        <div class="chat-box" id="chatBox">
            <div class="message bot">Hello 👋 I'm Gemini AI. Ask me anything — I'm here to help.</div>
        </div>
        <div class="input-area">
            <input type="text" id="userInput" placeholder="Type your message and press Enter..." />
            <button onclick="sendMessage()">Send</button>
        </div>
        <div class="footer">🚀 Built using Flask & Gemini API • Academic Demo Project</div>
    </div>
    <script>
        const chatBox = document.getElementById('chatBox');
        const userInput = document.getElementById('userInput');

        userInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });

        async function sendMessage() {
            const message = userInput.value.trim();
            if (!message) return;

            chatBox.innerHTML += `<div class="message user">${message}</div>`;
            userInput.value = '';
            chatBox.scrollTop = chatBox.scrollHeight;

            try {
                const response = await fetch('/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message })
                });
                const data = await response.json();
                chatBox.innerHTML += `<div class="message bot">${data.response || data.error}</div>`;
            } catch (error) {
                chatBox.innerHTML += `<div class="message bot">⚠️ Error: ${error.message}</div>`;
            }
            chatBox.scrollTop = chatBox.scrollHeight;
        }
    </script>
</body>
</html>"""

@app.route('/')
def home():
    return HTML

@app.route('/chat', methods=['POST'])
def chat():
    try:
        user_input = request.json.get('message')
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=user_input
        )
        return jsonify({'response': response.text})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
