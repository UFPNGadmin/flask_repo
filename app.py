from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/")
def index():
    return "Server is working!"

@app.route("/list-files", methods=["POST"])
def list_files():
    # Temporary placeholder
    zip_url = request.json.get("url")
    return jsonify({"status": "ok", "message": f"Would list files from {zip_url} here."})

if __name__ == "__main__":
    app.run(debug=True)
