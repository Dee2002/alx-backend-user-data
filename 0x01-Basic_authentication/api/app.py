from flask import Flask, jsonify, abort

app = Flask(__name__)

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized"}), 401

# Add your routes and other error handlers here

if __name__ == "__main__":
    app.run(host=os.getenv('API_HOST', '0.0.0.0'), port=int(os.getenv('API_PORT', 5000)))
