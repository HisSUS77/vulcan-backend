# server.py - additional patterns
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def unvalidated_redirect():
    url = request.args.get('next')
    return redirect(url)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save('/tmp/' + f.filename)
    return 'ok'

