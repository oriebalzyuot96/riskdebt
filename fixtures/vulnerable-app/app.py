import hashlib
from flask import Flask

app = Flask(__name__)
digest = hashlib.md5(b"x").hexdigest()
app.run(debug=True)
