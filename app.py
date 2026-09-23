from flask import Flask, render_template

from config import Config
from db import db, init_db

app = Flask(__name__)
app.config.from_object(Config)
init_db(app)

import models  # noqa: E402  (registers Scan/Finding on db.metadata before create_all)

with app.app_context():
    db.create_all()


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
