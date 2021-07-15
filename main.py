from flask import Flask
from flask_restful import Api

from controllers.spoof_check_api import SpoofCheck

app = Flask(__name__)
api = Api(app)

api.add_resource(SpoofCheck, "/v2/spoofCheck")

if __name__ == "__main__":
    app.run()
