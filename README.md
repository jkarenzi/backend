# backend
-clone the repo: git clone https://github.com/jkarenzi/backend

-set up the following environment variables in a .env file in the root of the project.

MAIL_USERNAME(gmail credentials)
MAIL_PASSWORD(gmail credentials)
SECRET_KEY(key used for signing jwt tokens)
USERNAME(mongodb username)
PASSWORD(mongodb password)
API_KEY(key used for ip geolocation on ipinfo website)

-set up CORS(set up the domains that are allowed to make requests to this server by updating the origins section of this line of code: 
cors = CORS(app, resources={r"/*": {"origins": ['http://localhost:3000']}}))

-running the local server:

export FLASK_APP=backend.py
flask run
