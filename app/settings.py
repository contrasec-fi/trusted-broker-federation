import os

# Environment Variables

PROVIDER_CLIENT_ID = os.environ.get('PROVIDER_CLIENT_ID', 'EU.EORI.PROVIDER')
CONSUMER_CLIENT_ID = os.environ.get('CONSUMER_CLIENT_ID', 'EU.EORI.CONSUMER')
CONSUMER_EMAIL = os.environ.get('EMAIL', 'johndoe@example.com')

KEYROCK_URL= os.environ.get('KEYROCK_URL', 'http://127.0.0.1:3000')
KEYROCK_AUTHZ_URL = KEYROCK_URL + '/oauth2/authorize?'
KEYROCK_TOKEN_URL = KEYROCK_URL + '/oauth2/token'

APP_URL = os.environ.get('APP_URL', 'http://127.0.0.1:5000')
AUTH_APP_URL = APP_URL + '/auth'
SCORPIO_URL = os.environ.get('SCORPIO_URL', 'http://127.0.0.1:9090')

PRIVATE_KEY = os.environ.get('PRIVATE_KEY', 'private_key')
X5C_VALUE = os.environ.get('X5C_VALUE', 'x5c_value')

PRIVATE_KEY_FILE = "/keys/secrets/{}".format(os.environ.get("PRIVATE_KEY_FILE", "private.key"))
X5C_VALUE_FILE = "/keys/secrets/{}".format(os.environ.get("X5C_VALUE_FILE", "x5c.value"))

if os.path.isfile(PRIVATE_KEY_FILE):
    with open(PRIVATE_KEY_FILE, "r") as PRIVATE_KEY_FILE:
        PRIVATE_KEY = PRIVATE_KEY_FILE.read()

if os.path.isfile(X5C_VALUE_FILE):
    with open(X5C_VALUE_FILE, "r") as X5C_VALUE_FILE:
        X5C_VALUE = X5C_VALUE_FILE.read().splitlines()
