from app import app
from waitress import serve
import os

serve(app, port=5000)