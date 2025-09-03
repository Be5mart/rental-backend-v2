from app import app

# Gunicorn entrypoint
# Usage in Procfile:
#   web: gunicorn wsgi:app --workers 2 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT
