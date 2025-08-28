# run.py
import os
from web.app import app
from web.db import init_db, reset_db

if __name__ == "__main__":
    # Only wipe tables if you explicitly opt in
    do_reset = os.getenv("RESET_DB") == "1"
    with app.app_context():
        if do_reset:
            print("🔄 RESET_DB=1 → dropping tables and recreating schema")
            reset_db()        # your helper that drops tables
        init_db()              # always ensure schema exists (creates if missing)

    # Windows-friendly (avoids file locks from the reloader)
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
