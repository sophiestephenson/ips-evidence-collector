#!/usr/bin/env python3
"""
The mainfile of ISDi repo.
"""
import webbrowser
from threading import Timer

import config
from phone_scanner import db
from web import app, sa

PORT = 6200 if not (config.TEST or config.DEBUG) else 6202
HOST = "127.0.0.1" if config.DEBUG else "0.0.0.0"

def open_browser():
    """Opens a browser to make it easy to navigate to ISDi
    """
    if not config.TEST:
        webbrowser.open('http://127.0.0.1:' + str(PORT), new=0, autoraise=True)


if __name__ == "__main__":
    import sys
    if 'TEST' in sys.argv[1:] or 'test' in sys.argv[1:]:
        print("Running in test mode.")
        config.set_test_mode(True)
        print(f"Checking mode = {config.TEST}\n"
              "App flags: {config.APP_FLAGS_FILE}\n"
              "SQL_DB: {config.SQL_DB_PATH}")

    print(f"TEST={config.TEST}")
    db.init_db(app, sa, force=config.TEST)
    config.setup_logger()
    Timer(1, open_browser).start()
    app.run(host=HOST, port=PORT, debug=config.DEBUG, use_reloader=config.DEBUG)

    # Use this to delete client data on exit
    #atexit.register(delete_client_data)
