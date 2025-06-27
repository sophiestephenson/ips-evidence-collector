from flask import redirect, render_template, request, session, url_for

import config
from phone_scanner import AndroidScan, IosScan, TestScan
from phone_scanner.db import get_client_devices_from_db, new_client_id
from web import app

# FIXME: why are we scanning devices before people clicked on scan now?
#android = AndroidScan()
#ios = IosScan()
#test = TestScan()


# all in all, this particular section has a terrible code smell...
def get_device(k):
    return {"android": AndroidScan(), "ios": IosScan(), "test": TestScan()}.get(k)


@app.route("/", methods=["GET"])
def index():
    # clientid = request.form.get('clientid', request.args.get('clientid'))
    # if not clientid: # if not coming from notes

    newid = request.args.get("newid")
    # if it's a new day (see app.permenant_session_lifetime),
    # or the client devices are all scanned (newid),
    # ask the DB for a new client ID (additional checks in DB).
    if "clientid" not in session or (newid is not None):
        session["clientid"] = new_client_id()
    
    return redirect(url_for('evidence_setup'))

    return render_template(
        "main.html",
        title=config.TITLE,
        device_primary_user=config.DEVICE_PRIMARY_USER,
        task="home",
        devices={
            "Android": android.devices(),
            "iOS": ios.devices(),
            "Test": test.devices(),
        },
        apps={},
        clientid=session["clientid"],
        currently_scanned=get_client_devices_from_db(session["clientid"]),
    )
