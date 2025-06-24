import hashlib
import hmac
import os
import random
import re
import shlex
import sqlite3
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

from flask import render_template, request, url_for

import config

#from phone_scanner import iosScreenshot
from phone_scanner.privacy_scan_android import do_privacy_check, take_screenshot
from web import app
from web.view.index import get_device


@app.route("/privacy", methods=["GET"])
def privacy():
    """
    TODO: Privacy scan. Think how should it flow.
    Privacy is a seperate page.
    """
    return render_template(
        "main.html",
        task="privacy",
        device_primary_user=config.DEVICE_PRIMARY_USER,
        title=config.TITLE,
    )


@app.route("/privacy/<device>/<cmd>/<context>", methods=["GET"])
def privacy_scan(device, cmd, context):
    print(cmd)
    print(device)
    sc = get_device(device)
    if(device == "ios"):
        print("Taking a IOS screenhsot")
        res = iosScreenshot(sc.serialno, context, nocache=True)
    else:
        res = do_privacy_check(sc.serialno, cmd, context)
    print("Screenshot Taken")
    return res

def iosScreenshot(serialNumber, context, nocache = False):
    fname = config.create_screenshot_fname(context)
    linkPro = subprocess.Popen(["pymobiledevice3", "lockdown", "start-tunnel"], stdout= subprocess.PIPE)
    time.sleep(2)
    output = linkPro.stdout
    rsdAddress = ""
    rsdPort = ""
    i = 0
    for lineByte in output:
        line = lineByte.decode('utf-8')
        print(line)
        if i == 6:
            break
        if "RSD Address" in line:
            rsdAddress = line[13:]
        if "RSD Port" in line:
            lineSplit = line.split(":")
            rsdPort = lineSplit[1][1:]
        i += 1
    command = "pymobiledevice3 developer dvt screenshot " + fname + " --rsd " + rsdAddress + " " + rsdPort
    subprocess.run(shlex.split(command))
    return add_image(fname.replace("webstatic/", ""), nocache=True)
def add_image(img, nocache=False):
        rand = random.randint(0, 10000)
        return "<img height='400px' src='" + \
            url_for('static', filename=img) + "?{}'/>".format(rand if nocache else '')
