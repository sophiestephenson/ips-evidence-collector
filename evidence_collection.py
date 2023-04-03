"""
Author: Sophie Stephenson
Date: 2023-03-15

Collect evidence of IPS. Basic version collects this data from the phone:

1. All apps that might be dual-use or spyware and data about them (install 
    time, desc, etc.)
2. Permission usage in the last 7 days (or 28 days, if we can)

"""
import json
import os
from pprint import pprint

from flask import render_template, session
from flask_wtf import FlaskForm
from wtforms import (
    FieldList,
    FormField,
    HiddenField,
    MultipleFileField,
    SelectField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import InputRequired

import config
from db import create_mult_appinfo, create_scan
from web.view.index import get_device
from web.view.scan import first_element_or_none

yes_no_choices = [('y', 'Yes'), ('n', 'No'), ('u', 'Unsure')]
device_type_choices=[('android', 'Android'), ('ios', 'iOS')]
accounts = ["Google", "iCloud", "Microsoft", "Lyft", "Uber"]
two_factor_options = ["Phone", "Email", "App"]

## HELPER FORMS FOR EVERY PAGE
class NotesForm(FlaskForm):
    client_notes = TextAreaField("Client notes")
    consultant_notes = TextAreaField("Consultant notes")

## HELPER FORMS FOR APPS
class PermissionForm(FlaskForm):
    permission_name = HiddenField("Permission")
    access = SelectField('Can your [ex-]partner access this information?', choices=yes_no_choices, validators=[InputRequired()])
    describe = TextAreaField("Please describe how you know this.")
    screenshot = MultipleFileField('Add screenshot(s)')

class InstallForm(FlaskForm):
    knew_installed = SelectField('Did you know this app was installed?', choices=yes_no_choices, validators=[InputRequired()])
    installed = SelectField('Did you install this app?', choices=yes_no_choices, validators=[InputRequired()])
    coerced = SelectField('Were you coerced into installing this app?', choices=yes_no_choices, validators=[InputRequired()])
    screenshot = MultipleFileField('Add screenshot(s)')

class SpywareAppForm(FlaskForm):
    app_name = HiddenField("App Name")
    install_form = FormField(InstallForm)
    notes = FormField(NotesForm)
    screenshot = MultipleFileField('Add screenshot(s)')

class DualUseAppForm(FlaskForm):
    app_name = HiddenField("App Name")
    install_form = FormField(InstallForm)
    permissions = FieldList(FormField(PermissionForm))
    notes = FormField(NotesForm)
    screenshot = MultipleFileField('Add screenshot(s)')


## HELPER FORMS FOR ACCOUNTS
class SuspiciousLoginsForm(FlaskForm):
    recognize = SelectField("Do you recognize all logged-in devices?", choices=yes_no_choices, validators=[InputRequired()])
    describe = TextAreaField("Which devices do you not recognize?")
    activity_log = SelectField("Are there any suspicious logins in the activity log?", choices=yes_no_choices, validators=[InputRequired()])
    screenshot = MultipleFileField('Add screenshot(s)')

class PasswordForm(FlaskForm):
    know = SelectField("Does your [ex-]partner know the password for this account?", choices=yes_no_choices, validators=[InputRequired()])
    guess = SelectField("Do you believe they could guess the password?", choices=yes_no_choices, validators=[InputRequired()])

class RecoveryForm(FlaskForm):
    phone = TextAreaField("What is the recovery phone number?")
    phone_owned = SelectField("Is this your phone number?", choices=yes_no_choices, validators=[InputRequired()])
    email = TextAreaField("What is the recovery email?")
    email_owned = SelectField("Is this your email address?", choices=yes_no_choices, validators=[InputRequired()])
    screenshot = MultipleFileField('Add screenshot(s)')

class TwoFactorForm(FlaskForm):
    enabled = SelectField("Is two-factor authentication enabled?", choices=yes_no_choices, validators=[InputRequired()])
    enabled = SelectField("What type of two-factor authentication is it?", choices=[(x.lower(), x) for x in two_factor_options], validators=[InputRequired()])
    email = TextAreaField("What is the second factor?")
    email_owned = SelectField("Do you control the second factor?", choices=yes_no_choices, validators=[InputRequired()])

class SecurityQForm(FlaskForm):
    enabled = SelectField("Does the account use security questions?", choices=yes_no_choices, validators=[InputRequired()])
    email = TextAreaField("Which questions are set?")
    enabled = SelectField("Would your [ex-]partner know the answer to any of these questions?", choices=yes_no_choices, validators=[InputRequired()])

class AccountInfoForm(FlaskForm):
    account_name = HiddenField("Account Name")
    suspicious_logins = FormField(SuspiciousLoginsForm)
    password_check = FormField(PasswordForm)
    recovery_settings = FormField(RecoveryForm)
    two_factor_settings = FormField(TwoFactorForm)
    security_questions = FormField(SecurityQForm)
    notes = FormField(NotesForm)

## INDIVIDUAL PAGES
class StartForm(FlaskForm):
    title = "Welcome to <Name of tool>"
    name = StringField('Name', validators=[InputRequired()])
    device_type = SelectField('Device type:', choices=device_type_choices, validators=[InputRequired()])
    submit = SubmitField("Continue")

class SpywareForm(FlaskForm):
    title = "Spyware Check"
    spyware_apps = FieldList(FormField(SpywareAppForm))
    submit = SubmitField("Continue")

class DualUseForm(FlaskForm):
    title = "Dual Use App Check"
    dual_use_apps = FieldList(FormField(DualUseAppForm))
    submit = SubmitField("Continue")

class AccountsUsedForm(FlaskForm):
    accounts_used = SelectMultipleField(choices=[(x.lower(), x) for x in accounts])
    submit = SubmitField("Continue")

class AccountCompromiseForm(FlaskForm):
    title = "Account Compromise Check"
    accounts = FieldList(FormField(AccountInfoForm))
    submit = SubmitField("Continue")

def remove_unwanted_data(data):
    unwanted_keys = ["csrf_token"]

    if type(data) == list:
        return [remove_unwanted_data(d) for d in data]
        
    elif type(data) == dict:
        new_data = {}
        for k in data.keys():
            if k not in unwanted_keys:
                new_v = remove_unwanted_data(data[k])
                new_data[k] = new_v

        return new_data
    
    else:
        return data  


def get_multiple_app_details(device, ser, apps):
    filled_in_apps = []
    for app in apps:
        d = get_app_details(device, ser, app["id"])
        d["flags"] = app["flags"]
        filled_in_apps.append(d)
    return filled_in_apps


def get_app_details(device, ser, appid):
    sc = get_device(device)
    d, info = sc.app_details(ser, appid)
    d = d.fillna('')
    d = d.to_dict(orient='index').get(0, {})
    d['appId'] = appid

    return d

def get_suspicious_apps(device, device_owner):

    # The following code is adapted from web/view/scan.py

    template_d = dict(
        task="home",
        title=config.TITLE,
        device=device,
        device_primary_user=config.DEVICE_PRIMARY_USER,   # TODO: Why is this sent
        apps={},
    )

    sc = get_device(device)
    if not sc:
        template_d["error"] = "Please choose one device to scan."
        return render_template("main.html", **template_d), 201
    if not device_owner:
        template_d["error"] = "Please give the device a nickname."
        return render_template("main.html", **template_d), 201

    ser = sc.devices()

    print("Devices: {}".format(ser))
    if not ser:
        # FIXME: add pkexec scripts/ios_mount_linux.sh workflow for iOS if
        # needed.
        error = "<b>A device wasn't detected. Please follow the "\
            "<a href='/instruction' target='_blank' rel='noopener'>"\
            "setup instructions here.</a></b>"
        template_d["error"] = error
        return render_template("main.html", **template_d), 201

    ser = first_element_or_none(ser)
    print(">>>scanning_device", device, ser, "<<<<<")

    if device == "ios":
        error = "If an iPhone is connected, open iTunes, click through the "\
                "connection dialog and wait for the \"Trust this computer\" "\
                "prompt to pop up in the iPhone, and then scan again."
    else:
        error = "If an Android device is connected, disconnect and reconnect "\
                "the device, make sure developer options is activated and USB "\
                "debugging is turned on on the device, and then scan again."
    error += "{} <b>Please follow the <a href='/instruction' target='_blank'"\
             " rel='noopener'>setup instructions here,</a> if needed.</b>"
    if device == 'ios':
        # go through pairing process and do not scan until it is successful.
        isconnected, reason = sc.setup()
        template_d["error"] = error.format(reason)
        if not isconnected:
            return render_template("main.html", **template_d), 201

    # TODO: model for 'devices scanned so far:' device_name_map['model']
    # and save it to scan_res along with device_primary_user.
    device_name_print, device_name_map = sc.device_info(serial=ser)

    # Finds all the apps in the device
    # @apps have appid, title, flags, TODO: add icon
    apps = sc.find_spyapps(serialno=ser).fillna('').to_dict(orient='index')
    if len(apps) <= 0:
        print("The scanning failed for some reason.")
        error = "The scanning failed. This could be due to many reasons. Try"\
            " rerunning the scan from the beginning. If the problem persists,"\
            " please report it in the file. <code>report_failed.md</code> in the<code>"\
            "phone_scanner/</code> directory. Checn the phone manually. Sorry for"\
            " the inconvenience."
        template_d["error"] = error
        return render_template("main.html", **template_d), 201

    scan_d = {
        'clientid': session['clientid'],
        'serial': config.hmac_serial(ser),
        'device': device,
        'device_model': device_name_map.get('model', '<Unknown>').strip(),
        'device_version': device_name_map.get('version', '<Unknown>').strip(),
        'device_primary_user': device_owner,
    }

    if device == 'ios':
        scan_d['device_manufacturer'] = 'Apple'
        scan_d['last_full_charge'] = 'unknown'
    else:
        scan_d['device_manufacturer'] = device_name_map.get(
            'brand', "<Unknown>").strip()
        scan_d['last_full_charge'] = device_name_map.get(
            'last_full_charge', "<Unknown>")

    rooted, rooted_reason = sc.isrooted(ser)
    scan_d['is_rooted'] = rooted
    scan_d['rooted_reasons'] = json.dumps(rooted_reason)

    # TODO: here, adjust client session.
    scanid = create_scan(scan_d)

    if device == 'ios':
        pii_fpath = sc.dump_path(ser, 'Device_Info')
        print('Revelant info saved to db. Deleting {} now.'.format(pii_fpath))
        cmd = os.unlink(pii_fpath)
        # s = catch_err(run_command(cmd), msg="Delete pii failed", cmd=cmd)
        print('iOS PII deleted.')

    print("Creating appinfo...")
    create_mult_appinfo([(scanid, appid, json.dumps(
        info['flags']), '', '<new>') for appid, info in apps.items()])

    template_d.update(dict(
        isrooted=(
            "<strong class='text-info'>Maybe (this is possibly just a bug with our scanning tool).</strong> Reason(s): {}"
            .format(rooted_reason) if rooted
            else "Don't know" if rooted is None 
            else "No"
        ),
        device_name=device_name_print,
        apps=apps,
        scanid=scanid,
        sysapps=set(),  # sc.get_system_apps(serialno=ser)),
        serial=ser,
        # TODO: make this a map of model:link to display scan results for that
        # scan.
        error=config.error()
    ))


    # new stuff from Sophie
    pprint(apps)

    suspicious_apps = []

    for k in apps.keys():
        app = apps[k]
        if 'dual-use' in app["flags"] or 'spyware' in app["flags"]:
            app["id"] = k
            suspicious_apps.append(app)

    detailed_apps = get_multiple_app_details(device, ser, suspicious_apps)
        
    return detailed_apps