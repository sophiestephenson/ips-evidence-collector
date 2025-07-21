import os
import traceback
from datetime import datetime
from pprint import pprint

from flask import (
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_bootstrap import Bootstrap

import config
from evidence_collection import (
    AccountCompromiseForm,
    AccountInvestigation,
    AppInvestigationForm,
    AppSelectPageForm,
    ConsultationData,
    ConsultDataTypes,
    ConsultNotesData,
    ConsultSetupData,
    HomepageNoteForm,
    ManualAddPageForm,
    MultScreenshotEditForm,
    ScanData,
    SetupForm,
    StartForm,
    TAQData,
    TAQForm,
    create_printout,
    get_scan_by_ser,
    get_scan_data,
    get_ser_from_scan_obj,
    get_serial,
    load_json_data,
    load_object_from_json,
    remove_unwanted_data,
    save_data_as_json,
    update_scan_by_ser,
)
from phone_scanner import AndroidScan, IosScan
from web import app

bootstrap = Bootstrap(app)

USE_PICKLE_FOR_SUMMARY = False
USE_FAKE_DATA = True

@app.route("/evidence/setup", methods={'GET', 'POST'})
def evidence_setup():

    form = SetupForm()

    if request.method == 'GET':

        # Load any data we already have
        setup_data = load_object_from_json(ConsultDataTypes.SETUP.value)
        pprint(setup_data)

        if setup_data.date.strip() == "":
            setup_data.date = datetime.now().strftime("%Y/%m/%d %H:%M:%S")

        form.process(data=setup_data.to_dict())

        context = dict(
            task = "evidence-setup",
            title=config.TITLE,
            form = form
        )

        return render_template('main.html', **context)

    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():
            # clean up and save data
            clean_data = remove_unwanted_data(form.data)
            setup_data = ConsultSetupData(**clean_data)

            # save clean data
            save_data_as_json(setup_data, ConsultDataTypes.SETUP.value)


            return redirect(url_for('evidence_home'))

        elif not form.validate():
            flash("Missing required fields")
            return redirect(url_for('evidence_setup'))


    return redirect(url_for('evidence_setup'))



@app.route("/evidence/home", methods={'GET', 'POST'})
def evidence_home():

    notes = load_json_data(ConsultDataTypes.NOTES.value)
    pprint(notes)

    consult_data = ConsultationData(
        setup=load_json_data(ConsultDataTypes.SETUP.value),
        taq=load_json_data(ConsultDataTypes.TAQ.value),
        accounts=load_json_data(ConsultDataTypes.ACCOUNTS.value),
        scans=load_json_data(ConsultDataTypes.SCANS.value),
        screenshot_dir = config.SCREENSHOT_LOCATION,
        notes = load_json_data(ConsultDataTypes.NOTES.value)
    )

    form = HomepageNoteForm(**consult_data.notes.to_dict())

    context = dict(
        task = "evidence-home",
        title=config.TITLE,
        consultdata=consult_data.to_dict(),
        form = form
    )

    if request.method == 'GET':

        return render_template('main.html', **context)

    if request.method == 'POST':

        pprint(form.data)

        if form.is_submitted() and form.validate():

            new_notes = ConsultNotesData(**form.data)
            save_data_as_json(new_notes, ConsultDataTypes.NOTES.value)

            return redirect(url_for('evidence_home'))

        elif not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')
            return render_template('main.html', **context)


@app.route("/evidence/taq", methods={'GET', 'POST'})
def evidence_taq():

    form = TAQForm()

    # Load the form including any existing data
    if request.method == 'GET':

        # Load any data we already have
        taq_data = load_object_from_json(ConsultDataTypes.TAQ.value)

        form.process(data=taq_data.to_dict())

        context = dict(
            task = "evidence-taq",
            form = form,
            title=config.TITLE,
            sessiondata = taq_data.to_dict()
        )

        return render_template('main.html', **context)


    # Submit the form
    if request.method == 'POST':

        if form.is_submitted() and form.validate():

            # load data as class
            taq_data = TAQData(**form.data)

            # save clean data
            save_data_as_json(taq_data, ConsultDataTypes.TAQ.value)

            return redirect(url_for('evidence_home'))

        elif not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')
            return redirect(url_for('evidence_taq'))

    return redirect(url_for('evidence_taq'))



@app.route("/evidence/scan", methods={'GET', 'POST'},
           defaults={'device_type': '', 'device_nickname': '', 'force_rescan': False})
@app.route("/evidence/scan/<device_type>/<device_nickname>", methods={'GET', 'POST'},
           defaults={'force_rescan': False})
@app.route("/evidence/scan/<device_type>/<device_nickname>/force-rescan-<force_rescan>", methods={'GET', 'POST'})
def evidence_scan_start(device_type, device_nickname, force_rescan):

    # always assume we are starting with a fresh scan
    all_scan_data = load_object_from_json(ConsultDataTypes.SCANS.value)
    current_scan = ScanData()
    form = StartForm(device_type=device_type, device_nickname=device_nickname)

    context = dict(
        task = "evidence-scan",
        form = form,
        title=config.TITLE,
        scan_data = current_scan.to_dict(),
        step = 1,
        id = 0,
    )

    if request.method == "GET":
        pprint(form.data)
        return render_template('main.html', **context)

    if request.method == "POST":
        pprint(form.data)
        if form.is_submitted() and form.validate():

            if form.manualadd.data:

                # if it's a manual add, create a new scan object and redirect to the manual add page
                current_scan = ScanData(
                    device_type=form.data["device_type"],
                    device_nickname=form.data["device_nickname"],
                    serial="MANADD-" + str(hash(form.data["device_nickname"])),
                    manual=True
                )
                current_scan.id = len(all_scan_data)
                all_scan_data.append(current_scan)
                save_data_as_json(all_scan_data, ConsultDataTypes.SCANS.value)

                return redirect(url_for('evidence_scan_manualadd',
                                        ser=current_scan.serial))

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            # Ensure any previous screenshots have been removed before scan
            # print("Removing files:")
            # os.system("ls webstatic/images/screenshots/")
            # os.system("rm webstatic/images/screenshots/*")

            # Do the above at end of consult instead

            try:
                # Before moving on, check if we're scanning a device we've already scanned.
                # If so, just load the next page for that device
                ser = get_serial(clean_data["device_type"], clean_data["device_nickname"])
                hmac_ser = config.hmac_serial(ser)
                print("SERIAL NUMBER: " + hmac_ser)
                if not force_rescan:
                    for scan in all_scan_data:
                        if scan.serial == hmac_ser:
                            flash("This device was already scanned.")
                            return redirect(url_for('evidence_scan_select', ser=hmac_ser, show_rescan=True))

                # Perform the scan
                scan_data, suspicious_apps_dict, other_apps_dict = get_scan_data(clean_data["device_type"], clean_data["device_nickname"])

                # Fill in the /investigate/ marker for suspicious apps
                for i in range(len(suspicious_apps_dict)):
                    suspicious_apps_dict[i]["investigate"] = True

                all_apps = suspicious_apps_dict + other_apps_dict

                # Create current scan object with this info
                current_scan = ScanData(scan_id=len(all_scan_data),
                                        **clean_data,
                                        **scan_data,
                                        all_apps=all_apps)

                current_scan.id = len(all_scan_data)
                all_scan_data.append(current_scan)

                save_data_as_json(all_scan_data, ConsultDataTypes.SCANS.value)
                return redirect(url_for('evidence_scan_select', ser=current_scan.serial))

            except Exception as e:
                print(traceback.format_exc())
                flash("Scan error: " + str(e))
                return redirect(url_for('evidence_scan_start',
                                        device_type=form.data["device_type"],
                                        device_nickname=form.data["device_nickname"]))

        elif not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')

    return redirect(url_for('evidence_scan_start'))



@app.route("/evidence/scan/select/<string:ser>", methods={'GET', 'POST'}, defaults={'show_rescan': False})
@app.route("/evidence/scan/select/<string:ser>/show-rescan-<show_rescan>", methods={'GET', 'POST'})
def evidence_scan_select(ser, show_rescan):

    # load all scans
    all_scan_data = load_object_from_json(ConsultDataTypes.SCANS.value)

    # get the right scan by serial number
    current_scan = get_scan_by_ser(ser, all_scan_data)
    assert current_scan.serial == ser

    pprint(current_scan.all_apps[0].permission_info.__dict__)

    # fill form
    form = AppSelectPageForm(apps=[app.to_dict() for app in current_scan.all_apps])

    # IF IT'S A GET:
    if request.method == 'GET':
        #form.process(data=current_scan.to_dict())

        context = dict(
            task = "evidence-scan",
            form = form,
            device = current_scan.device_type,
            nickname = current_scan.device_nickname,
            title=config.TITLE,
            all_apps = [app.to_dict() for app in current_scan.all_apps],
            isrooted = current_scan.is_rooted,
            rooted_reasons = current_scan.rooted_reasons,
            step = 2,
            num_sys_apps = len([app for app in current_scan.all_apps if 'system-app' in app.flags]),
            show_rescan = show_rescan
        )
        print("-"*80)
        print(context['device'])
        print("-"*80)

        return render_template('main.html', **context)

    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            #clean_data = remove_unwanted_data(form.data)

            # get selected apps from the form data
            to_investigate_ids = [app["appId"] for app in form.data['apps'] if app['investigate']]

            # remove apps we no longer want to investigate,
            # while maintaining info from previous investigations
            current_scan.selected_apps = [app for app in current_scan.selected_apps if app.appId in to_investigate_ids]

            # Update "investigate" marker and add new apps to selected_apps
            # TODO: Do we need the "investigate" marker?
            for a in current_scan.all_apps:
                if a.appId in to_investigate_ids:
                    if not a.investigate:
                        current_scan.selected_apps.append(a)
                        a.investigate = True
                else:
                    a.investigate = False

            # update the current scan data and save it as the most recent scan
            # current_scan.selected_apps = [AppInfo(**app) for app in selected_apps]
            all_scan_data = update_scan_by_ser(current_scan, all_scan_data)

            # save this updated data
            save_data_as_json(all_scan_data, ConsultDataTypes.SCANS.value)

            return redirect(url_for('evidence_scan_investigate', ser=ser))

        if not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')

        return redirect(url_for('evidence_scan_select'), ser=ser)

@app.route("/evidence/scan/manualadd/<string:ser>", methods={'GET', 'POST'})
def evidence_scan_manualadd(ser):

    all_scan_data = load_object_from_json(ConsultDataTypes.SCANS.value)
    current_scan = get_scan_by_ser(ser, all_scan_data)
    assert current_scan.serial == ser

    manual_add_apps = [{"app_name": app.title, "spyware": "spyware" in app.flags} for app in current_scan.selected_apps]

    form = ManualAddPageForm(apps = manual_add_apps,
                             device_nickname=current_scan.device_nickname,
                             device_type=current_scan.device_type)

    ### IF IT'S A GET:
    if request.method == 'GET':

        context = dict(
            task = "evidence-scan-manualadd",
            title = config.TITLE,
            form = form
        )

        return render_template('main.html', **context)

    ### IF IT'S A POST:
    if request.method == 'POST':

        if form.is_submitted():

            # if it's an addline request, do that and reload
            if form.addline.data:
                form.update_self()
                context = dict(
                    task = "evidence-scan-manualadd",
                    title = config.TITLE,
                    form = form
                )
                return render_template('main.html', **context)

            elif form.validate():
                # TODO take data and do something with it

                pprint(form.data)

                selected_apps = []
                for a in form.data['apps']:
                    flags = []
                    if a['spyware']:
                        flags = ['spyware']
                    if a['app_name'].strip() != "":
                        selected_apps.append({
                            "title": a['app_name'],
                            "investigate": True,
                            "flags": flags
                        })

                current_scan.all_apps = selected_apps
                current_scan.selected_apps = selected_apps

                # load all scans
                all_scan_data = load_object_from_json(ConsultDataTypes.SCANS.value)

                # add manual scan
                all_scan_data = update_scan_by_ser(current_scan, all_scan_data)

                # save
                save_data_as_json(all_scan_data, ConsultDataTypes.SCANS.value)

                return redirect(url_for('evidence_scan_investigate', ser=current_scan.serial))

            if not form.validate():
                flash("Form validation error - are you missing required fields?", 'error')

            return redirect(url_for('evidence_scan_manualadd', ser=ser))


@app.route("/evidence/scan/investigate/<string:ser>", methods={'GET', 'POST'})
def evidence_scan_investigate(ser):

    # load all scans
    all_scan_data = load_object_from_json(ConsultDataTypes.SCANS.value)

    # get the right scan by serial number
    current_scan = get_scan_by_ser(ser, all_scan_data)
    assert current_scan.serial == ser

    for a in current_scan.selected_apps:
        a = a.to_dict()
        pprint("App: {}  Flags: {}".format(a["title"], a["flags"]))
    pprint("INFO GIVEN TO INVESTIGATION FORM")

    form = AppInvestigationForm(selected_apps=[a.to_dict() for a in current_scan.selected_apps])

    ### IF IT'S A GET:
    if request.method == 'GET':

        context = dict(
            task = "evidence-scan",
            form = form,
            title=config.TITLE,
            scan_data = current_scan.to_dict(),
            device = current_scan.device_type,
            step = 3
        )

        return render_template('main.html', **context)


    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            # Update app info in selected_apps based on what was provided in the form
            for a in current_scan.selected_apps:
                for form_app in clean_data["selected_apps"]:
                    if a.appId == form_app["appId"]:
                        a.install_info = form_app["install_info"]
                        a.permission_info.access = form_app["permission_info"]["access"]
                        a.permission_info.describe = form_app["permission_info"]["describe"]
                        a.notes = form_app["notes"]

            all_scan_data = update_scan_by_ser(current_scan, all_scan_data)

            #  save this updated data
            save_data_as_json(all_scan_data, ConsultDataTypes.SCANS.value)

            return redirect(url_for('evidence_home'))

        elif not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')
            return redirect(url_for('evidence_scan_investigate', ser=ser))

    return redirect(url_for('evidence_scan_investigate', ser=ser))



@app.route("/evidence/account", methods={'GET'})
def evidence_account_default():

    # consider adding a place to save the num scans later if it becomes a pain to load it
    accounts = load_json_data(ConsultDataTypes.ACCOUNTS.value)
    if accounts is list:
        new_id = len(accounts)
    else:
        new_id = 0

    return redirect(url_for('evidence_account', id=new_id))

@app.route("/evidence/account/<int:id>", methods={'GET', 'POST'})
def evidence_account(id):

    all_account_data = load_object_from_json(ConsultDataTypes.ACCOUNTS.value)
    current_account = AccountInvestigation(account_id=id)

    if len(all_account_data) > id:
        current_account = all_account_data[id]

    form = AccountCompromiseForm()

    # This is so that we can take screenshots if needed
    ios_scan_obj = IosScan()
    android_scan_obj = AndroidScan()
    ios_ser = None
    android_ser = None

    try:
        ios_ser = get_ser_from_scan_obj(ios_scan_obj)
    except:  # noqa
        pass

    try:
        android_ser = get_ser_from_scan_obj(android_scan_obj)
    except:  # noqa
        pass

    if request.method == 'GET':
        form.process(data=current_account.to_dict())

        context = dict(
            task = "evidence-account",
            form = form,
            title=config.TITLE,
            android_ser = android_ser,
            ios_ser = ios_ser,
            sessiondata = current_account.to_dict()
            # for now, don't load anything
        )

        return render_template('main.html', **context)

    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint("FORM DATA START")
        pprint(form.data)
        pprint("FORM DATA END")
        if form.is_submitted() and form.validate():

            # save data in class
            account_investigation = AccountInvestigation(**form.data, account_id=id)

            # add it to the account data
            if len(all_account_data) <= id:
                all_account_data.append(account_investigation)
            else:
                all_account_data[id] = account_investigation

            save_data_as_json(all_account_data, ConsultDataTypes.ACCOUNTS.value)

            return redirect(url_for('evidence_home'))

        if not form.validate():
            flash("Form validation error - are you missing required fields?", 'error')
            pprint(form.errors)

@app.route("/evidence/screenshots", methods=['GET', 'POST'])
def evidence_screenshots():

    # compile all screenshot filenames
    app_screenshot_info = []
    scans = load_object_from_json(ConsultDataTypes.SCANS.value)
    for scan in scans:
        for a in scan.all_apps:
            for fname in a.screenshot_files:
                app_screenshot_info.append({
                    "fname": fname,
                    "type": "app",
                    "app_id": a.appId,
                    "app_name": a.app_name,
                    "device_serial": scan.serial,
                    "device_nickname": scan.device_nickname
                })

    account_screenshot_info = []
    accounts = load_object_from_json(ConsultDataTypes.ACCOUNTS.value)
    for account in accounts:
        for section in [account.suspicious_logins,
                        account.recovery_settings,
                        account.two_factor_settings,
                        account.security_questions]:
            for fname in section.screenshot_files:
                account_screenshot_info.append({
                    "fname": fname,
                    "type": "account",
                    "account_nickname": account.account_nickname,
                    "section": section.screenshot_label
                })
                # Would be good to capture the phone that took the screenshot

    form = MultScreenshotEditForm(app_screenshots=app_screenshot_info,
                                  acct_screenshots=account_screenshot_info)

    url_root = request.url_root

    if request.method == 'GET':

        context = dict(
            task = "evidence-screenshots",
            title=config.TITLE,
            app_screenshot_info = app_screenshot_info,
            account_screenshot_info = account_screenshot_info,
            form = form,
            url_root = url_root
        )

        return render_template('main.html', **context)

    if request.method == 'POST' and form.is_submitted():
        # Delete all screenshots that were selected for deletion
        for a in form.data["app_screenshots"] + form.data["acct_screenshots"]:
            if a["delete"] and os.path.exists(a["fname"]):
                os.remove(a["fname"])

        # Reload the screenshot page
        return redirect(url_for('evidence_screenshots'))

@app.route("/evidence/printout", methods=["GET"])
def evidence_printout():

    consult_data = ConsultationData(
        setup=load_json_data(ConsultDataTypes.SETUP.value),
        taq=load_json_data(ConsultDataTypes.TAQ.value),
        accounts=load_json_data(ConsultDataTypes.ACCOUNTS.value),
        scans=load_json_data(ConsultDataTypes.SCANS.value),
        screenshot_dir = config.SCREENSHOT_LOCATION,
        notes=load_json_data(ConsultDataTypes.NOTES.value)
    )

    consult_data.prepare_reports()

    context = consult_data.to_dict()

    # Change to dict to enable iteration with questions
    context["taq"] = consult_data.taq.to_dict()
    context["accounts"] = [acct.to_dict() for acct in consult_data.accounts]


    # Need url_root to load screenshots
    context["url_root"] = request.url_root

    # create the printout document
    filename = create_printout(context)
    workingdir = os.path.abspath(os.getcwd())
    return send_from_directory(workingdir, filename)
