import os
import pickle
import traceback
from datetime import datetime
from enum import Enum
from pprint import pprint

from flask import (
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_bootstrap import Bootstrap

import config
from evidence_collection import (
    CONTEXT_PKL_FNAME,
    FAKE_APP_DATA,
    AccountCompromiseForm,
    AccountsUsedForm,
    DualUseForm,
    Pages,
    ScanForm,
    SpywareForm,
    StartForm,
    create_account_summary,
    create_app_summary,
    create_overall_summary,
    create_printout,
    get_screenshots,
    get_suspicious_apps,
    reformat_verbose_apps,
    remove_unwanted_data,
    unpack_evidence_context,
)
from web import app

bootstrap = Bootstrap(app)

USE_PICKLE_FOR_SUMMARY = False
USE_FAKE_DATA = True

@app.route("/evidence/home", methods={'GET'})
def evidence_home():

    context = dict(
        task = "evidence-home",
        #device_primary_user=config.DEVICE_PRIMARY_USER,
        title=config.TITLE,
        sessiondata = session,
    )

    return render_template('main.html', **context)


@app.route("/evidence/taq", methods={'GET', 'POST'})
def evidence_taq():

    ## Just testing for now!!!

    form = StartForm()

    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            # add clean data to the session data
            session['taq'] = (clean_data)

            return redirect(url_for('evidence_home'))

    if 'taq' in session:
        form.process(data=session['taq'])

    context = dict(
        task = "evidence-taq",
        #device_primary_user=config.DEVICE_PRIMARY_USER,
        form = form,
        title=config.TITLE,
        sessiondata = session,
    )

    return render_template('main.html', **context)


@app.route("/evidence/scan", methods={'GET'})
def evidence_scan_default():

    new_id = 0
    if 'scans' in session:
        new_id = len(session['scans'])

    return redirect(url_for('evidence_scan', id=new_id, step=1))

@app.route("/evidence/scan/<int:id>/<int:step>", methods={'GET', 'POST'})
def evidence_scan(id,step=1):

    class ScanSteps(Enum):
        DEVICEINFO = 1
        APPLIST = 2
        APPCHECKS = 3

    form = StartForm()
    if step == ScanSteps.APPLIST.value:
        form = StartForm() #Create an AppSelectForm(applist)

    if step == ScanSteps.APPCHECKS.value:
        # Pass in the list of apps to check
        form = StartForm() # Create combined AppCheckForm(spyware,dualuse)


    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            ### STEP 1: Save device info, perform scan, and add list of apps
            if step == ScanSteps.DEVICEINFO.value:

                # Set up the place we'll put this scan info
                if 'scans' not in session:
                    session['scans'] = []
                if len(session['scans']) == id:
                    session['scans'].append(dict()) # this will fit in the ID slot
                assert len(session['scans']) == id + 1

                session['scans'][id]['device_type'] = clean_data["device_type"]
                session['scans'][id]['device_nickname'] = clean_data["device_nickname"]

                 # Ensure any previous screenshots have been removed before scan
                print("Removing files:")
                os.system("ls webstatic/images/screenshots/")
                os.system("rm webstatic/images/screenshots/*")

                try:
                    # Get app list
                    suspicious_apps, other_apps = get_suspicious_apps(clean_data["device_type"],
                                                       clean_data["device_nickname"])
                    #session['scans'][id]['all_apps'] = other_apps + suspicious_apps
                    session['scans'][id]['all_apps'] = ["empty list for now"]
                    
                    # Create pre-filled check app list
                    spyware, dualuse = reformat_verbose_apps(suspicious_apps)
                    session['scans'][id]['check_apps'] = []
                    for app in spyware:
                        app["type"] = "spyware"
                        session['scans'][id]['check_apps'].append(app)
                    for app in dualuse:
                        app["type"] = "dualuse"
                        session['scans'][id]['check_apps'].append(app)

                except Exception as e:
                    print(traceback.format_exc())
                    flash(str(e), "error")
                    return redirect(url_for('evidence_scan', id=id, step=step))

                return redirect(url_for('evidence_scan', id=id, step=step+1))


            ### STEP 2: Create the list of apps we want to investigate in phase 2
            if step == ScanSteps.APPLIST.value:
                # TODO: Process clean_data to create this list

                checked_apps = [
                    {"app_name": "TODO", "type": "spyware", "investigation": {
                        "2-factor": "okay",
                    }},
                    {"app_name": "ADD", "type": "dualuse", "investigation": {
                        "2-factor": "okay",
                    }},
                    {"app_name": "APPS", "type": "manual", "investigation": {
                        "2-factor": "okay",
                    }},
                ]
                session['scans'][id]['check_apps'] = checked_apps
            
                return redirect(url_for('evidence_scan', id=id, step=step+1))

            ### STEP 3: Add investigation data for all of these apps, update session data
            if step == ScanSteps.APPCHECKS.value:

                # TODO: Process clean_data to create this updated list
                checked_apps = [
                    {"app_name": "TODO", "type": "spyware", "investigation": {
                        "2-factor": "okay"
                    }},
                    {"app_name": "ADD", "type": "dualuse", "investigation": {
                        "2-factor": "okay"
                    }},
                    {"app_name": "APPS", "type": "manual", "investigation": {
                        "2-factor": "okay"
                    }},
                ]
                session['scans'][id]['check_apps'] == checked_apps

                return redirect(url_for('evidence_home'))

    ### IF IT'S A GET:

    if 'scans' in session and len(session['scans']) > id:
        form.process(data=session['scans'][id])

    context = dict(
        task = "evidence-scan",
        #device_primary_user=config.DEVICE_PRIMARY_USER,
        form = form,
        title=config.TITLE,
        sessiondata = session,
        step = step,
        id = id
    )

    return render_template('main.html', **context)



@app.route("/evidence/account", methods={'GET', 'POST'})
def evidence_account():

    ### ASSUME FOR NOW A FRESH ACCOUNT

    ## Later if u want to edit just add the app ID to the URL

    form = AccountCompromiseForm()

    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            # add clean data to the session data
            if 'accounts' not in session.keys():
                session['accounts'] = []
                
            session['accounts'].append(clean_data)

            return redirect(url_for('evidence_home'))

    if 'accounts' in session:
        form.process(data=session['accounts'][0])
        ### CHANGE THIS LATER!! JUST DO THE FIRST ONE FOR NOW
        
    context = dict(
        task = "evidence-account",
        #device_primary_user=config.DEVICE_PRIMARY_USER,
        form = form,
        title=config.TITLE,
        sessiondata = session,
    )

    return render_template('main.html', **context)





############################################
############################################
############################################


@app.route("/evidence/", methods={'GET'})
def evidence_default():
    session.clear()
    return redirect(url_for('evidence', step=1))

@app.route("/evidence/<int:step>", methods=['GET', 'POST'])
def evidence(step):

    # SAVE SESSION DATA INTO LOCAL VARIABLES

    spyware = []
    dualuse = []
    if 'apps' in session.keys():
        spyware = session['apps']['spyware']
        dualuse = session['apps']['dualuse']

    accounts=[]
    # have to do this step numbering better...
    if 'step{}'.format(Pages.ACCOUNTS_USED.value) in session.keys():
        accounts=[{"account_name": x} for x in session['step{}'.format(Pages.ACCOUNTS_USED.value)]['accounts_used']]

    pprint(session)

    # FORMS

    forms = {
        Pages.START.value: StartForm(),
        Pages.SCAN.value: ScanForm(),
        Pages.SPYWARE.value: SpywareForm(spyware_apps=spyware),
        Pages.DUALUSE.value: DualUseForm(dual_use_apps=dualuse),
        Pages.ACCOUNTS_USED.value: AccountsUsedForm(),
        Pages.ACCOUNT_COMP.value: AccountCompromiseForm(accounts=accounts),
    }

    form = forms.get(step, 1)

    # Submit the form if it's a POST
    if request.method == 'POST':
        pprint(form.data)
        if form.is_submitted() and form.validate():

            # clean up the submitted data
            clean_data = remove_unwanted_data(form.data)

            # for accounts used, have to reformat our data due to limitations with wtforms
            if step == Pages.ACCOUNTS_USED.value:
                accounts_used = []
                accounts_unused = []
                for k, v in clean_data.items():
                    if k != "submit" and v == True:
                        accounts_used.append(k)
                    elif k != "submit" :
                        accounts_unused.append(k)

                for k in accounts_unused:
                    clean_data.pop(k)

                clean_data['accounts_used'] = accounts_used

            # add clean data to the session data
            session['step{}'.format(step)] = clean_data

            # collect apps if we're on the scan step
            if step == Pages.SCAN.value:
                # Ensure any previous screenshots have been removed before scan
                print("Removing files:")
                os.system("ls webstatic/images/screenshots/")
                os.system("rm webstatic/images/screenshots/*")

                try:
                    verbose_apps = get_suspicious_apps(session['step{}'.format(Pages.START.value)]['device_type'],
                                                       session['step{}'.format(Pages.START.value)]['name'])
                    spyware, dualuse = reformat_verbose_apps(verbose_apps)
                    session['apps'] = {"spyware": spyware, "dualuse": dualuse}

                except Exception as e:
                    if not USE_FAKE_DATA:
                        print(traceback.format_exc())
                        flash(str(e), "error")
                        return redirect(url_for('evidence', step=step))

                    # use fake data
                    session['apps'] = FAKE_APP_DATA

            if step < len(forms):
                # Redirect to next step
                return redirect(url_for('evidence', step=step+1))
            else:
                # Redirect to finish
                return redirect(url_for('evidence_summary'))

    # If form data for this step is already in the session, populate the form with it
    if 'step{}'.format(step) in session:
        form.process(data=session['step{}'.format(step)])

    context = dict(
        task = "evidence",
        progress =  int(step / len(forms) * 100),
        step = step,
        form = form,
        device_primary_user=config.DEVICE_PRIMARY_USER,
        title=config.TITLE,
        device_owner = "",
        device = "",
        scanned=False,
        spyware=spyware,
        dualuse=dualuse,
        accounts=accounts
    )

    if 'step{}'.format(Pages.START.value) in session.keys():
        context["device_owner"] = session['step{}'.format(Pages.START.value)]["name"]
        context["device"] = session['step{}'.format(Pages.START.value)]["device_type"]

    return render_template('main.html', **context)

@app.route('/evidence/summary', methods=['GET'])
def evidence_summary():
    # to speed up dev...
    if USE_PICKLE_FOR_SUMMARY and os.path.isfile(CONTEXT_PKL_FNAME):
        context = pickle.load(open(CONTEXT_PKL_FNAME, 'rb'))
    else:
        context = unpack_evidence_context(session, task="evidencesummary")
        pickle.dump(context, open(CONTEXT_PKL_FNAME, 'wb'))

    context["concerns"] = create_overall_summary(context, second_person=True)

    return render_template('main.html', **context)

@app.route("/evidence/printout", methods=["GET"])
def evidence_printout():
    if USE_PICKLE_FOR_SUMMARY and os.path.isfile(CONTEXT_PKL_FNAME):
        context = pickle.load(open(CONTEXT_PKL_FNAME, 'rb'))
    else:
        context = unpack_evidence_context(session, task="evidencesummary")
        pickle.dump(context, open(CONTEXT_PKL_FNAME, 'wb'))

    # add datetime
    now = datetime.now()
    dt_string = now.strftime("%Y/%m/%d %H:%M:%S")
    context["current_time"] = dt_string

    # add screenshot directory
    context["screenshot_dir"] = config.SCREENSHOT_LOCATION

    # add fake screenshots
    # context["spyware"][0]['screenshots'] = ['step3-1.png']
    # context["dualuse"][1]['screenshots'] = ['step4-1.png']
    # context["accounts"][0]['screenshots'] = ['step6-1.png', 'step6-2.png']

    for app in context["spyware"]:
         summary, concerning = create_app_summary(app, spyware=True)
         app['summary'] = summary
         app['concerning'] = concerning
         app['screenshots'] = get_screenshots('spyware', app['app_name'], context["screenshot_dir"])

    for app in context["dualuse"]:
         summary, concerning = create_app_summary(app, spyware=False)
         app['summary'] = summary
         app['concerning'] = concerning
         app['screenshots'] = get_screenshots('dualuse', app['app_name'], context["screenshot_dir"])

    for account in context["accounts"]:
        access, ability, access_concern, ability_concern = create_account_summary(account)
        account["access_summary"] = access
        account["ability_summary"] = ability
        account["concerning"] = access_concern or ability_concern
        account['screenshots'] = get_screenshots('accounts', account['account_name'], context["screenshot_dir"])

    context["concerns"] = create_overall_summary(context)

    pprint(context)

    filename = create_printout(context)
    workingdir = os.path.abspath(os.getcwd())
    return send_from_directory(workingdir, filename)
