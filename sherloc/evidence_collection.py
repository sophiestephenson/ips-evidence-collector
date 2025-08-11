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
import re
import shutil
import subprocess
from enum import Enum
from pathlib import Path

import config
import jinja2
import pdfkit
from config import DUMP_DIR, SCREENSHOT_DIR, SHERLOC_VERSION
from filelock import FileLock
from flask_wtf import FlaskForm
from phone_scanner.db import create_mult_appinfo, create_scan
from phone_scanner.privacy_scan_android import take_screenshot
from web.view.index import get_device
from web.view.scan import first_element_or_none
from wtforms import (
    BooleanField,
    FieldList,
    FormField,
    HiddenField,
    RadioField,
    SelectMultipleField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import InputRequired

TMP_CONSULT_DATA_DIR = "tmp-consult-data"

SCREENSHOT_FOLDER = os.path.join("tmp", "isdi-screenshots/")
CONTEXT_PKL_FNAME = "context.pkl"

YES_NO_DEFAULT = ""
PERSON_DEFAULT = ""
LEGAL_DEFAULT = ""
TWO_FACTOR_DEFAULT = ""

SECOND_FACTORS = ["Phone", "Email", "Authenticator App", "Trusted Device", "Other"]
ACCOUNTS = ["Google", "iCloud", "Microsoft", "Lyft", "Uber", "Doordash", "Grubhub", "Facebook", "Twitter", "Snapchat", "Instagram"]

EMPTY_CHOICE = [('', 'Nothing selected')]
YES_NO_UNSURE_CHOICES = EMPTY_CHOICE + [('yes', 'Yes'), ('no', 'No'), ('unsure', 'Unsure')]
YES_NO_CHOICES = EMPTY_CHOICE + [('yes', 'Yes'), ('no', 'No')]
PERSON_CHOICES = [('me', 'Me'), ('poc', 'Person of concern'), ('someoneelse', 'Someone else'), ('unsure', 'Unsure')]
PWD_CHOICES = [('online', 'Online notes'), ('paper', 'Paper notes'), ('pwd_manager', 'Password manager'), ('photo', "Take a photo of it"), ('other_pwd', 'Other'), ('none', 'No specific method')]

LEGAL_CHOICES = [('ro', 'Restraining order'), ('div', 'Divorce or other family court'), ('cl', 'Criminal case'), ('other_legal', 'Other')]
DEVICE_TYPE_CHOICES = EMPTY_CHOICE + [('android', 'Android'), ('ios', 'iOS')]
#two_factor_choices = [empty_choice] + [(x.lower(), x) for x in second_factors]
TWO_FACTOR_CHOICES = [(x.lower().replace(" ", "_"), x) for x in SECOND_FACTORS]
ACCOUNT_CHOICES = [(x, x) for x in ACCOUNTS]

class Pages(Enum):
    START = 1
    SCAN = 2
    SPYWARE = 3
    DUALUSE = 4
    ACCOUNTS_USED = 5
    ACCOUNT_COMP = 6

    ### ----------------------------------
### ----------------------------------
### DATA TYPING
### ----------------------------------
### ----------------------------------

### HELPER CLASSES

# Helps create JSON encoding from nested classes
class EvidenceDataEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Path):
            return str(o)
        return o.__dict__

class Dictable:
    def to_dict(self):
        return json.loads(json.dumps(self, cls=EvidenceDataEncoder))

# Base class for nested classes where we'll input data as dict (for ease)
class DictInitClass(Dictable):
    attrs = []

    def __init__(self, datadict=dict()):
        for k in self.attrs:
            if k in list(datadict.keys()):
                setattr(self, k, datadict[k])
            else:
                setattr(self, k, "")


class AccountSection(DictInitClass):
    screenshot_label = ""
    attrs = ["account_id"]

    def __init__(self, datadict=dict()):
        super(AccountSection, self).__init__(datadict=datadict)
        self.screenshot_files = list()
        self.screenshot_info = list()

    def set_screenshot_files(self, screenshot_files):
        self.screenshot_files = screenshot_files

    def create_screenshot_info(self, get_metadata=True):
        '''
        Creates screenshot objects for all screenshot files related to this account section.
        '''
        self.screenshot_info = [ScreenshotInfo(
            fname=fname,
            context="account",
            get_metadata=get_metadata
        ) for fname in self.screenshot_files]

        return self.screenshot_info

class SuspiciousLogins(AccountSection):
    questions = {
        'recognize': "Do you see any unrecognized devices that are logged into this account?",
        'describe_logins': "Which devices do you not recognize?",
        'activity_log': "In the login history, do you see any suspicious logins?",
        'describe_activity': "Which logins are suspicious, and why?"
    }
    attrs = AccountSection.attrs + list(questions.keys())
    screenshot_label = "suspicious_logins"

    def generate_risk_report(self):
        '''
        Generate a risk report about suspicious logins. Possible risks:
            - Unrecognized devices
            - Suspicious logins
        '''
        risks = list()

        if self.recognize == 'yes':
            new_risk = Risk(
                risk = "Unrecognized devices",
                description = "There are unrecognized devices currently logged into this account."
            )
            risks.append(new_risk)

        if self.activity_log == 'yes':
            new_risk = Risk(
                risk = "Suspicious logins",
                description = "There are suspicious logins to this account that do not appear to have come from the client."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report

class PasswordCheck(AccountSection):
    questions = {
        "last_updated": "When did you last update this password (approximately)?",
        "know": "Does the person of concern know the password for this account?",
        "guess": "Do you believe the person of concern could guess the password?",
        "federated": "Do you log into this account using a federated login (e.g., Google, Facebook, Apple)?",
        "federated_which": "What other account do you use to log in?",
        "federated_comp": "Do you believe the person of concern has access to the federated account?",
    }
    attrs = AccountSection.attrs + list(questions.keys())

    def __init__(self, datadict=dict()):
        super(PasswordCheck, self).__init__(datadict=datadict)

    def generate_risk_report(self):
        '''
        Generate a risk report about password knowledge. Possible risks:
            - Knowledge of passwords
            - Ability to guess password
        '''
        risks = list()

        if self.know == 'yes':
            new_risk = Risk(
                risk = "Password compromise",
                description = "Knowing the password to this account could enable the person of concern to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)"
            )
            risks.append(new_risk)

        elif self.guess == 'yes':
            new_risk = Risk(
                risk = "Potential password compromise",
                description = "The client believes the person of concern could guess the password for this account. If they guess correctly, it would enable them to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)"
            )
            risks.append(new_risk)

        if self.federated_comp == "yes":
            new_risk = Risk(
                risk = "Compromised federated account",
                description = "By compromising the federated account, the person of concern could log into this account without needing to know the password."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report

class RecoverySettings(AccountSection):
    questions = {
        'phone_present': "Is there a recovery phone number set for this account?",
        'phone': "What is the recovery phone number?",
        'phone_access': "Do you believe the person of concern has access to the recovery phone number?",
        'email_present': "Is there a recovery email address set for this account?",
        'email': "What is the recovery email address?",
        'email_access': "Do you believe the person of concern has access to this recovery email address?"
    }
    attrs = AccountSection.attrs + list(questions.keys())
    screenshot_label = "recovery_settings"

    def generate_risk_report(self):
        '''
        Generate a risk report about recovery settings. Possible risks:
            - Recovery settings compromised
        '''
        risks = list()

        if self.phone_access == 'yes' or self.email_access == 'yes':
            new_risk = Risk(
                risk = "Compromised recovery information",
                description = "With access to the recovery contact information, someone can access an account without knowing the password using the 'Forgot password' option."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report

class TwoFactorSettings(AccountSection):
    questions = {
        'enabled': "Is two-factor authentication enabled for this account?",
        'second_factor_type': "What type of two-factor authentication is it?",
        'describe': "Which phone/email/app is set as the second factor?",
        'second_factor_access': "Do you believe the person of concern has access to this second factor?",
    }
    attrs = AccountSection.attrs + list(questions.keys())
    screenshot_label = "two_factor_settings"

    def generate_risk_report(self):
        '''
        Generate a risk report about two factor settings. Possible risks:
            - Two factor not set
            - 2nd factor compromised
        '''
        risks = list()

        if self.second_factor_access == 'yes':
            new_risk = Risk(
                risk = "Compromised second factor",
                description = "If someone has access to the second authentication factor, they only need the account password to log into the account. They could also intercept and delete login notifications."
            )
            risks.append(new_risk)

        elif self.enabled == 'no':
            new_risk = Risk(
                risk = "Two-factor authentication disabled",
                description = "Without two-factor authentication, others only need the account password to log in."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class SecurityQuestions(AccountSection):
    questions = {
        'present': "Does the account use security questions?",
        'know': "Do you believe the person of concern knows the answer to any of these questions?",
        'which': "Which questions might they be able to answer?",
    }
    attrs = AccountSection.attrs + list(questions.keys())
    screenshot_label = "security_questions"

    def generate_risk_report(self):
        '''
        Generate a risk report about security questions. Possible risks:
            - Enabled
            - Known
        '''
        risks = list()

        if self.present == 'yes':

            if self.know == 'yes':
                new_risk = Risk(
                    risk = "Guessable security questions",
                    description = "The client believes the person of concern knows the answers to security questions, which could allow them an easy way to log into the account."

                )
                risks.append(new_risk)

            else:
                new_risk = Risk(
                    risk = "Use of security questions",
                    description = "The account allows login using security questions, which are not secure because they are easy to guess."
                )
                risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report

class InstallInfo(DictInitClass):
    questions = {
        'knew_installed': 'Did you know this app was installed?',
        'installed': 'Did you install this app?',
        'coerced': 'Did the person of concern coerce you into installing this app?'
    }
    attrs = list(questions.keys())

    def generate_risk_report(self, system_app = False):
        risks = list()

        if not system_app:
            if self.knew_installed == 'no' or self.installed == 'no' or self.coerced == 'yes':

                description = ""
                if self.knew_installed == 'no':
                    description = "The client did not know this app was installed, indicating someone else installed it."

                elif self.installed == 'no':
                    description = "The client did not install this app, indicating someone else installed it."

                elif self.coerced == 'yes':
                    description = "The client was coerced into installing this app."

                new_risk = Risk(
                    risk="App installed without permission",
                    description=description
                )
                risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)
        return self.risk_report

class PermissionInfo(DictInitClass):
    questions = {
        "access": "Is any information being leaked to the person of concern through this app?",
        "describe": "If yes, please describe."
    }
    attrs = ['permissions',
             'access',
             'describe']

    def generate_risk_report(self):
        risks = list()

        if self.access == 'yes':
            new_risk = Risk(
                risk="Data leakage",
                description="This app is sharing data with the person of concern."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)
        return self.risk_report


class AppInfo(Dictable):
    def __init__(self,
                 title="",
                 app_name="",
                 appId="",
                 install_time="",
                 app_version="",
                 last_updated="",
                 flags=[],
                 application_icon="",
                 app_website="",
                 description="",
                 developerwebsite="",
                 investigate=False,
                 permission_info=dict(),
                 permissions=[],
                 install_info=dict(),
                 notes=dict(),
                 device_serial_udid="",
                 **kwargs):

        self.title = title
        self.app_name = app_name
        if self.app_name.strip() == "":
            self.app_name = title
        if self.title.strip() == "":
            self.title = app_name
        if self.app_name.strip() == "" or self.app_name.strip() == "App":
            self.app_name = appId
            self.title = appId
        self.appId = appId

        self.install_time = install_time
        self.app_version = app_version
        self.last_updated = last_updated

        # Fill in flags, removing any flags == ""
        self.flags = list(filter(None, flags))

        self.application_icon = application_icon
        self.app_website = app_website
        self.description = description
        self.developerwebsite = developerwebsite
        self.investigate = investigate

        # I DON"T REALLY KNOW WHY THE BELOW LOGIC IS NECESSARY

        # If permission_info is empty, then we need to create
        # a new PermissionInfo object with the permissions
        if len(permission_info) == 0:
            self.permission_info = PermissionInfo({
                'permissions': permissions
            })

        # Otherwise, create a PermissionInfo object with the provided data
        else:
            self.permission_info = PermissionInfo(permission_info)

        self.install_info = InstallInfo(install_info)
        self.notes = Notes(notes)

        self.device_serial_udid = device_serial_udid
        self.screenshot_files = list()
        self.screenshot_info = list()

    def set_screenshot_files(self, screenshot_files):
        self.screenshot_files = screenshot_files

    def create_screenshot_info(self, get_metadata=True):
        '''
        Creates screenshot objects for all screenshot files related to this app.
        '''
        self.screenshot_info = [ScreenshotInfo(
            fname=fname,
            context="app",
            app_id=self.appId,
            app_name=self.app_name,
            device_serial=self.device_serial_udid,
            get_metadata=get_metadata
        ) for fname in self.screenshot_files]

        return self.screenshot_info

    def _get_flag_risk(self):
        if 'spyware' in self.flags or 'onstore-spyware' in self.flags or 'offstore-spyware' in self.flags:
            return Risk(
                risk="Spyware application",
                description="This app is designed for covert surveillance."
            )
        elif 'regex-spy' in self.flags:
            return Risk(
                risk="Potential spyware application",
                description="This app may be a spyware application based on its title and description."
            )
        return None

    def generate_risk_report(self):
        '''
        Generate a risk report about this app. Possible risks:
            - Flag-based concerns (spyware, offstore)
            - App installed without permission (accounting for system apps)
            - App is sharing data
        '''
        risks = list()

        # Flag-based risk
        flag_risk = self._get_flag_risk()
        if flag_risk:
            risks.append(flag_risk)

        # Data leakage
        data_risks = self.permission_info.generate_risk_report()
        risks.extend(data_risks.risk_details)

        # Installation issues
        install_risks = self.install_info.generate_risk_report(system_app='system-app' in self.flags)
        risks.extend(install_risks.risk_details)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report

class Risk(Dictable):
    def __init__(self,
                 risk="",
                 description=""):
        self.risk = risk
        self.description = description

class RiskReport(Dictable):
    def __init__(self,
                 risk_details=list()):
        self.risk_details = risk_details
        self.risk_present = len(risk_details) > 0

class TAQDevices(DictInitClass):
    questions = {
        'live_together': "Do you live with the person of concern?",
        'purchase_device': "Did the person of concern purchase and/or set up any of your devices?",
        'purchase_device_which': "Which devices did the person of concern purchase and/or set up?",
        'physical_access': "Has the person of concern had physical access to your devices at any point in time?",
        'physical_access_which': "To which devices has the person of concern had physical access?",
        'device_pin': "Can the person of concern unlock any of these devices with PIN, password, or biometrics?",
    }
    attrs = list(questions.keys())

    def generate_risk_report(self) -> RiskReport:
        '''
        Generate a risk report for device compromise. Possible risk:
            - Physical access to devices
        '''
        risks = list()

        # Both indicate the same thing: physical access to devices.
        if self.live_together.lower() == 'yes' or self.physical_access.lower() == 'yes' or self.purchase_device.lower() == 'yes':
            new_risk = Risk(
                risk="Physical access to devices",
                description="A person with physical access to devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device."
            )
            if self.device_pin.lower() == 'yes':
                new_risk.description += " They can also unlock the device with a PIN, password, or biometrics, which would allow them to access all data on the device."
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQAccounts(DictInitClass):
    questions = {'pwd_mgmt': "How do you remember your passwords?",
                 'pwd_mgmt-describe': "Please provide more details on how you remember your passwords.",
                 'pwd_comp': "Do you believe the person of concern knows, or could guess, any of your passwords?",
                 'pwd_comp_which': "Which passwords do you believe are compromised, and why?"}
    attrs = list(questions.keys())

    def generate_risk_report(self) -> RiskReport:
        '''
        Generate a risk report for password compromise. Possible risks:
            - Password compromise
            - Password manager compromise TODO
        '''
        risks = list()

        if self.pwd_comp == 'yes':
            new_risk = Risk(
                risk="Password compromise",
                description="Someone who knows account passwords may be able to access and/or manipulate those accounts."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQSharing(DictInitClass):
    questions = {'share_phone_plan': "Do you share a phone plan with the person of concern?",
                 'phone_plan_admin': "If you share a phone plan, who is the family 'head' or plan administrator?",
                 'share_accounts': "Do you share any accounts with the person of concern?",
                 'share_which': "Which accounts are shared with the person of concern?"}
    attrs = list(questions.keys())

    def generate_risk_report(self) -> RiskReport:
        '''
        Generate a risk report for account compromise due to sharing. Possible risks:
            - Shared phone plan
            - Shared accounts
        '''
        risks = list()

        if self.share_phone_plan == 'yes':
            new_risk = Risk(
                risk="Shared phone plan",
                description="A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. The account administrator of the client's phone plan has even more privileged access to this information."
            )
            # Going to need to reformat the administrator here bc it'll probably say 'poc' not spelled out
            risks.append(new_risk)

        if self.share_accounts == 'yes':
            new_risk = Risk(
                risk="Shared accounts",
                description="The client has shared accounts with the person of concern. Any information on those accounts can be assumed to be known by the person of concern."
            )
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQSmarthome(DictInitClass):
    questions = {'smart_home': "Do you have any smart home devices?",
                 'smart_home_setup': "Who installed and set up your smart home devices?",
                 'smart_home_access': "Did the person of concern ever have physical access to the devices?",
                 'smart_home_acct_sharing': "Do you share any smart home accounts with the person of concern?",
                 'smart_home_acct_linking': "Can the person of concern access any of the smart home devices via their own smart home account?"}
    attrs = list(questions.keys())

    def _get_phys_access_risk(self):
        if self.smart_home_setup == 'poc':  # Check that this is what it would be, and not "Person of Concern"
            return Risk(
                risk="Physical access to smart home devices",
                description="With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control. Someone who initially set up the devices would have even more power to configure as they wish."
            )
        elif self.smart_home_access == 'yes':
            return Risk(
                risk="Physical access to smart home devices",
                description="With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control."
            )
        return None

    def _get_online_access_risk(self):
        if self.smart_home_acct_sharing == 'yes' or self.smart_home_acct_linking == 'yes':
            return Risk(
                risk="Online access to smart home devices",
                description="Someone with online access to a smart home device might be able to gather data (e.g., viewing video recordings or voice commands used) or manipulate the device state (e.g., turning a light off or locking a smart lock.)"
            )
        return None

    def generate_risk_report(self) -> RiskReport:
        '''
        Generate a risk report for smart home device compromise. Possible risks:
            - Physical access to smart home devices
            - Online access to smart home devices
        '''
        risks = list()

        # Physical access
        phys_access_risk = self._get_phys_access_risk()
        if phys_access_risk:
            risks.append(phys_access_risk)

        # Online access
        online_access_risk = self._get_online_access_risk()
        if online_access_risk:
            risks.append(online_access_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQKids(DictInitClass):
    questions = {
        'custody': "If you have children, do they have electronic devices?",
        'child_phys_access': "Has the person of concern had physical access to any of the child(ren)'s devices?",
        'child_phone_plan': "Does the person of concern pay for the child(ren)'s phone plan?"}
    attrs = list(questions.keys())

    def generate_risk_report(self) -> RiskReport:
        '''
        Generate a risk report for children's devices. Possible risks:
            - Physical access to devices
            - Shared phone plan
            - TODO: Other things like accounts shared, location sharing, ??
        '''
        risks = list()

        if self.child_phys_access == 'yes':
            new_risk = Risk(
                risk="Physical access to children's devices",
                description="A person with physical access to children's devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device. These changes could allow monitoring of the parent, for example by tracking the children's location when they are with their parent."
            )
            risks.append(new_risk)

        if self.child_phone_plan == 'yes':
            new_risk = Risk(
                risk="Shared phone plan (child)",
                description="A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. This could include information about the parent, such as their phone number and location when with the children. The plan administrator has even more privileged access to this information."
            )
            # Going to need to reformat the administrator here bc it'll probably say 'poc' not spelled out
            risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQLegal(DictInitClass):
    questions = {
        'legal': "Do you have any ongoing or upcoming legal cases?",
    }
    attrs = list(questions.keys())

class Notes(DictInitClass):
    attrs = ['client_notes', 'consultant_notes']

class RiskFactor():

    def __init__(self, risk, description):
        self.risk = risk
        self.description = description


### REAL CLASSES

class ConsultationData(Dictable):

    def __init__(self,
                 setup = dict(),
                 taq = dict(),
                 accounts = [],
                 scans = [],
                 screenshot_dir = "",
                 notes = dict(),
                 **kwargs):
        self.setup = ConsultSetupData(**setup)
        self.taq = TAQData(**taq)
        self.accounts = [AccountInvestigation(**account) for account in accounts]
        self.scans = [ScanData(**scan) for scan in scans]
        self.screenshot_dir = screenshot_dir
        self.notes = ConsultNotesData(**notes)

        # Grab questions that we will use to generate the printout
        # TODO: streamline
        self.formquestions = dict()
        self.formquestions["accounts"] = dict(
            suspicious_logins = SuspiciousLogins().questions,
            password_check = PasswordCheck().questions,
            recovery_settings = RecoverySettings().questions,
            two_factor_settings = TwoFactorSettings().questions,
            security_questions = SecurityQuestions().questions
        )
        self.formquestions["taq"] = dict(
            devices = TAQDevices().questions,
            accounts = TAQAccounts().questions,
            sharing = TAQSharing().questions,
            smarthome = TAQSmarthome().questions,
            kids = TAQKids().questions,
            legal = TAQLegal().questions
        )
        self.formquestions["apps"] = dict(
            permission_info = PermissionInfo().questions,
            install_info = InstallInfo().questions
        )

    def prepare_reports(self):
        '''
        Create all risk reports for the elements of the consultation.
        '''
        self.taq.generate_risk_reports()
        for scan in self.scans:
            scan.generate_risk_report()
        for account in self.accounts:
            account.generate_risk_report()

    def prepare_screenshots(self, get_metadata=True):
        """
        Get all screenshot information about consultation data.
        Need to do this for scans, account sections, and apps.
        """

        all_screenshots = get_all_screenshot_files()

        for scan in self.scans:
            scan_screenshots = all_screenshots["device_root"].get(scan.serial_or_udid, list())
            scan.set_screenshot_files(scan_screenshots)
            scan.create_screenshot_info(get_metadata=get_metadata)

            for app in scan.selected_apps:
                app_screenshots = all_screenshots["apps"].get(app.appId, list())
                app.set_screenshot_files(app_screenshots)
                app.create_screenshot_info(get_metadata=get_metadata)

        for account in self.accounts:
            if str(account.account_id) in list(all_screenshots["account_sections"].keys()):
                for section in [account.recovery_settings,
                                account.security_questions,
                                account.suspicious_logins,
                                account.two_factor_settings]:
                    section_screenshots = all_screenshots["account_sections"][str(account.account_id)][section.screenshot_label]
                    section.set_screenshot_files(section_screenshots)
                    section.create_screenshot_info(get_metadata=get_metadata)


class AccountInvestigation(Dictable):
    def __init__(self,
                 account_id=0,
                 platform="",
                 account_nickname="",
                 suspicious_logins=dict(),
                 password_check=dict(),
                 recovery_settings=dict(),
                 two_factor_settings=dict(),
                 security_questions=dict(),
                 notes=dict(),
                 **kwargs):
        self.account_id = account_id
        self.platform = platform
        self.account_nickname = account_nickname
        if self.account_nickname.strip() == "":
            self.account_nickname = platform

        # insert account id where needed to get screenshots
        for dict in [suspicious_logins, recovery_settings, two_factor_settings, security_questions]:
            dict['account_id'] = account_id
        self.suspicious_logins = SuspiciousLogins(suspicious_logins)
        self.password_check = PasswordCheck(password_check)
        self.recovery_settings = RecoverySettings(recovery_settings)
        self.two_factor_settings = TwoFactorSettings(two_factor_settings)
        self.security_questions = SecurityQuestions(security_questions)
        self.notes = Notes(notes)

        self.generate_risk_report()


    def generate_risk_report(self):

        risks = list()

        for obj in [self.suspicious_logins, self.password_check, self.recovery_settings, self.two_factor_settings, self.security_questions]:
            risk_report: RiskReport = obj.generate_risk_report()
            risks.extend(risk_report.risk_details)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class ScanData(Dictable):
    def __init__(self,
                 manual=False,
                 scan_id=0,
                 device_type="",
                 device_nickname="",
                 serial="",
                 adb_serial="",
                 serial_or_udid="",  # TODO: Just use this one
                 device_model="",
                 device_version="",
                 device_manufacturer="",
                 is_rooted="",
                 rooted_reasons="",
                 all_apps=list(),
                 selected_apps=list(),
                 **kwargs):

        self.manual = manual
        self.scan_id = scan_id
        self.device_type = device_type
        self.device_nickname = device_nickname
        self.serial = serial
        self.serial_or_udid = serial_or_udid
        if self.serial_or_udid.strip() == "":
            self.serial_or_udid = adb_serial
        self.device_model = device_model
        self.device_version = device_version
        self.device_manufacturer = device_manufacturer
        self.is_rooted = is_rooted
        self.rooted_reasons = rooted_reasons

        # sort all_apps by title, with system apps at the end,
        # checked apps at the top, and flagged investigated apps at the top top
        self.all_apps = [AppInfo(**app) for app in all_apps]
        self.all_apps.sort(key=lambda x: x.title.lower())
        self.all_apps.sort(key=lambda x: len(x.flags) > 0, reverse=True)
        self.all_apps.sort(key=lambda x: 'system-app' in x.flags and len(x.flags) == 1)
        self.all_apps.sort(key=lambda x: x.investigate, reverse=True)

        self.selected_apps = [AppInfo(**app) for app in selected_apps]

        self.screenshot_files = list()
        self.screenshot_info = list()

        self.generate_risk_report()

    def set_screenshot_files(self, screenshot_files):
        self.screenshot_files = screenshot_files

    def create_screenshot_info(self, get_metadata=True):
        '''
        Creates screenshot objects for all screenshot files related to this device scan.
        '''
        self.screenshot_info = [ScreenshotInfo(
            fname=fname,
            context="root",
            device_nickname=self.device_nickname,
            device_serial=self.serial,
            get_metadata=get_metadata
        ) for fname in self.screenshot_files]

        return self.screenshot_info

    def generate_risk_report(self):
        '''
        Generate a risk report for this device. Possible risks:
            - Jailbroken device
            - Risk from installed apps (raise up from apps)
        '''
        risks = list()
        self.concerning_apps = list()

        # Jailbreaking
        if self.is_rooted:
            new_risk = Risk(
                risk="Evidence of jailbreaking",
                description="The device may be jailbroken, giving the person of concern nearly unbounded access to the device and the client's activity on the device."
            )
            risks.append(new_risk)

        # Apps
        for a in self.selected_apps:
            app_risk_report = a.generate_risk_report()
            if app_risk_report.risk_present:
                self.concerning_apps.append(a)
                app_risk_list = [r.risk for r in app_risk_report.risk_details]
                new_risk = Risk(
                    risk="Risk from app: {}".format(a.title),
                    description="Risks identified: {}.".format(", ".join(app_risk_list))
                )
                risks.append(new_risk)

        self.risk_report = RiskReport(risk_details=risks)

        return self.risk_report


class TAQData(Dictable):

    def __init__(self,
                 marked_done=False,
                 devices=dict(),
                 accounts=dict(),
                 sharing=dict(),
                 smarthome=dict(),
                 kids=dict(),
                 legal=dict(),
                 **kwargs):
        self.marked_done = marked_done
        self.devices = TAQDevices(devices)
        self.accounts = TAQAccounts(accounts)
        #if self.accounts.pwd_comp_which.strip() == "":
        #    self.accounts.pwd_comp_which = "[Not provided]"
        self.sharing = TAQSharing(sharing)
        if self.sharing.phone_plan_admin == []:
            self.sharing.phone_plan_admin = ""
        self.smarthome = TAQSmarthome(smarthome)
        self.kids = TAQKids(kids)
        self.legal = TAQLegal(legal)

        self.generate_risk_reports()

    def generate_risk_reports(self):
        '''
        Generates all of the risk reports for the TAQ subforms.
        Gathers all risks together for the summary.
        '''
        self.all_risks = list()

        for obj in [self.devices, self.accounts, self.sharing, self.smarthome, self.kids]:
            risk_report: RiskReport = obj.generate_risk_report()
            self.all_risks.extend(risk_report.risk_details)

        return self.all_risks


class ConsultSetupData(Dictable):
    def __init__(self,
                 client="",
                 date="",
                 **kwargs):
        self.client = client
        self.date = date

class ConsultNotesData(Dictable):
    def __init__(self,
                 consultant_notes="",
                 client_notes="",
                 **kwargs):
        self.consultant_notes = consultant_notes
        self.client_notes = client_notes

class ScreenshotInfo(Dictable):
    def __init__(self,
                 fname="",
                 context="",  # root, account, or app
                 device_nickname=None,
                 device_serial=None,
                 app_id=None,
                 app_name=None,
                 account_nickname=None,
                 account_section=None,
                 get_metadata=True):
        self.fname = fname
        self.context = context

        # For root and app screenshots
        self.device_nickname = device_nickname
        self.device_serial = device_serial

        # Just for app screenshots
        self.app_id = app_id
        self.app_name = app_name

        # Just for account screenshots
        self.account_nickname = account_nickname
        self.account_section = account_section

        self.metadata = dict()
        if get_metadata:
            self.get_metadata()

    def get_metadata(self):
        """
        Uses exiftool (bash) to get metadata for our PNG screenshots.
        Available metadata:
            - ExifToolVersion
            - FileName
            - Directory
            - FileSize
            - FileModifyDate
            - FileAccessDate
            - FileInodeChangeDate
            - FilePermissions
            - FileType
            - FileTypeExtension
            - MIMEType
            - ImageWidth
            - ImageHeight
            - BitDepth
            - ColorType
            - Compression
            - Filter
            - Interlace
            - SRGBRendering
            - SignificantBits
            - ImageSize
            - Megapixels
        """

        data_to_get = ["FileSize",
                       "FileModifyDate",
                       "FileAccessDate",
                       "FileType",]

        self.metadata = dict()

        for item in data_to_get:
            result = subprocess.run(
                ["exiftool", "-" + item, self.fname],
                capture_output=True, text=True
            )
            data = result.stdout.split(":", 1)[-1].strip()
            self.metadata[item] = data

        return self.metadata


def get_scan_by_ser(ser, all_scan_data: list[ScanData]):

    for scan in all_scan_data:
        if scan.serial == ser:
            return scan

    return ScanData()




def update_scan_by_ser(new_scan: ScanData, all_scan_data: list[ScanData]):
    """
    Adds new_scan to all_scan_data.
    If new_scan matches serial numbers of an existing scan, it replaces that scan.
    Otherwise, it appends the new scan to the list.
    """

    for i in range(len(all_scan_data)):
        scan = all_scan_data[i]

        # if serial numbers match, replace with the new one
        if scan.serial == new_scan.serial:
            all_scan_data[i] = new_scan
            return all_scan_data

    # Otherwise, just append the new scan
    all_scan_data.append(new_scan)
    return all_scan_data

class ConsultDataTypes(Enum):
    TAQ = 1
    SCANS = 2
    ACCOUNTS = 3
    SETUP = 4
    NOTES = 5

def get_data_filename(datatype: ConsultDataTypes):

    if datatype == ConsultDataTypes.SETUP.value:
        return "setup.json"
    elif datatype == ConsultDataTypes.TAQ.value:
        return "taq.json"
    elif datatype == ConsultDataTypes.SCANS.value:
        return "scans.json"
    elif datatype == ConsultDataTypes.ACCOUNTS.value:
        return "accounts.json"
    else:
        return "notes.json"

########################
###### FORMS ###########
########################

## HELPER FORMS FOR EVERY PAGE
class NotesForm(FlaskForm):
    client_notes = TextAreaField("Client notes")
    consultant_notes = TextAreaField("Consultant notes")

## HELPER FORMS FOR APPS
class PermissionForm(FlaskForm):
    permissions = HiddenField("Permissions")
    access = RadioField(PermissionInfo().questions["access"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    describe = TextAreaField(PermissionInfo().questions["describe"])

# HELPER FORM FOR SCREENSHOTS

class InstallForm(FlaskForm):
    knew_installed = RadioField(InstallInfo().questions["knew_installed"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    installed = RadioField(InstallInfo().questions["installed"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    coerced = RadioField(InstallInfo().questions["coerced"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    #who = TextAreaField("If you were coerced, who coerced you?")

class SpywareAppForm(FlaskForm):
    title = HiddenField("App Name")
    install_form = FormField(InstallForm)
    app_name = HiddenField("App Name")
    appId = HiddenField("App ID")
    flags = HiddenField("Flags")
    application_icon = HiddenField("App Icon")
    app_website = HiddenField("App Website")
    description = HiddenField("Description")
    #descriptionHTML = HiddenField("HTML Description")
    developerwebsite = HiddenField("Developer Website")
    permissions = HiddenField("Permissions")
    subclass = HiddenField("Subclass")
    summary = HiddenField("Summary")
    notes = FormField(NotesForm)

class DualUseAppForm(FlaskForm):
    title = HiddenField("App Name")
    install_info = FormField(InstallForm)
    permissions = FieldList(FormField(PermissionForm))
    app_name = HiddenField("App Name")
    appId = HiddenField("App ID")
    flags = HiddenField("Flags")
    application_icon = HiddenField("App Icon")
    app_website = HiddenField("App Website")
    description = HiddenField("Description")
    #descriptionHTML = HiddenField("HTML Description")
    developerwebsite = HiddenField("Developer Website")
    subclass = HiddenField("Subclass")
    summary = HiddenField("Summary")
    notes = FormField(NotesForm)

## HELPER FORMS FOR ACCOUNTS
class SuspiciousLoginsForm(FlaskForm):
    recognize = RadioField(SuspiciousLogins().questions["recognize"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    describe_logins = TextAreaField(SuspiciousLogins().questions["describe_logins"])
    activity_log = RadioField(SuspiciousLogins().questions["activity_log"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    describe_activity = TextAreaField(SuspiciousLogins().questions["describe_activity"])

class PasswordForm(FlaskForm):
    last_updated = TextAreaField(PasswordCheck().questions["last_updated"])
    know = RadioField(PasswordCheck().questions["know"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    guess = RadioField(PasswordCheck().questions["guess"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    federated = RadioField(PasswordCheck().questions["federated"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    federated_which = TextAreaField(PasswordCheck().questions["federated_which"])
    federated_comp = RadioField(PasswordCheck().questions["federated_comp"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)

class RecoveryForm(FlaskForm):
    phone_present = RadioField(RecoverySettings().questions["phone_present"], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    phone = TextAreaField(RecoverySettings().questions["phone"])
    phone_access = RadioField(RecoverySettings().questions["phone_access"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    email_present = RadioField(RecoverySettings().questions["email_present"], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    email = TextAreaField(RecoverySettings().questions["email"])
    email_access = RadioField(RecoverySettings().questions["email_access"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)

class TwoFactorForm(FlaskForm):
    enabled = RadioField(TwoFactorSettings().questions["enabled"], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    second_factor_type = SelectMultipleField(TwoFactorSettings().questions["second_factor_type"], choices=TWO_FACTOR_CHOICES, default=TWO_FACTOR_DEFAULT)
    describe = TextAreaField(TwoFactorSettings().questions["describe"])
    second_factor_access = RadioField(TwoFactorSettings().questions["second_factor_access"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)

class SecurityQForm(FlaskForm):
    present = RadioField(SecurityQuestions().questions["present"], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    know = RadioField(SecurityQuestions().questions["know"], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    which = TextAreaField(SecurityQuestions().questions["which"])

class AccountInfoForm(FlaskForm):
    account_nickname = TextAreaField("Account Nickname")
    account_platform = TextAreaField("Platform")
    suspicious_logins = FormField(SuspiciousLoginsForm)
    password_check = FormField(PasswordForm)
    recovery_settings = FormField(RecoveryForm)
    two_factor_settings = FormField(TwoFactorForm)
    security_questions = FormField(SecurityQForm)
    notes = FormField(NotesForm)

class AppSelectForm(FlaskForm):
    title = HiddenField("App Name")
    appId = HiddenField("App ID")
    flags = HiddenField("Flags")
    app_name = HiddenField("App Name")
    #application_icon = HiddenField("App Icon")
    app_website = HiddenField("App Website")
    #description = HiddenField("Description")
    #descriptionHTML = HiddenField("HTML Description")
    #developerwebsite = HiddenField("Developer Website")
    #permission_info = HiddenField(FormField(PermissionForm))
    #subclass = HiddenField("Subclass")
    #summary = HiddenField("Summary")
    investigate = BooleanField("Check this app?")

## INDIVIDUAL PAGES
class StartForm(FlaskForm):
    title = "Device To Be Scanned"
    device_nickname = StringField('Device nickname', validators=[InputRequired()])
    device_type = RadioField('Device type', choices=DEVICE_TYPE_CHOICES, validators=[InputRequired()])
    submit = SubmitField("Scan Device")
    manualadd = SubmitField("Select apps manually")

class ScanForm(FlaskForm):
    title = "Scan Instructions"
    submit = SubmitField("Scan")

class SpywareForm(FlaskForm):
    title = "Step 1: Spyware Check"
    spyware_apps = FieldList(FormField(SpywareAppForm))
    submit = SubmitField("Continue")

class DualUseForm(FlaskForm):
    title = "Step 2: Dual Use App Check"
    dual_use_apps = FieldList(FormField(DualUseAppForm))
    submit = SubmitField("Continue")

class SingleAppCheckForm(FlaskForm):
    title = HiddenField("App Name")
    install_info = FormField(InstallForm)
    permission_info = FormField(PermissionForm)
    appId = HiddenField("App ID")
    flags = HiddenField("Flags")
    application_icon = HiddenField("App Icon")
    app_website = HiddenField("App Website")
    description = HiddenField("Description")
    descriptionHTML = HiddenField("HTML Description")
    developerwebsite = HiddenField("Developer Website")
    subclass = HiddenField("Subclass")
    summary = HiddenField("Summary")
    investigate = HiddenField("Investigate?")
    notes = FormField(NotesForm)

class AppInvestigationForm(FlaskForm):
    title = "App Investigations"
    selected_apps = FieldList(FormField(SingleAppCheckForm))
    submit = SubmitField("Save Investigation")

class AccountCompromiseForm(FlaskForm):
    title = "Account Compromise Check"
    platform = StringField('Platform', validators=[InputRequired()])
    account_nickname = StringField('Account Nickname')
    suspicious_logins = FormField(SuspiciousLoginsForm)
    password_check = FormField(PasswordForm)
    recovery_settings = FormField(RecoveryForm)
    two_factor_settings = FormField(TwoFactorForm)
    security_questions = FormField(SecurityQForm)
    notes = FormField(NotesForm)
    submit = SubmitField("Save")

class SetupForm(FlaskForm):
    title = "Consultation Information"
    client = StringField('Client Name', validators=[InputRequired()])
    date = StringField('Consultation Date and Time', validators=[InputRequired()], render_kw={'readonly': True})
    submit = SubmitField("Start Consultation")

class AppSelectPageForm(FlaskForm):
    title = "Select Apps to Investigate"
    apps = FieldList(FormField(AppSelectForm))
    submit = SubmitField("Select")

class ManualAppSelectForm(FlaskForm):
    app_name = StringField("App Name")
    spyware = BooleanField("Appears to be a spyware app?")
    dualuse = BooleanField("Appears to be a dual-use app?")

class ManualAddPageForm(FlaskForm):
    title = "Manual App Investigation: Select Apps"
    device_nickname = StringField("Device Nickname", validators=[InputRequired()])
    device_version = StringField("Device Version")
    device_model = StringField("Device Model", validators=[InputRequired()])
    device_manufacturer = StringField("Device Manufacturer")
    device_serial = StringField("Device Serial Number")
    is_rooted = RadioField("Is the device rooted?", choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    rooted_reasons = TextAreaField("Reasons rooting is suspected (if applicable).")
    apps = FieldList(FormField(ManualAppSelectForm))
    addline = SubmitField("Add a new app")
    submit = SubmitField("Submit")

    def update_self(self):
        # read the data in the form
        read_form_data = self.data

        # modify the data as you see fit:
        updated_list = read_form_data['apps']
        if read_form_data['addline']:
            updated_list.append({})
        read_form_data['apps'] = updated_list

        # reload the form from the modified data
        self.__init__(formdata=None, **read_form_data)
        self.validate()  # the errors on validation are cancelled in the line above

class ScreenshotEditForm(FlaskForm):
    fname = StringField("Filename")
    delete = BooleanField("Delete")

class MultScreenshotEditForm(FlaskForm):
    title = "Screenshot Edit Form"
    root_screenshots = FieldList(FormField(ScreenshotEditForm))
    app_screenshots = FieldList(FormField(ScreenshotEditForm))
    acct_screenshots = FieldList(FormField(ScreenshotEditForm))
    submit = SubmitField("Delete Selected Screenshots")

### TAQ Forms
class TAQDeviceCompForm(FlaskForm):
    title = "Device Compromise Indicators"
    live_together = RadioField(
        TAQDevices().questions['live_together'], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    purchase_device = RadioField(
        TAQDevices().questions['purchase_device'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    purchase_device_which = TextAreaField(TAQDevices().questions['purchase_device_which'])
    physical_access = RadioField(
        TAQDevices().questions['physical_access'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    physical_access_which = TextAreaField(TAQDevices().questions['physical_access_which'])
    device_pin = RadioField(
        TAQDevices().questions['device_pin'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)

class TAQAccountsForm(FlaskForm):
    title = "Account and Password Management"
    pwd_mgmt = SelectMultipleField(TAQAccounts().questions['pwd_mgmt'], choices=PWD_CHOICES)
    pwd_mgmt_describe = TextAreaField(TAQAccounts().questions['pwd_mgmt-describe'])
    pwd_comp = RadioField(
        TAQAccounts().questions['pwd_comp'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    pwd_comp_which = TextAreaField(TAQAccounts().questions['pwd_comp_which'])

class TAQSharingForm(FlaskForm):
    title = "Account Sharing"
    share_phone_plan = RadioField(
        TAQSharing().questions['share_phone_plan'], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    phone_plan_admin = SelectMultipleField(
        TAQSharing().questions['phone_plan_admin'], choices=PERSON_CHOICES, default=PERSON_DEFAULT)
    share_accounts = RadioField(
        TAQSharing().questions['share_accounts'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    share_which = TextAreaField(TAQSharing().questions['share_which'])

class TAQSmartHomeForm(FlaskForm):
    title = "Smart Home Devices"
    smart_home = RadioField(
        TAQSmarthome().questions['smart_home'], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    smart_home_setup = SelectMultipleField(
        TAQSmarthome().questions['smart_home_setup'], choices=PERSON_CHOICES, default=PERSON_DEFAULT)
    smart_home_access = RadioField(
        TAQSmarthome().questions['smart_home_access'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    smart_home_acct_sharing = RadioField(
        TAQSmarthome().questions['smart_home_acct_sharing'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    smart_home_acct_linking = RadioField(
        TAQSmarthome().questions['smart_home_acct_linking'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)

class TAQKidsForm(FlaskForm):
    title = "Children's Devices"
    custody = RadioField(
        TAQKids().questions['custody'], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)
    child_phys_access = RadioField(
        TAQKids().questions['child_phys_access'], choices=YES_NO_UNSURE_CHOICES, default=YES_NO_DEFAULT)
    child_phone_plan = RadioField(
        TAQKids().questions['child_phone_plan'], choices=YES_NO_CHOICES, default=YES_NO_DEFAULT)

class TAQLegalForm(FlaskForm):
    title = "Legal Proceedings"
    legal = SelectMultipleField(
        TAQLegal().questions['legal'], choices=LEGAL_CHOICES, default=LEGAL_DEFAULT)

class TAQForm(FlaskForm):
    title = "Technology Assessment Questionnaire (TAQ)"
    marked_done = BooleanField("Mark as complete")
    devices = FormField(TAQDeviceCompForm)
    accounts = FormField(TAQAccountsForm)
    sharing = FormField(TAQSharingForm)
    smarthome = FormField(TAQSmartHomeForm)
    kids = FormField(TAQKidsForm)
    legal = FormField(TAQLegalForm)
    submit = SubmitField("Save TAQ")

class HomepageNoteForm(FlaskForm):
    title = "Overall Consultation Notes"
    consultant_notes = TextAreaField("Consultant Notes")
    client_notes = TextAreaField("Client Notes")
    submit = SubmitField("Save Notes")

def create_printout(context):
    out_file = os.path.join('reports', 'test_report.pdf')
    template = os.path.join('templates', 'printout.html')
    css_path = os.path.join('webstatic', 'style.css')

    template_loader = jinja2.FileSystemLoader("./")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template(template)
    html_string = template.render(context)

    config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')

    options = {
        'enable-local-file-access': True,
        'margin-top': '15mm',
        'margin-bottom': '20mm',
        'margin-left': '10mm',
        'margin-right': '10mm',
        'footer-spacing': '5',
        'footer-center': 'Created by Madison Tech Clinic using Sherloc {} • Page [page] of [toPage]'.format(SHERLOC_VERSION),
        'footer-font-name': 'Georgia',
        'footer-font-size': '8',
    }

    pdfkit.from_string(html_string, out_file, options=options, configuration=config, css=css_path, verbose=True)

    print("Printout created. Filename is", out_file)

    # Also try one of the screenshots
    #pdfkit.from_file("/Users/Soph/research/evidence-project/ips-evidence-collector/webstatic/images/screenshots/HSN_1db594fa7f4b6f487b0f650a92209e0e43b077390bd7ff4f4b41c57b888d78d1/com.google.android.apps.pixelmigrate/27-06-2025_09-59-39.png", "reports/screenshot.pdf", options=options, configuration=config, css=css_path, verbose=True)

    return out_file


def create_overall_summary(context, second_person=False):
    concerns = dict(
        spyware = [],
        dualuse = [],
        accounts = []
    )

    return concerns

def get_screenshots(context, name, dir):
    screenshots = os.listdir(dir)
    name = name.replace(' ', '')
    return list(filter(lambda x: context in x and name in x, screenshots))


def screenshot(device, fname):
    """Take a screenshot and return the file where the screenshot is"""
    fname = os.path.join(SCREENSHOT_FOLDER, fname)

    sc = get_device(device)
    ser = sc.devices()

    if device.lower() == "android":
        take_screenshot(ser, fname=fname)

    else:
        # don't know how to do this yet
        return None

    return fname

def remove_unwanted_data(data):
    """Clean data from forms (e.g., remove CSRF tokens so they don't live in the session)"""
    unwanted_keys = ["csrf_token"]

    if isinstance(data, list):
        return [remove_unwanted_data(d) for d in data]

    elif isinstance(data, dict):
        new_data = {}
        for k in data.keys():
            if k not in unwanted_keys:
                new_v = remove_unwanted_data(data[k])
                new_data[k] = new_v

        return new_data

    else:
        return data

def account_is_concerning(account):
    login_concern = account['suspicous_logins']['recognize'] != 'y' or account['suspicous_logins']['activity_log'] != 'n'
    pwd_concern = account['password_check']['guess'] != 'n' or account['password_check']['know'] != 'n'
    recovery_concern = account['recovery_settings']['phone_owned'] != 'y' or account['recovery_settings']['email_owned'] != 'y'
    twofactor_concern = account['two_factor_settings']['second_factor_owned'] != 'n'
    security_concern = account['security_questions']['know'] != 'n'

    return login_concern or pwd_concern or recovery_concern or twofactor_concern or security_concern

def get_multiple_app_details(device, ser, apps):
    filled_in_apps = []
    for app in apps:
        d = get_app_details(device, ser, app["id"])
        d["flags"] = app["flags"]
        d["appId"] = app["id"]
        filled_in_apps.append(d)
    return filled_in_apps

def get_app_details(device, ser, appid):
    sc = get_device(device)
    d, info = sc.app_details(ser, appid)

    # Copy some info over from the info dict
    # TODO: Just return this all in one clean dictionary from app_details()...
    info_things = ["install_time", "last_updated", "app_version"]
    for item in info_things:
        try:
            d[item] = info[item]
            if d[item].strip() == "":
                d[item] = ""
        except KeyError:
            d[item] = ""

    #d = d.fillna('')
    #d = d.to_dict(orient='index').get(0, {})
    #d['appId'] = appid

    return d

def get_scan_obj(device, nickname):
    """Create the scan object."""
    sc = get_device(device)
    if not sc:
        raise Exception("Please choose one device to scan.")
    if not nickname:
        raise Exception("Please give the device a nickname.")
    return sc

def get_ser_from_scan_obj(sc):
    """Get the serial number of the device, if it exists."""
    ser = sc.devices()

    print("Devices: {}".format(ser))
    if not ser:
        # FIXME: add pkexec scripts/ios_mount_linux.sh workflow for iOS if
        # needed.
        raise Exception("A device wasn't detected.")

    ser = first_element_or_none(ser)
    return ser

def get_serial(device, nickname):
    sc = get_scan_obj(device, nickname)
    ser = get_ser_from_scan_obj(sc)
    return ser


def get_scan_data(device, device_owner):

    # The following code is adapted from web/view/scan.py

    template_d = dict(
        task="home",
        title=config.TITLE,
        device=device,
        device_primary_user=config.DEVICE_PRIMARY_USER,   # TODO: Why is this sent
        apps={},
    )

    try:
        sc = get_scan_obj(device, device_owner)
        ser = get_ser_from_scan_obj(sc)

        print(">>>scanning_device", device, ser, "<<<<<")

        if device == 'ios':
            # go through pairing process and do not scan until it is successful.
            isconnected, reason = sc.setup()
            if not isconnected:
                error = "If an iPhone is connected, open iTunes, click through the "\
                        "connection dialog and wait for the \"Trust this computer\" "\
                        "prompt to pop up in the iPhone, and then scan again."
                template_d["error"] = error.format(reason)
                raise Exception(error)

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
                " please report it in the file. Check the phone manually. Sorry for"\
                " the inconvenience."
            template_d["error"] = error
            raise Exception(error)

        clientid = "1"

        scan_d = {
            'clientid': clientid,
            'serial': config.hmac_serial(ser),
            'serial_or_udid': ser,
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
        scan_d['rooted_reasons'] = rooted_reason

        scanid = create_scan(scan_d)

        # if device == 'ios':
        #    pii_fpath = sc.dump_path(ser, 'Device_Info')
        #    print('Revelant info saved to db. Deleting {} now.'.format(pii_fpath))
        #    cmd = os.unlink(pii_fpath)
        #    s = catch_err(run_command(cmd), msg="Delete pii failed", cmd=cmd)
        #    print('iOS PII deleted.')

        create_mult_appinfo([(scanid, appid, json.dumps(
            info['flags']), '', '<new>') for appid, info in apps.items()])

        template_d.update(dict(
            isrooted=(
                "Maybe (this is possibly just a bug with our scanning tool). Reason(s): {}"
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

        suspicious_apps = []
        other_apps = []

        for k in apps.keys():
            app = apps[k]
            app["id"] = k
            app["app_name"] = app["title"]
            if app["app_name"].strip() == "":
                app["app_name"] = k

            # Check if any suspicious flags are present and add to the suspicious list
            suspicious_flags = ['spyware',
                                'dual-use',
                                'regex-spy',
                                'offstore-spyware',
                                'co-occurrence',
                                'onstore-dual-use',
                                'offstore-app']
            if len([x for x in app["flags"] if x in suspicious_flags]) > 0:
                suspicious_apps.append(app)
            else:
                other_apps.append(app)

        detailed_suspicious_apps = get_multiple_app_details(device, ser, suspicious_apps)
        detailed_other_apps = get_multiple_app_details(device, ser, other_apps)

        return scan_d, detailed_suspicious_apps, detailed_other_apps

    except Exception as e:
        template_d["error"] = str(e)
        raise e


# Save data to the right tmp file as JSON
# Overwrites it always, assume any previous data has been incorporated
def save_data_as_json(data, datatype: ConsultDataTypes):

    json_object = json.dumps(data, cls=EvidenceDataEncoder)

    fname = os.path.join(TMP_CONSULT_DATA_DIR, get_data_filename(datatype))

    lock = FileLock(fname + ".lock")
    with lock:
        with open(fname, 'w') as outfile:
            outfile.write(json_object)

    return

def load_json_data(datatype: ConsultDataTypes):

    fname = os.path.join(TMP_CONSULT_DATA_DIR, get_data_filename(datatype))

    lock = FileLock(fname + ".lock")
    with lock:
        if not os.path.exists(fname):
            if datatype in [ConsultDataTypes.SETUP.value, ConsultDataTypes.NOTES.value, ConsultDataTypes.TAQ.value]:
                return dict()
            else:
                return list()

        with open(fname, 'r') as openfile:
            json_object = json.load(openfile)
            return json_object

def load_object_from_json(datatype: ConsultDataTypes):
    json_data = load_json_data(datatype)
    if datatype == ConsultDataTypes.SETUP.value:
        return ConsultSetupData(**json_data)

    if datatype == ConsultDataTypes.TAQ.value:
        return TAQData(**json_data)

    if datatype == ConsultDataTypes.ACCOUNTS.value:
        assert isinstance(json_data, list)
        return [AccountInvestigation(**acct) for acct in json_data]

    if datatype == ConsultDataTypes.SCANS.value:
        assert isinstance(json_data, list)
        return [ScanData(**scan) for scan in json_data]

    if datatype == ConsultDataTypes.NOTES.value:
        return ConsultNotesData(**json_data)

    return None

def delete_client_data():

    # Delete the consult data stored as json
    print("Deleting consultation data...")
    for datatype in ConsultDataTypes:
        fname = os.path.join(TMP_CONSULT_DATA_DIR, get_data_filename(datatype.value))
        if os.path.exists(fname):
            os.remove(fname)

    # Delete phone dumps
    print("Deleting phone dumps...")
    print(DUMP_DIR)
    shutil.rmtree(DUMP_DIR)
    os.makedirs(DUMP_DIR, exist_ok=True)

    # Delete screenshots
    print("Deleting screenshots...")
    print(SCREENSHOT_DIR)
    shutil.rmtree(SCREENSHOT_DIR)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    print("Client data deleted.")

def get_all_screenshot_files():
    '''
    Gather all screenshot files at once. This will greatly speed up
    compiling screenshot filenames.

    Returns screenshot_files, a dict() with keys:
        - device_root (accessed by serial)
        - apps (accessed by app id)
        - account_sections (accessed by account id (str), then section label)
    '''

    # Everything is in SCREENSHOT_DIR under a device serial number
    # Need to get:
    #   - Device jailbreak (<device ser>/rooting/)
    #   - Device apps (<device ser>/<appid>/)
    #   - Account sections (<any ser>/account<id>_<section>/)

    screenshot_files = dict(
        device_root = dict(),  # accessed by ser
        apps = dict(),  # accessed by ser
        account_sections = dict()  # accessed by account id as a string
    )

    account_pattern = re.compile(r"account\d+_[a-zA-Z_]+")

    overall_screenshot_dir = os.path.join("webstatic", "images", "screenshots")
    if os.path.exists(overall_screenshot_dir):

        # go into all device dirs and subdirs
        device_dirs = [f for f in os.scandir(overall_screenshot_dir) if os.path.isdir(f)]
        for device_dir in device_dirs:
            screenshot_dirs = [f for f in os.scandir(device_dir.path) if os.path.isdir(f)]

            for screenshot_dir in screenshot_dirs:
                # get all screenshot files from this directory
                files = os.listdir(screenshot_dir.path)
                full_fnames = [os.path.join(screenshot_dir, f) for f in files]
                full_fnames.sort()

                if len(full_fnames) > 0:

                    # save the fnames in the right place
                    if screenshot_dir.name == "rooting":
                        screenshot_files["device_root"][device_dir.name] = full_fnames

                    elif account_pattern.match(screenshot_dir.name):
                        fname_parts = screenshot_dir.name.split("_", 1)
                        account_id_str = fname_parts[0][-1]
                        account_section = fname_parts[1]

                        if account_id_str not in list(screenshot_files["account_sections"].keys()):
                            section_dict = dict()
                            section_dict[SuspiciousLogins().screenshot_label] = list()
                            section_dict[RecoverySettings().screenshot_label] = list()
                            section_dict[TwoFactorSettings().screenshot_label] = list()
                            section_dict[SecurityQuestions().screenshot_label] = list()
                            screenshot_files["account_sections"][account_id_str] = section_dict

                        screenshot_files["account_sections"][account_id_str][account_section].extend(full_fnames)

                    else:
                        screenshot_files["apps"][screenshot_dir.name] = full_fnames

    return screenshot_files
