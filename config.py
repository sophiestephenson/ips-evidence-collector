import hashlib
import hmac
import logging
import logging.handlers as handlers
import os
import secrets
import shlex
from datetime import datetime
from pathlib import Path
from sys import platform

SHERLOC_VERSION = "1.0.2"

SCREENSHOT_LOCATION = "/Users/Soph/research/evidence-project/ips-evidence-collector/screenshots/"

def setup_logger():
    """
    Set up a logger with a rotating file handler.

    The logger will write in a file named 'app.log' in the 'logs' directory.
    The log file will rotate when it reaches 100,000 bytes, keeps a maximum of 30 files.

    Returns:
        logging.Logger: The configured logger object.
    """
    handler = handlers.RotatingFileHandler(
        "logs/app.log", maxBytes=100000, backupCount=30
    )
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


DEV_SUPPRTED = ["android", "ios"]  # 'windows', 'mobileos', later
THIS_DIR = Path(__file__).absolute().parent

# Used by data_process only.
source_files = {
    "playstore": "static_data/android_apps_crawl.csv.gz",
    "appstore": "static_data/ios_apps_crawl.csv.gz",
    "offstore": "static_data/offstore_apks.csv",
}
spyware_list_file = "static_data/spyware.csv"  # hand picked


# ---------------------------------------------------------
DEBUG = bool(int(os.getenv("DEBUG", "0")))
TEST = bool(int(os.getenv("TEST", "0")))

DEVICE_PRIMARY_USER = {
    "me": "Me",
    "child": "A child of mine",
    "partner": "My current partner/spouse",
    "family_other": "Another family member",
    "other": "Someone else",
}

ANDROID_PERMISSIONS_CSV = "static_data/android_permissions.csv"
IOS_DUMPFILES = {
    "Jailbroken-FS": "ios_jailbroken.log",
    "Jailbroken-SSH": "ios_jailbreak_ssh.retcode",
    "Apps": "ios_apps.json",
    "Info": "ios_info.xml",
}

TEST_APP_LIST = "static_data/android.test.apps_list"
# TITLE = "Anti-IPS: Stop Intimate Partner Surveillance"

TITLE = {"title": "Sherloc{}".format(" (test)" if TEST else "")}


APP_FLAGS_FILE = "static_data/app-flags.csv"
APP_INFO_SQLITE_FILE = "sqlite:///static_data/app-info.db"

# IOC stalkware indicators
IOC_PATH = "stalkerware-indicators"
IOC_FILE = os.path.join(IOC_PATH, "ioc.yaml")

# we will resolve the database path using an absolute path to __FILE__ because
# there are a couple of sources of truth that may disagree with their "path
# relavitity". Needless to say, FIXME
SQL_DB_PATH = f"sqlite:///{str(THIS_DIR / 'data/fieldstudy.db')}"
# SQL_DB_CONSULT_PATH = 'sqlite:///data/consultnotes.db' + ("~test" if TEST else "")


def set_test_mode(test):
    """
    Sets the test mode to the given value and returns the new values of APP_FLAGS_FILE and SQL_DB_PATH.
    """
    app_flags_file, sql_db_path = APP_FLAGS_FILE, SQL_DB_PATH
    if test:
        if not app_flags_file.endswith("~test"):
            app_flags_file = APP_FLAGS_FILE + "~test"
        if not sql_db_path.endswith("~test"):
            sql_db_path = sql_db_path + "~test"
    else:
        if app_flags_file.endswith("~test"):
            app_flags_file = app_flags_file.replace("~test", "")
        if sql_db_path.endswith("~test"):
            sql_db_path = sql_db_path.replace("~test", "")
    return app_flags_file, sql_db_path


APP_FLAGS_FILE, SQL_DB_PATH = set_test_mode(TEST)


STATIC_DATA = THIS_DIR / "static_data"

# TODO: We should get rid of this, ADB_PATH is very confusing
ANDROID_HOME = os.getenv("ANDROID_HOME", "")
PLATFORM = (
    "darwin"
    if platform == "darwin"
    else (
        "linux"
        if platform.startswith("linux")
        else "win32" if platform == "win32" else None
    )
)

ADB_PATH = shlex.quote(os.path.join(ANDROID_HOME, "adb"))

# LIBIMOBILEDEVICE_PATH = shlex.quote(str(STATIC_DATA / ("libimobiledevice-" + PLATFORM)))
LIBIMOBILEDEVICE_PATH = ""
# MOBILEDEVICE_PATH = 'mobiledevice'
# MOBILEDEVICE_PATH = os.path.join(THISDIR, "mdf")  #'python2 -m MobileDevice'
if PLATFORM:
    MOBILEDEVICE_PATH = shlex.quote(str(STATIC_DATA / ("ios-deploy-" + PLATFORM)))
else:
    MOBILEDEVICE_PATH = shlex.quote(str(STATIC_DATA / ("ios-deploy-none")))

DUMP_DIR = THIS_DIR / "phone_dumps"
SCRIPT_DIR = THIS_DIR / "scripts"
SCREENSHOT_DIR = THIS_DIR / "webstatic" / "images" / "screenshots"

DATE_STR = "%Y-%m-%d %I:%M %p"
ERROR_LOG = []

APPROVED_INSTALLERS = {"com.android.vending", 
                       "com.sec.android.preloadinstaller", 
                       "com.sec.android.app.samsungapps"}

REPORT_PATH = THIS_DIR / "reports"
PII_KEY_PATH = STATIC_DATA / "pii.key"


def open_or_create_random_key(fpath, keylen=32):
    """
    Opens the file at the given path or creates a new file with a random key of the specified length.

    Args:
        fpath (str): The path to the file.
        keylen (int, optional): The length of the random key. Defaults to 32.

    Returns:
        bytes: The contents of the file as bytes.
    """

    def create():
        with fpath.open("wb") as f:
            f.write(secrets.token_bytes(keylen))

    if not fpath.exists():
        create()
    k = fpath.open("rb").read(keylen)
    if len(k) != keylen:
        create()
    return fpath.open("rb").read()


PII_KEY = open_or_create_random_key(PII_KEY_PATH, keylen=32)

FLASK_SECRET_PATH = STATIC_DATA / "flask.secret"
FLASK_SECRET = open_or_create_random_key(FLASK_SECRET_PATH)

if not REPORT_PATH.exists():
    os.mkdir(REPORT_PATH)


def hmac_serial(ser: str) -> str:
    """Returns a string starting with HSN_<hmac(ser)>. If ser already have 'HSN_',
    it returns the same value."""
    if ser.startswith("HSN_"):
        return ser
    hser = hmac.new(PII_KEY, ser.encode("utf8"), digestmod=hashlib.sha256).hexdigest()
    return f"HSN_{hser}"


def add_to_error(*args):
    global ERROR_LOG
    m = "\n".join(str(e) for e in args)
    print(m)
    ERROR_LOG.append(m)


def error():
    global ERROR_LOG
    e = ""
    if len(ERROR_LOG) > 0:
        e, ERROR_LOG = ERROR_LOG[0], ERROR_LOG[1:]

        print(f"ERROR: {e}")
    return e.replace("\n", "<br/>")

def create_screenshot_fname(context, serial="misc"):
    # Verify the directory exists and create it if not
    subfolder = context.replace(" ", "")
    dir_path = os.path.join(THIS_DIR, "webstatic", "images", "screenshots", serial, subfolder)
    os.makedirs(dir_path, exist_ok=True)

    # Create a filename with the current time and context
    curr_time = datetime.now().strftime('%d-%m-%Y_%H-%M-%S')
    fname = os.path.join(dir_path, curr_time + '.png')

    print("This is the filename: {}".format(fname))

    return fname