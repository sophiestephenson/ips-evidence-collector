import os
import shutil

from config import DUMP_DIR, SCREENSHOT_DIR
from evidence_collection import (
    TMP_CONSULT_DATA_DIR,
    ConsultDataTypes,
    get_data_filename,
)


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


if __name__ == "__main__":
    delete_client_data()
