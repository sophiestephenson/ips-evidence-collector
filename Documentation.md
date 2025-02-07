# dir __pycache____
   -  Bytecode compiled python files to make the script run 
# dir .github / workflows
   ## get-stalkerware-indicators.yml
      - Fetches "indicators of stalkerware every week on sunday from AssoEchap/stalkerware-indicators
      - Also runs a pull request from peter-evans/create-pull-request@v5
      - Donwloads and upgrades python dependencies ???
      - This updates the flags and updates the csv in static_data/app-flags.csv which is then used by get-stalkerware-indicators.py
   ## super-linter.yml
      - This runs automating linting checks only on modified files done, having common linters run when it occurs 
# dir bin
   ## activate 
      - starts a python virutal enviornment in a bash enviornment
      - begins with the command "source bin/activate" to start it, and "deactivate" to return back to the intial enviornment (could be nested virtual one)
      - SHOULD BE APART OF INSTALLATION DOCUMENTATION
      - THIS COULD BE OPTIMIZED ALONGSIDE CSH AND FISH
   ## activate.sh
      - accomplished same task but for csh shell 
   ## activate.fish
      - accomplished same task but for fish shell
   ## Activate.ps1
      - accomplishes the same thing but in powershell
   ## alembic 
      - this is a created file, which prepares a virtual enviornment to use alembic
      - Used for flasks migrate 
   ## similar files to alembic (automatically generated, this is now a list of which seem to be not used)
      - autopep8 // seems to function if removed
      - dotenv // can't remove
      - mako // is needed to run in packages is a dependency 
      - pycodestyle // seems to function if removed
# dir data
   ## .dummy
      - An empty file
      - DELETE (STILL IN MAIN BRANCH)
   ## fieldstudy.db
      - not sure what this is, can't seem to read it and doesn't correlate with what is in the github (no idea why) 
      - maybe same file with a new name?
# dir dumps
   ## .dummy
      - An empty file
      - DELETE (STILL IN MAIN BRANCH)
      - this entire directory doesn't seem to exist, could be "phone_dumps"
# dir include
   ## dir python3.12
      - empty directory
   ## site/python3.12/greenlet
      - Allows C extensions to create, switch, and manage greenlets for python concurrency efficency without threads
# dir logs
   ## .dummy
      - this is empty (unsure if this is used)
   ## app.log
      - this is empty
      - called but ./isdi  
         "handler = handlers.RotatingFileHandler('logs/app.log', maxBytes=100000, backupCount=30)"
         Setting up a RotatingFileHandler
      - COULD THIS BE EMPTY DUE TO LOGS BEING WIPED AFTER EVERY CALL
# dir phone_dumps
   - directory containing created files so not touching that
# dir reports
   - empty 
# dir scripts
   ## aapt-x86, aapt2, aapt2-3.2.1-4818971-linux.jar, aapt2-3.2.1-4818971-osx.jar,
      - "builds android apps" 
   # android_scan.sh
      - Methods
         1. scan
            -- This scans android phones using serial number (method argument 2) 
            -- Uses dumpsys and method argument 1 to indicate which system to scan
            -- Takes output, censoring all email addresses using regex
         2. scan_spy
            -- After scan, checks the file "./phone_dumps/(modified serial)_android.txt exists which is list of apps on phone
            -- if not, it returns, echoing error message to scan first
            -- else it will search the entire file for the term "spy" sorting the results and removing duplicates 
         3. retrieve
            -- takes in the name of app as first method argument 
            -- Searches through"./phone_dumps/(modified serial)_android.txt exists which is list of apps on phone 
            -- Prints information regarding the app specified (processes, installation date, memroy usage, network data usage, and battery life)
         4. dump
            -- For every service/app in the services array (defined right before), it runs a scan on each
            -- then prints out service stats using /proc/net/xt_qtaguid/stats modifying the output to replace spaces with commas
            -- iterates over list {secure, system, global} using settings list to retrieve them 
         5. full_scan
            -- if the file "./phone_dumps/(modified serial)_android.txt" is too old (20 minutes), calls dump to remake it
            -- also "pulls apks" using the script ./scripts/pull_apks.sh "$serial"
      - Main
         -- First checks number of arguments of the script (needs at least 1)
         --sets platform equal to the OS of the phone
         -- checks to see if adb can be called, setting the command to adb, changing how this is done based on if this is an error (static adb)
         -- prints platform and adb
         -- sets adb to be enviornmental variable 
         -- sets "serial" to be "-s (second arguement)"
         -- sets "hmac_serial" to be "-s (third arguement)"
         -- sets dump_dir to "./phone_dumps/" and sets ofname to be the file of scan ./phone_dumps/(third argument)_android.txt
         -- sets email regex
         -- sets services array to (package location media.camera netpolicy mount cpuinfo dbinfo meminfo procstats batterystats "netstats detail" usagestats activity appops)
         -- if (arguement 1) is "scan", runs "adb devices", appends ./dumps/android_scan.logs with a call of method full_scan, sleeps for 2 minutes, then runs adb (serial) shell pm clear com.android.settings, removing developer options
         -- if (arguement 1) is "info" it will run retrieve on third arguement
         if anything else just echos it out and exits
      - Notes
         -- hmac serial is only used in creation of file, just use normal serial number or rewrite variables to be their arguments instead of relying on $1 $2 and #3, then only use variable names sparingly?

# phone_scanner.py
   - Classes 
      - AppScan(object)
         1. init(self, dev_type, cli)
            -- Checks to see if the "dev_type" is allowed (windows, and ios) which is all setup in config
            -- sets self.device_type = dev_type
            -- sets self.cli = cli 
         2. setup(self)
            -- not implemmented 
         3. devices(self)
            -- not implemented
         4. get_apps(self, serialno: str, from_device: bool) -> list
            -- pass
         5. get_offstore_apps(self, serialno):
            -- return []
         6. dump_path(self, serial, fkind='json')
         7. app_details(self, serialno, appid)
         8. find_spyapps(self, serialno, from_dump=False)
         9. flag_apps(self, serialno)
         10. uninstall
         11. save
         12. device_info
         13. isrooted
      - Android(AppScan)
         1. init(self)
         2. setup(self)
         3. _get_apps_from_device(self, serialno, flag) -> list
         4. _get_apps_from_dump(self, serialno)
         5. get_apps(self, serialno, from_device=True) -> list
         6. get_system_apps(self, serialno, from_device=True)
         7. get_offstore_apps(self, serialno, from_device=False)
         8. devices(self)
         9. device_info(self, serial)
         10. uninstall(self, serial, appid)
         11. app_details(self, serialno, appid)
         12. isrooted(self, serial)
               -- has grayed out
      - IosScan(AppScan)
         1. init(self)
            -- calls AppScan.init('ios',cli=config.LIBIMOBILEDEVICE_PATH)
            -- sets self.installed_apps = None
            -- sets self.serialno = None
            -- sets self.parse_dump = None
            -- NOTE: in config, LIBIMOBILEDEVICE_PATH is set to ' '
         2. setup(self, attempt_remount=False)
            -- 
         3. get_app_titles(self, serialno)
         4. get_apps(self, serialno: str, from_device: bool) -> list
         5. get_system_apps(self, serialno) -> list
         6. devices(self)
         7. device_info(self, serial)
         8. _load_dump(self, serial) -> parse_dump.IosDump
         9. _dump_phone(self, serial: str) -> bool
         10. uninstall(self, serial, appid)
         11. isrooted(self, serial)
      - Test Scan 
         1. init(self)
         2. get_apps(self, serialno)
         3. devices(self)
         4. get_system_apps(self, serialno)
         5. get_offstore_apps(self, serialno)
         6. uninstall(self, serial, appid)
   - Methods
      1. iosScreenshot
         -- sets teh currtime, and gets homeDir, verifying the path to "webstatic/images/screenshots" exists, else it makes it
         -- sets filename to images/screenshots/context_currtime.png
         -- runs "pymobiledevice3 lockdown start-tunnel"
         -- parses output of this to find the RSD Address and PORT
         -- takes screenshot using "pymobiledevice3 developer dvt screenshot " + tempFname + " --rsd " + rsdAddress + " " + rsdPort" 
         -- calls addImage using file name as return value 
   - Main
   - Notes
      -- try to modify addImage return so that tempFname doesn't need to exist.
      --Move this method as soon as possible 
      -- a lot of commented out code, more grayed out code, especially on IOS rooted which doesn't function

# phone_scanner.command
   -- I don't know if this is every actually run 
   -- Delete?

# requirements.txt
   - could remove
      autopep8
      pycodestyle 

