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
# requirements.txt
   - could remove
      autopep8
      pycodestyle 

