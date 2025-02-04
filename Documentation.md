# __pycache____
   -  Bytecode compiled python files to make the script run 
# .github / workflows
   ## get-stalkerware-indicators.yml
      - Fetches "indicators of stalkerware every week on sunday from AssoEchap/stalkerware-indicators
      - Also runs a pull request from peter-evans/create-pull-request@v5
      - Donwloads and upgrades python dependencies ???
      - This updates the flags and updates the csv in static_data/app-flags.csv which is then used by get-stalkerware-indicators.py
   ## super-linter.yml
      - This runs automating linting checks only on modified files done, having common linters run when it occurs 
# bin
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
      - WE DON'T SEEM TO USE ALEMBIC
   ## similar files to alembic (automatically generated, this is now a list of which seem to be not used)
      - autopep8
      - dotenv
      - mako
      - pycodestyle
