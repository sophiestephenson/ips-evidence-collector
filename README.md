# Sherloc 
### A.K.A. Software to Help with Evidence Retrieval and Log Online Cyberabuse

Sherloc is a tool to support computer security clinics. It is meant to be run by a tech clinic consultant, allowing the consultant to enter findings and investigations. Then, Sherloc enables the consultant to create an evidentiary document synthesizing the consultation.

Sherloc is built on [ISDI](https://github.com/stopipv/isdi), which checks Android or iOS devices for spyware.

## Installing Sherloc :computer:

Right now, Sherloc only natively supports **macOS and Linux**. If you are using a Windows device, you can use the Windows Subsystem for Linux 2
(WSL2), which can be installed by following [these instructions](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After this,
follow the remaining instructions as a Linux user would, cloning/running 
Sherloc inside the Linux container of your choice. 

### Python dependencies
- You will need Python 3.6 or higher (check by running `python3` in your
Terminal and see what happens).  On macOS, you can get this by running the
following commands in your Terminal application:

```bash
# Installs developer tools
xcode-select --install 

# Installs Brew (a software package manager)
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Installs Python
brew install python
```

### Operating system dependencies

#### Generic
* [adb](https://developer.android.com/studio/releases/platform-tools.html)
* expect
* ideviceinstaller

#### macOS
On macOS you can quickly install project dependencies with Homebrew by running `brew bundle`.

You can also fulfill the requirements by doing:
```bash
brew install --cask android-platform-tools
brew install expect libimobiledevice ideviceinstaller
```

#### Debian family

```
sudo apt install adb expect libimobiledevice-utils ideviceinstaller ifuse
```

#### Windows Subsystem Linux (v2)
Installing **adb** is not so straightforward in WSL2, and
it won't work straightaway. You have to ensure having the *same* version of adb
*both* in WSL2 and in normal Windows (with `adb version`), then you will need to
start the adb process first in Windows, then in WSL2 (with for example `adb
devices`).

## Running Sherloc

After Sherloc is installed, run the following command in the terminal (in
the top-level directory of this repository):

```bash
cd sherloc
./sherloc [--nosudo]
```

Sherloc is run in sudo by default, which is required to take screenshots on iPhones using `pymobiledevice3`. If you do not want to run Sherloc with sudo, please use the `--nosudo` flag when running `./sherloc`.

Sherloc should open `http://localhost:6200` in the browser.

## Debugging tips 
If you encounter errors, please file a [GitHub issue](../../issues/) with the server error output. 
Pull requests are welcome. 

#### Android tips 
In the terminal of the computer, run `adb devices` to see if
the device is connected properly.

#### iOS tips 
In the terminal of the computer (in the base directory of this repository), 
run `./static_data/libimobiledevice-darwin/idevice_id -l` to see if
the device is connected properly (replace `darwin` with `linux` if your system is Linux.)

#### Cast iOS Screens or Mirror Android Screens 
It is possible to view your
device screen(s) in real time on the macOS computer in a new window. This may
be useful to have while you are running the scan (and especially if you use the
privacy checkup feature), as it will be easy for you to see the mobile device
screen(s) in real time on the Mac side-by-side with the scanner.

**How to do it:** 
You can mirror Android device screens in a new window using
[scrcpy](https://github.com/Genymobile/scrcpy), and cast iOS device screens on
macOS with QuickTime 10 (launch it and click File --> New Movie Recording -->
(on dropdown by red button) the iPhone/iPad name).

## Downloaded data ## 
The data downloaded and stored in the study are the
following.  1. A `sqlite` database containing the feedback and actions taken by
the user.  2. `phone_dump/` folder will have dump of some services in the
phone.  (For Android I have figured out what are these, for iOS I don't know
how to get those information.)

##### Android 
The services that we can dump safely using `dumpsys` are the
following.
* Application static details: `package` Sensor and configuration info:
* `location`, `media.camera`, `netpolicy`, `mount` Resource information:
* `cpuinfo`, `dbinfo`, `meminfo` Resource consumption: `procstats`,
* `batterystats`, `netstats`, `usagestats` App running information: `activity`,
* `appops`

See details about the services in [notes.md](notes.md)

##### iOS 
Only the `appIds`, and their names. Also, I got "permissions" granted
to the application. I don't know how to get install date, resource usage, etc.
(Any help will be greatly welcomed.)
