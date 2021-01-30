# nf18acv-ssh-reboot
Python script to remotely reboot NetComm NF18ACV modems/routers/gateways via its integrated SSH interface.

## Installation
1. Choose one of these methods:

    1. Script direct download (the simplest and shortest method):
        ```
        wget https://raw.githubusercontent.com/boonhui/nf18acv-ssh-reboot/main/nf18acv-ssh-reboot.py -O nf18acv-ssh-reboot.py
        ```

    2. You can download the entire repository by using `git clone` or `git clone --depth 1 -b main` followed by the cloning URL above.

2. Create a netrc file to hold credentials necessary to login to your device:

    On a Mac, UNIX, or Linux system the netrc file should be named .netrc (dot netrc) and on Windows it should be named _netrc (underscore netrc). The file should be located in your home directory and the permissions on the file must be set so that you are the only user who can read it, i.e. it is unreadable to everyone else. It should be set to at least Read (400), or Read/Write (600).

    To create the netrc on a Windows machine, first create an environment variable called ’HOME’ that is set to your home directory (c:/Users/<User-Name> on Vista or Windows 7) or any directory you want to use.

    In that directory, create a text file with the prefix appropriate to your system, either an underscore or dot.

    The following lines must be included in the file. The lines must be separated by either white space (spaces, tabs, or newlines) or commas:
    ```
    machine <device ip or name>
    login <username>
    password <password>
    ```

    One example would be:
    ```
    machine 192.168.20.1
    login admin
    password admin
    ```

    Another example would be:
    ```
    machine 192.168.20.1 login admin password admin
    ```

    ---
    Avoid leaving extra newlines at the end of your netrc file. Some applications may interpret these as missing additional entries or premature EOFs.

    ---

## Usage
```
nf18acv-ssh-reboot.py <device ip or name>
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[GPLv3](https://choosealicense.com/licenses/gpl-3.0/)