# SRX-R515-Tools 📽

Tools for the Sony SRX-R515 SMS Server.

Mostly written in Python.

## cplinfo.py

Returns a list of all Composition Playlists on the SMS Server.

```sh
# show all options
./cplinfo.py --help
# list all CPL as markdown table
./cplinfo.py --server 172.23.31.101 --markdown
# list all CPL as tabulate table
./cplinfo.py --server 172.23.31.101
```
