# Shadowcrypter

## What does it do?
It is a small desktop tool for finding XOR-encryption keys of XML files. (Requirement: the game needs to use XOR-encryption on the save file!)
Max key length (in byte): 16. (Can be adjusted in the code if needed.)

## Youtube tutorial
"Coming soon"

## Features

- **Find key**: enter a known number, auto will try int and float numbers and the tool recovers the key
- **Editor**: view the decrypted values + names in a table. Filter, change values, add rows, delete rows, duplicate...
- **Safety checks**: warns you about overflow (int), NaN/inf (float) and displays changed values yellow (easier to revert)
- **Encrypted file view**: view the raw XML directly after editing. (allows copying without opening the file)
- **Streamer mode**: hide sensitive values from the editor while recording.
- **Themes**: choose between dark, light (eyecancer) or set your custom colours

## Download

Download the latest `Shadowcrypter.exe` from the [Releases page](https://github.com/Cyb3rSh4d0w/Shadowcrypter/releases/latest).

**Sidenote:** 
Due to encryption/decryption patterns, the executable might be flagged by some anti-virus programs. 
The full source is in this repo, so read the code yourself.

## Run from source

```
pip install -r requirements.txt
python Shadowcrypter.py
```

Requires Python 3.8+ with Tkinter (included on Windows; for Linux `sudo apt install python3-tk`).
Pillow is optional and only used for the icon on Linux / macOS.

## 3 step usage

1. **Find key**: pick XML file -> enter known number -> press *Search* -> save key
2. **Editor**: choose the key -> open XML again (the tool copies it into it's own project folder) -> double click on the value -> change it -> control + s
3. **Encrypted file**: shows the XML as it is on disk

## Files created by the tool

- `keys.txt`: all saved keys
- `settings.json`: settings 
- `<name>/<name>.xml`: copied XML file (when the XML file is opened in the Editor)
- `<name>.xml.bak`: one time backup (trust me, you might need it)
- `<name>_unlocked.json`: decrypted export

## Disclaimer

Designed to be used on **single-player / offline** game save files. Editing save files of online games (that lack the knowledge to properly encrypt the save file, have no abnormal stat checks, not enough money for a good server) can get your account banned. The tool edits files in place. The backup is only made once, so make sure to keep your own backups aswell (leave the starting backup, if anything breaks just go back to it). 
Provided as is, use at your own risk.

## License

MIT, see [LICENSE](LICENSE).
