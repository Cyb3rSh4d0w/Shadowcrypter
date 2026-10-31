import base64
import glob
import json
import math
import os
import re
import shutil
import struct
import urllib.parse
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
import sys
import subprocess

try:
    import tkinter as tk
    from tkinter import colorchooser, filedialog, messagebox, ttk
except ImportError: 
    tk = ttk = colorchooser = filedialog = messagebox = None

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)        
    RES_DIR = getattr(sys, "_MEIPASS", APP_DIR)        
else:
    APP_DIR = RES_DIR = os.path.dirname(os.path.abspath(__file__))

KEYS_FILE = os.path.join(APP_DIR, "keys.txt")
SETTINGS_FILE = os.path.join(APP_DIR, "settings.json")
ICON_FILE = os.path.join(RES_DIR, "logo.ico")
XML_HEADER = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>"

M = 0xFFFFFFFF
P1, P2, P3, P4, P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393

def _rol(x, r):
    return ((x << r) | (x >> (32 - r))) & M

def xxh32(data, seed=0):
    n, i = len(data), 0
    if n >= 16:
        v = [(seed + P1 + P2) & M, (seed + P2) & M, seed, (seed - P1) & M]
        while i <= n - 16:
            for j in range(4):
                v[j] = (_rol((v[j] + struct.unpack_from("<I", data, i)[0] * P2) & M, 13) * P1) & M
                i += 4
        h = (_rol(v[0], 1) + _rol(v[1], 7) + _rol(v[2], 12) + _rol(v[3], 18)) & M
    else:
        h = (seed + P5) & M
    h = (h + n) & M
    while i <= n - 4:
        h = (_rol((h + struct.unpack_from("<I", data, i)[0] * P3) & M, 17) * P4) & M
        i += 4
    while i < n:
        h = (_rol((h + data[i] * P5) & M, 11) * P1) & M
        i += 1
    h ^= h >> 15
    h = (h * P2) & M
    h ^= h >> 13
    h = (h * P3) & M
    h ^= h >> 16
    return h

def load_keys():
    keys = {}
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, hexs = line.split("=", 1)
                hexs = re.sub(r"[^0-9a-fA-F]", "", hexs)
                if name.strip() and len(hexs) >= 2 and len(hexs) % 2 == 0:
                    keys[name.strip()] = bytes.fromhex(hexs)
    return keys

def save_key(name, key):
    keys = load_keys()
    keys[name] = key
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        f.write("# name = key in hex\n")
        for n, k in keys.items():
            f.write(f"{n} = {k.hex()}\n")

THEMES = {
    "dark": {"bg": "#1e1f26", "fg": "#e6e6e6", "field": "#2a2c36", "select": "#3d6fb4"},
    "light": {"bg": "#f0f0f0", "fg": "#000000", "field": "#ffffff", "select": "#3584e4"},
}
COLOR_LABELS = (("bg", "Background"), ("fg", "Text"), ("field", "Fields"), ("select", "Selection"))
DEFAULT_SETTINGS = {
    "theme": "light",  
    "custom": dict(THEMES["dark"]),
    "streamer": False,
    "mask_all": False,
    "keywords": ["token", "password", "secret", "mail", "user", "account", "steam", "login", "auth",
                 "session", "license", "serial", "phone", "address", "nick", "uuid", "guid", "device",
                 "playername", "player_name"],
}

def load_settings():
    cfg = json.loads(json.dumps(DEFAULT_SETTINGS))  
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        cfg["custom"].update(data.pop("custom", {}))
        cfg.update({k: v for k, v in data.items() if k in cfg})
    except (OSError, ValueError, AttributeError):
        pass
    return cfg

def save_settings(cfg):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass

def palette(cfg):
    return cfg["custom"] if cfg["theme"] == "custom" else THEMES.get(cfg["theme"], THEMES["light"])

def is_dark(color):
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.299 * r + 0.587 * g + 0.114 * b < 128

def row_colors(pal):
    dark = is_dark(pal["bg"])
    return {"mod": "#5c5220" if dark else "#fff3c4",
            "new": "#245a2c" if dark else "#d6f5d6",
            "sus": "#6b2626" if dark else "#ffd6d6"}

def mask(name, cfg, tag=""):
    """Streamer mode: hide sensitive names (keyword match, or all names) on screen only."""
    if cfg["streamer"] and (cfg["mask_all"] or any(k in name.lower() for k in cfg["keywords"])):
        return "••••••••" + tag
    return name

NAME_RE = re.compile(r"^[A-Za-z0-9_\-. ]+$")
TAGS = {"int": 0x05, "float": 0x14}

def unb64(s):
    s = urllib.parse.unquote(s)
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)

def b64q(b):
    return urllib.parse.quote(base64.b64encode(b).decode(), safe="")

def xor_text(text, key):
    return "".join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(text))

def decrypt_name(raw, key):
    try:
        name = xor_text(unb64(raw).decode("utf-8"), key)
    except Exception:
        return None
    return name if NAME_RE.match(name) else None

def encrypt_name(name, key):
    return b64q(xor_text(name, key).encode("utf-8"))

def split_value(text):
    """Return raw bytes if the text looks like an encrypted value, else None."""
    try:
        raw = unb64(text)
    except Exception:
        return None
    if len(raw) < 7 or raw[-6:-4] != b"\x04\x00":
        return None
    return raw

def decode_value(raw, key):
    data, tag, trailer = raw[:-7], raw[-7], raw[-4:]
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    if tag in (0x05, 0x14) and len(data) == 4:
        ok = struct.pack("<I", xxh32(plain)) == trailer
        if tag == 0x14:
            return "float", struct.unpack("<f", plain)[0], ok
        return "int", struct.unpack("<i", plain)[0], ok
    if tag == 0x0F:
        head = plain[:4].decode("latin-1")
        tail = "".join(chr(b) if 32 <= b < 127 else "·" for b in data[4:])
        return "string_enc", head + tail, None
    return "raw_enc", raw.hex(), None

def encode_number(value, kind, key):
    plain = struct.pack("<f", float(value)) if kind == "float" else struct.pack("<i", int(value))
    enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(plain))
    return b64q(enc + bytes([TAGS[kind], 4, 0]) + struct.pack("<I", xxh32(plain)))

ADDABLE = {  
    "int (encrypted)": "int",
    "float (encrypted)": "float",
    "int (plain, not encrypted)": "plain_int",
    "string (plain, not encrypted)": "plain_string",
}
ENCRYPTED_NUMBER = ("int", "float")

def parse_entries(path, key):
    entries = []
    for el in ET.parse(path).getroot():
        e = {"tag": el.tag, "id": el.get("name", "")}
        if el.tag == "int":
            e.update(kind="plain_int", name=urllib.parse.unquote(e["id"]), value=int(el.get("value")))
        elif el.tag == "string":
            text = el.text or ""
            raw, name = split_value(text), decrypt_name(e["id"], key)
            if raw is not None and name is not None:
                kind, val, ok = decode_value(raw, key)
                e.update(kind=kind, name=name, value=val, ok=ok, raw=text)
            elif raw is not None:
                e.update(kind="raw_enc", name="[undecoded] " + e["id"], value=raw.hex(), raw=text)
            else:
                e.update(kind="plain_string", name=urllib.parse.unquote(e["id"]), value=text)
        else:
            e.update(kind="other", name=urllib.parse.unquote(e["id"]), value="",
                     xml=ET.tostring(el, encoding="unicode").strip())
        e["orig"] = {"kind": e["kind"], "value": e["value"], "name": e["name"]}
        entries.append(e)
    return entries

def parse_value(kind, text):
    """Convert user text to a value of the given kind; raises ValueError/OverflowError.

    NaN / infinity are accepted here; the GUI asks for confirmation (see App._confirm_value).
    """
    if kind in ("int", "plain_int"):
        v = int(text.strip())
        if not -2**31 <= v < 2**31:
            raise ValueError("Integer must fit in 32 bit (-2147483648 … 2147483647).")
        return v
    if kind == "float":
        v = float(text.strip())
        struct.pack("<f", v) 
        return v
    return text

def check_name(name, kind):
    """Validate a (new) entry name; returns the cleaned name."""
    if not name or not name.isascii() or not name.isprintable():
        raise ValueError("Name must be printable ASCII.")
    if kind in ENCRYPTED_NUMBER + ("string_enc",) and not NAME_RE.match(name):
        raise ValueError("Encrypted names may only contain letters, digits, _ - . and space "
                         "(otherwise the game / this tool cannot read them back).")
    return name

def make_entry(name, kind, text):
    """Build a brand new entry (no 'orig' -> shown as NEW)."""
    if kind not in ADDABLE.values():
        raise ValueError("This row type cannot be created.")
    name = check_name(name.strip(), kind)
    value = text if kind == "plain_string" else parse_value(kind, text)
    e = {"tag": "int" if kind == "plain_int" else "string", "id": "", "kind": kind,
         "name": name, "value": value, "orig": None}
    if kind in ENCRYPTED_NUMBER:
        e["ok"] = True
    return e

def entry_id(e, key):
    """Keep the original id unless the clear name was changed."""
    k = e["kind"]
    if k in ("int", "float", "string_enc"):
        return e["id"] if decrypt_name(e["id"], key) == e["name"] else encrypt_name(e["name"], key)
    if k in ("plain_int", "plain_string"):
        return e["id"] if urllib.parse.unquote(e["id"]) == e["name"] else urllib.parse.quote(e["name"], safe="._-")
    return e["id"]

def attr(s):
    return escape(s, {'"': "&quot;"})

def entry_xml(e, key):
    k = e["kind"]
    if k == "other":
        return "    " + e["xml"]
    eid = attr(entry_id(e, key))
    if k == "plain_int":
        return f'    <int name="{eid}" value="{int(e["value"])}" />'
    if k in ("int", "float"):
        text = encode_number(e["value"], k, key)
    elif k in ("string_enc", "raw_enc"):
        text = e["raw"]
    else:
        text = e["value"]
    return f'    <string name="{eid}">{escape(text)}</string>'

def build_xml(entries, key):
    lines = [XML_HEADER, "<map>"] + [entry_xml(e, key) for e in entries] + ["</map>"]
    return "\n".join(lines) + "\n"

def entries_to_json(entries):
    out = []
    for e in entries:
        item = {"name": e["name"], "type": e["kind"], "value": e["value"], "id": e["id"]}
        if e["kind"] in ("string_enc", "raw_enc"):
            item["raw"] = e["raw"]
        if e["kind"] == "other":
            item["xml"] = e["xml"]
        out.append(item)
    return out

def ensure_workspace(path, on_conflict=None):
    path = os.path.abspath(path)
    folder, app = os.path.dirname(path), os.path.abspath(APP_DIR)
    try:
        inside = folder != app and os.path.commonpath([folder, app]) == app
    except ValueError:  
        inside = False
    if inside:
        return path, None
    stem = os.path.splitext(os.path.basename(path))[0]
    target_dir = os.path.join(app, stem)
    target = os.path.join(target_dir, os.path.basename(path))
    os.makedirs(target_dir, exist_ok=True)
    if os.path.exists(target):
        if (on_conflict(target) if on_conflict else "keep") == "keep":
            return target, f"Using existing {stem}/{os.path.basename(path)}"
    (shutil.move if folder == app else shutil.copy2)(path, target)
    verb = "moved" if folder == app else "copied"
    return target, f"{os.path.basename(path)} {verb} into folder {stem}/"

def suspicious(e):
    """Hints for values the game may not handle."""
    v = e["value"]
    if e["kind"] == "float":
        return "not finite" if not math.isfinite(v) else ""
    if e["kind"] not in ("int", "plain_int"):
        return ""
    if abs(v) > 2147483647:
        return "beyond 32-bit int range"
    if abs(v) >= 100000000:
        return "very large"
    if v < 0:
        return "negative"
    return ""

def same(a, b):
    """Equality that treats NaN as equal to NaN."""
    return a == b or (a != a and b != b)

def is_new(e):
    return e.get("orig") is None

def is_modified(e):
    o = e.get("orig")
    return bool(o) and (o["kind"] != e["kind"] or o["name"] != e["name"] or not same(o["value"], e["value"]))

def unique_name(entries, base):
    names = {e["name"] for e in entries}
    if base not in names:
        return base
    i = 2
    while f"{base}_{i}" in names:
        i += 1
    return f"{base}_{i}"

def backup_once(path):
    bak = path + ".bak"
    if os.path.exists(path) and not os.path.exists(bak):
        shutil.copy2(path, bak)

def unlocked_path(xml_path):
    return os.path.splitext(xml_path)[0] + "_unlocked.json"

def write_json(path, entries):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(entries_to_json(entries), f, indent=2, ensure_ascii=False)

VALID = {ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-. "}
_FREQ = {"E": 12.7, "T": 9.1, "A": 8.2, "O": 7.5, "I": 7.0, "N": 6.7, "S": 6.3, "R": 6.0, "H": 6.1,
         "D": 4.3, "L": 4.0, "C": 2.8, "U": 2.8, "M": 2.4, "W": 2.4, "F": 2.2, "G": 2.0, "Y": 2.0,
         "P": 1.9, "B": 1.5, "V": 1.0, "K": 0.8, "J": 0.15, "X": 0.15, "Q": 0.1, "Z": 0.07}

WEIGHT = {ord("_"): 2.4}
for _c, _f in _FREQ.items():
    WEIGHT[ord(_c)] = math.log(_f)
    WEIGHT[ord(_c.lower())] = math.log(_f * 0.3)
for _c in "0123456789":
    WEIGHT[ord(_c)] = math.log(2.0)
for _c in "-. ":
    WEIGHT[ord(_c)] = math.log(0.5)
BAD = math.log(0.0005)

def _best_byte(chars):
    best, best_score = 0, None
    for k in range(256):
        sc = sum(WEIGHT.get(c ^ k, BAD) for c in chars)
        if best_score is None or sc > best_score:
            best, best_score = k, sc
    return best

def _quality(texts, key):
    total = good = 0
    for t in texts:
        for i, c in enumerate(t):
            total += 1
            good += (ord(c) ^ key[i % len(key)]) in VALID
    return good / total if total else 0.0

def derive_key(head, texts, length=0, max_len=64):
    options = []
    lengths = [length] if length else range(4, max_len + 1)
    for L in lengths:
        if L <= 4:
            key = bytes(head[:L]) if L else bytes(head)
        else:
            key = list(head)
            for p in range(4, L):
                chars = [ord(t[i]) for t in texts for i in range(p, len(t), L)]
                if not chars:
                    break
                key.append(_best_byte(chars))
            if len(key) < L:
                continue
            key = bytes(key)
        options.append((_quality(texts, key), L, key))
    if not options:
        return bytes(head), 0.0
    top = max(o[0] for o in options)
    for score, L, key in sorted(options, key=lambda o: o[1]):
        if score >= top - 0.001:
            return key, score

def search_key(path, number_text, kind="auto", length=0):
    values = []
    for el in ET.parse(path).getroot():
        if el.tag == "string":
            raw = split_value(el.text or "")
            if raw is not None:
                values.append((el.get("name", ""), raw))
    plains = []
    try:
        iv = int(number_text)
        if kind in ("auto", "int") and -2**31 <= iv < 2**31:
            plains.append(("int", 0x05, struct.pack("<i", iv)))
    except ValueError:
        pass
    try:
        fv = float(number_text)
        if kind in ("auto", "float"):
            plains.append(("float", 0x14, struct.pack("<f", fv)))
    except (ValueError, OverflowError):
        pass
    heads = {}
    for eid, raw in values:
        if len(raw) != 11:
            continue
        for k, tag, plain in plains:
            if raw[-7] == tag and struct.pack("<I", xxh32(plain)) == raw[-4:]:
                head = bytes(a ^ b for a, b in zip(raw[:4], plain))
                heads.setdefault(head, []).append((eid, k))
    texts = []
    for eid, _ in values:
        try:
            texts.append(unb64(eid).decode("utf-8"))
        except Exception:
            pass
    results = []
    for head, matches in heads.items():
        key, score = derive_key(head, texts, length)
        results.append({"head": head, "key": key, "score": score, "matches": matches})
    results.sort(key=lambda r: -len(r["matches"]))
    return results, texts

def preview_names(texts, key, limit=12):
    return [xor_text(t, key) for t in texts[:limit]]

def xml_files():
    """XML files in the app folder and its sub folders (relative paths)."""
    found = glob.glob(os.path.join(APP_DIR, "**", "*.xml"), recursive=True)
    return sorted(os.path.relpath(p, APP_DIR) for p in found)

def fmt_num(kind, v):
    return f"{v:.9g}" if kind == "float" else str(v)

def fmt_value(e):
    return fmt_num(e["kind"], e["value"])

def open_folder(path):
    try:
        if os.name == "nt":
            os.startfile(path)  
        elif sys.platform == "darwin":
            subprocess.run(["open", path])
        else:
            subprocess.run(["xdg-open", path])
    except Exception:
        pass

def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)

class App(tk.Tk if tk else object):
    def __init__(self):
        super().__init__()
        self.title("Shadowcrypter")
        self.geometry("1020x680")
        self.keys = load_keys()
        self.settings = load_settings()
        self.key_boxes = []
        self.style = ttk.Style(self)
        self.style.theme_use("clam") 
        self._set_icon()
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.tab_find, self.tab_edit, self.tab_view, self.tab_set = (ttk.Frame(nb) for _ in range(4))
        nb.add(self.tab_find, text="1. Find key")
        nb.add(self.tab_edit, text="2. Editor")
        nb.add(self.tab_view, text="3. Encrypted file")
        nb.add(self.tab_set, text="4. Settings")
        self._build_find()
        self._build_edit()
        self._build_view()
        self._build_settings()
        self.apply_theme()

    def _set_icon(self):
        if not os.path.exists(ICON_FILE):
            return
        try:
            self.iconbitmap(default=ICON_FILE)  
        except tk.TclError:  
            try:
                from PIL import Image, ImageTk
                self._icon = ImageTk.PhotoImage(Image.open(ICON_FILE))
                self.iconphoto(True, self._icon)
            except Exception:
                pass

    def apply_theme(self):
        pal = self.pal = palette(self.settings)
        bg, fg, field, sel = pal["bg"], pal["fg"], pal["field"], pal["select"]
        st = self.style
        st.configure(".", background=bg, foreground=fg, fieldbackground=field, troughcolor=bg,
                     bordercolor=field, lightcolor=field, darkcolor=field, insertcolor=fg,
                     selectbackground=sel, selectforeground="#ffffff")
        st.configure("TNotebook", background=bg)
        st.configure("TNotebook.Tab", background=field, foreground=fg, padding=(10, 4))
        st.map("TNotebook.Tab", background=[("selected", bg)])
        st.configure("TButton", background=field)
        st.map("TButton", background=[("active", sel)])
        st.map("TCombobox", fieldbackground=[("readonly", field)], foreground=[("readonly", fg)],
               selectbackground=[("readonly", field)], selectforeground=[("readonly", fg)])
        st.map("Treeview", background=[("selected", sel)], foreground=[("selected", "#ffffff")])
        st.configure("Treeview", background=field, foreground=fg)
        st.configure("Treeview.Heading", background=field, foreground=fg)
        st.map("Treeview.Heading", background=[("active", sel)])
        st.configure("TScrollbar", background=field, arrowcolor=fg)
        for style in ("TCheckbutton", "TRadiobutton"):
            st.map(style, background=[("active", bg)], indicatorcolor=[("selected", sel)])
        self.configure(bg=bg)
        for opt, val in (("background", field), ("foreground", fg),
                         ("selectBackground", sel), ("selectForeground", "#ffffff")):
            self.option_add(f"*TCombobox*Listbox.{opt}", val) 
        rows = row_colors(pal)
        for w in walk(self):
            try:
                if isinstance(w, tk.Text):
                    w.configure(bg=field, fg=fg, insertbackground=fg, selectbackground=sel)
                elif isinstance(w, tk.Toplevel):
                    w.configure(bg=bg)
                elif isinstance(w, ttk.Treeview):
                    for tag, color in rows.items():
                        w.tag_configure(tag, background=color, foreground=fg)
                elif isinstance(w, ttk.Combobox):  
                    pop = self.tk.eval(f"ttk::combobox::PopdownWindow {w}")
                    self.tk.call(f"{pop}.f.l", "configure", "-background", field, "-foreground", fg,
                                 "-selectbackground", sel, "-selectforeground", "#ffffff")
            except tk.TclError:
                pass
        for key, sw in self.s_swatch.items():
            sw.configure(bg=self.settings["custom"][key])

    def shown(self, e, i=None):
        return mask(e["name"], self.settings, f" #{i + 1}" if i is not None else "")

    def is_hidden(self, name):
        return mask(name, self.settings) != name

    def key_combo(self, parent):
        cb = ttk.Combobox(parent, state="readonly", width=24, values=sorted(self.keys))
        if self.keys:
            cb.current(0)
        self.key_boxes.append(cb)
        return cb

    def refresh_keys(self, select=None):
        self.keys = load_keys()
        for cb in self.key_boxes:
            cb["values"] = sorted(self.keys)
            if select and select in self.keys:
                cb.set(select)
            elif not cb.get() and self.keys:
                cb.current(0)

    def get_key(self, cb):
        name = cb.get()
        if name not in self.keys:
            messagebox.showerror("Key", "Choose a key first (create one in tab 1 or add a line "
                                        "'name = hex' to keys.txt, then press Reload keys).")
            return None
        return self.keys[name]

    def _conflict(self, target):
        rel = os.path.relpath(target, APP_DIR)
        yes = messagebox.askyesno("File already exists",
                                  f"{rel} already exists.\n\nYes = replace it with the selected file\n"
                                  "No = open the existing one instead")
        return "replace" if yes else "keep"

    def workspace(self, path):
        return ensure_workspace(path, self._conflict)

    def _path(self, name):
        return name if os.path.isabs(name) else os.path.join(APP_DIR, name)

    def _build_find(self):
        f = self.tab_find
        top = ttk.Frame(f)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Label(top, text="XML file:").grid(row=0, column=0, sticky="w")
        self.f_file = ttk.Combobox(top, values=xml_files(), width=40)
        self.f_file.grid(row=0, column=1, padx=4)
        if xml_files():
            self.f_file.current(0)
        ttk.Button(top, text="Browse…", command=self._find_browse).grid(row=0, column=2)
        ttk.Label(top, text="Known number:").grid(row=1, column=0, sticky="w", pady=6)
        self.f_num = ttk.Entry(top, width=20)
        self.f_num.grid(row=1, column=1, sticky="w", padx=4)
        ttk.Label(top, text="Type:").grid(row=1, column=2, sticky="e")
        self.f_kind = ttk.Combobox(top, values=["auto", "int", "float"], width=7, state="readonly")
        self.f_kind.current(0)
        self.f_kind.grid(row=1, column=3, padx=4)
        ttk.Label(top, text="Key length (0 = auto):").grid(row=1, column=4)
        self.f_len = ttk.Spinbox(top, from_=0, to=16, width=4)
        self.f_len.set(0)
        self.f_len.grid(row=1, column=5, padx=4)
        ttk.Button(top, text="Search", command=self.do_search).grid(row=1, column=6, padx=8)

        cols = ("key", "len", "matches", "quality")
        self.f_tree = ttk.Treeview(f, columns=cols, show="headings", height=6)
        for c, w in zip(cols, (420, 60, 80, 90)):
            self.f_tree.heading(c, text=c)
            self.f_tree.column(c, width=w)
        self.f_tree.pack(fill="x", padx=8)
        self.f_tree.bind("<<TreeviewSelect>>", self._find_select)

        mid = ttk.Frame(f)
        mid.pack(fill="x", padx=8, pady=6)
        ttk.Label(mid, text="Key (hex, editable):").pack(side="left")
        self.f_hex = ttk.Entry(mid, width=40)
        self.f_hex.pack(side="left", padx=4)
        ttk.Button(mid, text="Preview names", command=self._find_preview).pack(side="left")
        ttk.Label(mid, text="Save as:").pack(side="left", padx=(16, 2))
        self.f_name = ttk.Entry(mid, width=16)
        self.f_name.pack(side="left")
        ttk.Button(mid, text="Save key", command=self._find_save).pack(side="left", padx=6)
        self.f_prev = tk.Text(f, height=12)
        self.f_prev.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.f_results, self.f_texts = [], []

    def _find_browse(self):
        p = filedialog.askopenfilename(initialdir=APP_DIR, filetypes=[("XML", "*.xml"), ("All", "*.*")])
        if p:
            self.f_file.set(p)

    def do_search(self):
        try:
            self.f_results, self.f_texts = search_key(
                self._path(self.f_file.get()), self.f_num.get().strip(), self.f_kind.get(), int(self.f_len.get() or 0))
        except Exception as ex:
            messagebox.showerror("Search", str(ex))
            return
        self.f_tree.delete(*self.f_tree.get_children())
        for i, r in enumerate(self.f_results):
            self.f_tree.insert("", "end", iid=str(i), values=(r["key"].hex(), len(r["key"]),
                                                              len(r["matches"]), f"{r['score']:.0%}"))
        self.f_prev.delete("1.0", "end")
        if not self.f_results:
            self.f_prev.insert("end", "No entry with that number found.\nCheck the number, the type (int/float) "
                                      "and that it is the value stored in the file (the game may show +1).")
        else:
            self.f_tree.selection_set("0")

    def _find_select(self, _=None):
        sel = self.f_tree.selection()
        if not sel:
            return
        r = self.f_results[int(sel[0])]
        self.f_hex.delete(0, "end")
        self.f_hex.insert(0, r["key"].hex())
        self._find_preview(r)

    def _find_preview(self, r=None):
        try:
            key = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", self.f_hex.get()))
            assert key
        except Exception:
            messagebox.showerror("Key", "Invalid hex key.")
            return
        self.f_prev.delete("1.0", "end")
        if isinstance(r, dict):
            self.f_prev.insert("end", "Matched entries: " + ", ".join(m[1] + ":" + m[0][:16] for m in r["matches"][:6]) + "\n\n")
        names = [mask(n, self.settings) for n in preview_names(self.f_texts, key, 40)]
        self.f_prev.insert("end", "Names with this key:\n" + "\n".join(names))

    def _find_save(self):
        name = self.f_name.get().strip()
        try:
            key = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", self.f_hex.get()))
        except ValueError:
            key = b""
        if not name or not key:
            messagebox.showerror("Save key", "Enter a key name and a valid hex key.")
            return
        save_key(name, key)
        self.refresh_keys(select=name)
        messagebox.showinfo("Save key", f"Saved '{name}' to keys.txt")

    def _build_edit(self):
        f = self.tab_edit
        top = ttk.Frame(f)
        top.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Label(top, text="Key:").pack(side="left")
        self.e_key = self.key_combo(top)
        self.e_key.pack(side="left", padx=4)
        ttk.Button(top, text="Reload keys", command=self.refresh_keys).pack(side="left")
        ttk.Button(top, text="Open XML…", command=self.edit_open).pack(side="left", padx=4)
        ttk.Button(top, text="Reload", command=self.edit_reload).pack(side="left")
        ttk.Button(top, text="Save (Ctrl+S)", command=self.edit_save).pack(side="left", padx=8)
        self.e_auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Auto-save after each edit", variable=self.e_auto).pack(side="left", padx=8)
        ttk.Label(top, text="Filter:").pack(side="left", padx=(12, 2))
        self.e_filter = tk.StringVar()
        self.e_filter.trace_add("write", lambda *_: self.edit_fill())
        ttk.Entry(top, textvariable=self.e_filter, width=18).pack(side="left")

        bar = ttk.Frame(f)
        bar.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(bar, text="+ Add row…", command=self.edit_add).pack(side="left")
        ttk.Button(bar, text="Duplicate", command=self.edit_duplicate).pack(side="left", padx=4)
        ttk.Button(bar, text="Delete (Del)", command=self.edit_delete).pack(side="left")
        ttk.Button(bar, text="Revert selected", command=self.edit_revert).pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Swap int ↔ float", command=self.edit_swap).pack(side="left", padx=4)
        ttk.Button(bar, text="Open folder", command=lambda: self.e_path and open_folder(os.path.dirname(self.e_path))
                   ).pack(side="left")
        ttk.Label(bar, text="yellow = changed, green = new, red = suspicious (⚠)").pack(side="left", padx=12)

        cols = ("name", "type", "value", "orig", "chk")
        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True, padx=8)
        self.e_tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended")
        heads = {"name": "name", "type": "type", "value": "value", "orig": "original", "chk": "check"}
        for c, w in zip(cols, (340, 100, 270, 200, 70)):
            self.e_tree.heading(c, text=heads[c])
            self.e_tree.column(c, width=w)
        sb = ttk.Scrollbar(wrap, command=self.e_tree.yview)
        self.e_tree.configure(yscrollcommand=sb.set)
        self.e_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.e_tree.bind("<Double-1>", self.edit_cell)
        self.e_tree.bind("<Delete>", lambda _: self.edit_delete())
        self.bind("<Control-s>", lambda _: self.edit_save())
        self.e_status = ttk.Label(f, text="No file open.", wraplength=960, justify="left")
        self.e_status.pack(fill="x", padx=8, pady=6)
        self.e_path, self.e_entries, self.e_use_key, self.e_head = None, [], None, ""

    def edit_open(self):
        p = filedialog.askopenfilename(initialdir=APP_DIR, filetypes=[("XML", "*.xml")])
        if not p:
            return
        try:
            self.e_path, note = self.workspace(p)
        except Exception as ex:
            messagebox.showerror("Open", str(ex))
            return
        self.edit_reload(note)

    def edit_reload(self, note=None):
        key = self.get_key(self.e_key)
        if key is None or not self.e_path:
            return
        try:
            self.e_entries = parse_entries(self.e_path, key)
        except Exception as ex:
            messagebox.showerror("Open", str(ex))
            return
        self.e_use_key = key
        self.edit_fill()
        self.edit_status(note or "")
        self.viewer_follow()

    def edit_status(self, head=None):
        """Rebuild the status text from the current entries (so streamer mode can re-mask it)."""
        if head is not None:
            self.e_head = head
        if not self.e_path:
            return
        enc = [e for e in self.e_entries if e["kind"] in ("int", "float", "string_enc", "raw_enc")]
        bad = sum(1 for e in enc if e["kind"] == "raw_enc")
        lines = [self.e_head] if self.e_head else []
        lines.append(f"{os.path.relpath(self.e_path, APP_DIR)}: {len(self.e_entries)} entries, "
                     f"{len(enc) - bad} decrypted, {bad} undecodable"
                     + ("  (wrong key?)" if enc and bad == len(enc) else ""))
        sus = [f"{self.shown(e)} ({fmt_value(e)}: {suspicious(e)})" for e in self.e_entries if suspicious(e)]
        if sus:
            lines.append("⚠ Suspicious: " + "; ".join(sus[:8]) + (" …" if len(sus) > 8 else ""))
        self.e_status.config(text="\n".join(lines))

    def edit_fill(self, select=None):
        flt = self.e_filter.get().lower()
        self.e_tree.delete(*self.e_tree.get_children())
        for i, e in enumerate(self.e_entries):
            if flt and flt not in e["name"].lower():
                continue
            sus = suspicious(e)
            chk = ("" if e.get("ok") is None else ("✓" if e["ok"] else "✗")) + ("⚠" if sus else "")
            new, mod = is_new(e), is_modified(e)
            o = e.get("orig")
            if new:
                orig = "NEW"
            else:
                orig = (f"{mask(o['name'], self.settings)}  " if o["name"] != e["name"] else "") + \
                       (fmt_num(o["kind"], o["value"]) if mod and o["value"] != "" else "")
            tags = ("sus",) if sus else (("new",) if new else (("mod",) if mod else ()))
            self.e_tree.insert("", "end", iid=str(i), tags=tags,
                               values=(self.shown(e, i), e["kind"], fmt_value(e), orig, chk))
        if select:
            ids = [str(i) for i in select if self.e_tree.exists(str(i))]
            if ids:
                self.e_tree.selection_set(ids)
                self.e_tree.see(ids[0])

    def edit_cell(self, event):
        row, col = self.e_tree.identify_row(event.y), self.e_tree.identify_column(event.x)
        if not row or col not in ("#1", "#3"):
            return
        e = self.e_entries[int(row)]
        field = "name" if col == "#1" else "value"
        if field == "value" and e["kind"] in ("string_enc", "raw_enc", "other"):
            messagebox.showinfo("Read-only", "Encrypted strings / unknown entries are kept unchanged.")
            return
        if field == "name" and e["kind"] in ("raw_enc", "other"):
            messagebox.showinfo("Read-only", "This entry's name cannot be decoded, so it is kept unchanged.")
            return
        bbox = self.e_tree.bbox(row, col)
        if not bbox:
            return
        x, y, w, h = bbox
        box = ttk.Entry(self.e_tree)
        box.place(x=x, y=y, width=w, height=h)
        if field == "value":
            box.insert(0, fmt_value(e))
        elif not self.is_hidden(e["name"]):  
            box.insert(0, e["name"])
        box.focus()
        box.select_range(0, "end")
        done = {"v": False}

        def commit(_=None):
            if done["v"]:
                return
            done["v"] = True
            text = box.get()
            box.destroy()
            self.apply_edit(int(row), field, text)

        box.bind("<Return>", commit)
        box.bind("<FocusOut>", commit)
        box.bind("<Escape>", lambda _: (done.update(v=True), box.destroy()))

    def _confirm_value(self, kind, v, parent=None):
        """Ask before writing values the game may not survive."""
        if kind in ("int", "plain_int") and v >= 2147483647:
            return messagebox.askyesno(
                "Very large", "2147483647 is the int maximum. The game may add 1 and overflow to "
                              "-2147483648 (this broke the stat display before).\n\nUse it anyway?", parent=parent)
        if kind == "float" and not math.isfinite(v):
            return messagebox.askyesno(
                "NaN / infinity", "NaN and infinity are usually not handled by games and can break stats, "
                                  "calculations or the whole save (the .bak keeps the original).\n\nUse it anyway?",
                icon="warning", parent=parent)
        return True

    def apply_edit(self, idx, field, text):
        e = self.e_entries[idx]
        try:
            if field == "name":
                if not text or text == e["name"]:
                    return
                e["name"] = check_name(text, e["kind"])
            else:
                v = parse_value(e["kind"], text)
                if same(v, e["value"]) or not self._confirm_value(e["kind"], v):
                    return
                e["value"] = v
            if e.get("ok") is not None:
                e["ok"] = True
        except (ValueError, OverflowError, struct.error) as ex:
            messagebox.showerror("Invalid value", str(ex))
            return
        self.edit_fill(select=[idx])
        self.edit_status()
        if self.e_auto.get():
            self.edit_save()

    def _selected_idx(self):
        return sorted(int(i) for i in self.e_tree.selection())

    def _need_file(self):
        if not self.e_path or self.e_use_key is None:
            messagebox.showinfo("Editor", "Open an XML file first.")
            return False
        return True

    def _changed(self, select=None):
        """Common tail of every table change."""
        self.edit_fill(select=select)
        self.edit_status()
        if self.e_auto.get():
            self.edit_save()

    def edit_add(self):
        if not self._need_file():
            return
        dlg = tk.Toplevel(self)
        dlg.title("Add row")
        dlg.configure(bg=self.pal["bg"])
        dlg.transient(self)
        dlg.resizable(False, False)
        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Name:").grid(row=0, column=0, sticky="w", pady=3)
        name = ttk.Entry(frm, width=36)
        name.grid(row=0, column=1, pady=3)
        ttk.Label(frm, text="Type:").grid(row=1, column=0, sticky="w", pady=3)
        kind = ttk.Combobox(frm, values=list(ADDABLE), state="readonly", width=33)
        kind.current(0)
        kind.grid(row=1, column=1, pady=3)
        ttk.Label(frm, text="Value:").grid(row=2, column=0, sticky="w", pady=3)
        value = ttk.Entry(frm, width=36)
        value.insert(0, "0")
        value.grid(row=2, column=1, pady=3)
        ttk.Label(frm, text="Position:").grid(row=3, column=0, sticky="w", pady=3)
        pos = ttk.Combobox(frm, values=["After selected row", "At end", "At top"], state="readonly", width=33)
        pos.current(0 if self.e_tree.selection() else 1)
        pos.grid(row=3, column=1, pady=3)
        msg = ttk.Label(frm, text="", foreground="#e05555", wraplength=330)
        msg.grid(row=4, column=0, columnspan=2, sticky="w")

        def submit(close):
            try:
                e = make_entry(name.get(), ADDABLE[kind.get()], value.get())
            except (ValueError, OverflowError, struct.error) as ex:
                msg.config(text=str(ex), foreground="#e05555")
                return
            if not self._confirm_value(e["kind"], e["value"], parent=dlg):
                return
            if any(x["name"] == e["name"] for x in self.e_entries) and not messagebox.askyesno(
                    "Duplicate name", f"A row named '{self.shown(e)}' already exists. Add another one anyway?",
                    parent=dlg):
                return
            sel = self._selected_idx()
            if pos.get() == "At end" or (pos.get() == "After selected row" and not sel):
                at = len(self.e_entries)
            elif pos.get() == "At top":
                at = 0
            else:
                at = sel[-1] + 1
            self.e_entries.insert(at, e)
            if self.e_filter.get():
                self.e_filter.set("")
            self._changed(select=[at])
            if close:
                dlg.destroy()
            else:
                msg.config(text=f"Added '{self.shown(e)}'.", foreground="#3fae5a")
                name.delete(0, "end")
                name.focus()
                pos.current(0)  

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="Add", command=lambda: submit(True)).pack(side="left", padx=4)
        ttk.Button(btns, text="Add & keep open", command=lambda: submit(False)).pack(side="left", padx=4)
        ttk.Button(btns, text="Close", command=dlg.destroy).pack(side="left")
        dlg.bind("<Return>", lambda _: submit(True))
        dlg.bind("<Escape>", lambda _: dlg.destroy())
        name.focus()
        dlg.grab_set()

    def edit_duplicate(self):
        if not self._need_file():
            return
        sel = [i for i in self._selected_idx()
               if self.e_entries[i]["kind"] in ("int", "float", "plain_int", "plain_string")]
        if not sel:
            messagebox.showinfo("Duplicate", "Select int / float / plain rows to duplicate.")
            return
        added = []
        for n, i in enumerate(sel):
            src = self.e_entries[i]
            copy = make_entry(unique_name(self.e_entries, src["name"] + "_copy"), src["kind"], fmt_value(src))
            at = i + 1 + n
            self.e_entries.insert(at, copy)
            added.append(at)
        self._changed(select=added)

    def edit_delete(self):
        if not self._need_file():
            return
        sel = self._selected_idx()
        if not sel:
            messagebox.showinfo("Delete", "Select one or more rows first.")
            return
        names = ", ".join(self.shown(self.e_entries[i], i) for i in sel[:5]) + (" …" if len(sel) > 5 else "")
        if not messagebox.askyesno("Delete rows", f"Delete {len(sel)} row(s)?\n{names}\n\n"
                                                  "(The .bak file still has the original file.)"):
            return
        for i in reversed(sel):
            del self.e_entries[i]
        self._changed()

    def edit_revert(self):
        sel = self._selected_idx()
        if not sel:
            messagebox.showinfo("Revert", "Select one or more rows first.")
            return
        drop = set()
        for i in sel:
            e = self.e_entries[i]
            o = e.get("orig")
            if o is None: 
                drop.add(i)
                continue
            e["kind"], e["value"], e["name"] = o["kind"], o["value"], o["name"]
            if e.get("ok") is not None:
                e["ok"] = True
        self.e_entries = [e for i, e in enumerate(self.e_entries) if i not in drop]
        self._changed()

    def edit_swap(self):
        sel = [(i, self.e_entries[i]) for i in self._selected_idx() if self.e_entries[i]["kind"] in ("int", "float")]
        if not sel:
            messagebox.showinfo("Swap type", "Select int or float rows first.")
            return
        if not messagebox.askyesno("Swap type", "The game reads each entry with one specific type. Only swap if an "
                                                "entry has the wrong type (int/float mix-up).\n\nSwap the selected rows?"):
            return
        for i, e in sel:
            try:
                if e["kind"] == "int":
                    e["kind"], e["value"] = "float", float(e["value"])
                else:
                    v = int(round(e["value"]))
                    if not -2**31 <= v < 2**31:
                        raise ValueError(f"{fmt_value(e)} does not fit into an int.")
                    e["kind"], e["value"] = "int", v
            except (ValueError, OverflowError) as ex:
                messagebox.showerror("Swap type", f"{self.shown(e, i)}: {ex}")
        self._changed()

    def edit_save(self):
        if not self.e_path or self.e_use_key is None:
            return
        try:
            backup_once(self.e_path) 
            text = build_xml(self.e_entries, self.e_use_key)
            with open(self.e_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            write_json(unlocked_path(self.e_path), self.e_entries)
        except Exception as ex:
            messagebox.showerror("Save", str(ex))
            return
        self.edit_status(f"Saved {os.path.relpath(self.e_path, APP_DIR)} + "
                         f"{os.path.basename(unlocked_path(self.e_path))} (backup: .bak)")
        self.viewer_follow()

    def _build_view(self):
        f = self.tab_view
        top = ttk.Frame(f)
        top.pack(fill="x", padx=8, pady=8)
        ttk.Button(top, text="Open…", command=self.viewer_open).pack(side="left")
        ttk.Button(top, text="Reload", command=lambda: self.viewer_load(self.v_path)).pack(side="left", padx=4)
        ttk.Button(top, text="Copy all", command=self.viewer_copy_all).pack(side="left")
        ttk.Button(top, text="Copy selection", command=self.viewer_copy_sel).pack(side="left", padx=4)
        ttk.Button(top, text="Export copy…", command=self.viewer_export).pack(side="left")
        ttk.Button(top, text="Open folder", command=lambda: self.v_path and open_folder(
            os.path.dirname(self.v_path))).pack(side="left", padx=4)
        self.v_follow = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Follow editor (reload after each save)", variable=self.v_follow
                        ).pack(side="left", padx=12)
        self.v_label = ttk.Label(f, text="No file loaded.")
        self.v_label.pack(fill="x", padx=8)
        wrap = ttk.Frame(f)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)
        self.v_text = tk.Text(wrap, wrap="none", font=("Courier", 10), state="disabled")
        ys = ttk.Scrollbar(wrap, command=self.v_text.yview)
        xs = ttk.Scrollbar(wrap, orient="horizontal", command=self.v_text.xview)
        self.v_text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        xs.pack(side="bottom", fill="x")
        ys.pack(side="right", fill="y")
        self.v_text.pack(side="left", fill="both", expand=True)
        self.v_path = None

    def viewer_open(self):
        p = filedialog.askopenfilename(initialdir=APP_DIR, filetypes=[("XML", "*.xml"), ("All", "*.*")])
        if p:
            self.viewer_load(p)

    def viewer_load(self, path):
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except Exception as ex:
            messagebox.showerror("Open", str(ex))
            return
        self.v_path = path
        self.v_text.config(state="normal")
        self.v_text.delete("1.0", "end")
        self.v_text.insert("1.0", text)
        self.v_text.config(state="disabled")
        self.v_label.config(text=f"{os.path.relpath(path, APP_DIR) if path.startswith(APP_DIR) else path}"
                                 f"   ({len(text)} chars, {text.count(chr(10))} lines)")

    def viewer_follow(self):
        if self.v_follow.get() and self.e_path:
            self.viewer_load(self.e_path)

    def _clip(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()

    def viewer_copy_all(self):
        self._clip(self.v_text.get("1.0", "end-1c"))
        self.v_label.config(text=self.v_label.cget("text").split("   copied")[0] + "   copied to clipboard")

    def viewer_copy_sel(self):
        try:
            self._clip(self.v_text.get("sel.first", "sel.last"))
        except tk.TclError:
            messagebox.showinfo("Copy", "Select some text first.")

    def viewer_export(self):
        if not self.v_path:
            return
        dst = filedialog.asksaveasfilename(initialfile=os.path.basename(self.v_path), defaultextension=".xml")
        if dst:
            shutil.copy2(self.v_path, dst)

    def _build_settings(self):
        f, cfg = self.tab_set, self.settings
        look = ttk.LabelFrame(f, text="Appearance", padding=10)
        look.pack(fill="x", padx=8, pady=(8, 4))
        self.s_theme = tk.StringVar(value=cfg["theme"])
        for label, val in (("Dark", "dark"), ("Light", "light"), ("Custom", "custom")):
            ttk.Radiobutton(look, text=label, value=val, variable=self.s_theme,
                            command=self.on_settings).pack(side="left", padx=8)

        custom = ttk.LabelFrame(f, text="Custom colors (click to pick, selects the Custom theme)", padding=10)
        custom.pack(fill="x", padx=8, pady=4)
        self.s_swatch = {}
        for col, (key, label) in enumerate(COLOR_LABELS):
            ttk.Button(custom, text=label, command=lambda k=key: self.pick_color(k)).grid(row=0, column=col * 2, padx=(8, 2))
            self.s_swatch[key] = tk.Label(custom, width=4, relief="solid", bd=1)
            self.s_swatch[key].grid(row=0, column=col * 2 + 1, padx=(0, 12))

        stream = ttk.LabelFrame(f, text="Streamer mode", padding=10)
        stream.pack(fill="x", padx=8, pady=4)
        self.s_stream = tk.BooleanVar(value=cfg["streamer"])
        self.s_all = tk.BooleanVar(value=cfg["mask_all"])
        ttk.Checkbutton(stream, text="Hide sensitive names in the editor", variable=self.s_stream,
                        command=self.on_settings).pack(anchor="w")
        ttk.Checkbutton(stream, text="Hide ALL names", variable=self.s_all,
                        command=self.on_settings).pack(anchor="w")
        ttk.Label(stream, text="Sensitive keywords (comma separated, matched anywhere in a name, "
                               "case-insensitive):").pack(anchor="w", pady=(8, 2))
        self.s_kw = tk.StringVar(value=", ".join(cfg["keywords"]))
        kw = ttk.Entry(stream, textvariable=self.s_kw)
        kw.pack(fill="x")
        kw.bind("<Return>", lambda _: self.on_settings())
        kw.bind("<FocusOut>", lambda _: self.on_settings())
        ttk.Label(stream, wraplength=900, justify="left",
                  text="Names are only masked on screen: editing, saving and the filter still use the real "
                       "names. To rename a hidden row, double-click it and type the new name (the box starts "
                       "empty; leave it empty to keep the name). The _unlocked.json and the key hex in tab 1 "
                       "are not masked.").pack(anchor="w", pady=(8, 0))

    def pick_color(self, key):
        color = colorchooser.askcolor(color=self.settings["custom"][key], title="Pick a color")[1]
        if color:
            self.settings["custom"][key] = color
            self.s_theme.set("custom")
            self.on_settings()

    def on_settings(self):
        cfg = self.settings
        cfg["theme"], cfg["streamer"], cfg["mask_all"] = self.s_theme.get(), self.s_stream.get(), self.s_all.get()
        cfg["keywords"] = [k.strip().lower() for k in self.s_kw.get().split(",") if k.strip()]
        save_settings(cfg)
        self.apply_theme()
        self.edit_fill(select=self._selected_idx())
        self.edit_status()
        if self.f_texts and self.f_hex.get().strip():
            self._find_preview()

if __name__ == "__main__":
    if tk is None:
        raise SystemExit("tkinter is not installed (on Linux: sudo apt install python3-tk).")
    App().mainloop()