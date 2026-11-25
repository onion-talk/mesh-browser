import ctypes, os, sys
from PIL import Image

win = int(sys.argv[1])
x11 = ctypes.cdll.LoadLibrary("libX11.so.6")
x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
x11.XOpenDisplay.restype = ctypes.c_void_p
x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
x11.XDefaultRootWindow.restype = ctypes.c_ulong
x11.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
x11.XInternAtom.restype = ctypes.c_ulong
x11.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
x11.XSendEvent.restype = ctypes.c_int
x11.XChangeProperty.argtypes = [
    ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
    ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int
]
x11.XChangeProperty.restype = ctypes.c_int
x11.XFlush.argtypes = [ctypes.c_void_p]
x11.XCloseDisplay.argtypes = [ctypes.c_void_p]

class XClientMessageEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong),
        ("message_type", ctypes.c_ulong),
        ("format", ctypes.c_int),
        ("data", ctypes.c_long * 5),
        ("_pad", ctypes.c_long * 12),
    ]

dpy = x11.XOpenDisplay(None)
if dpy:
    # Maximize window (keeps - and x buttons)
    root = x11.XDefaultRootWindow(dpy)
    wm_state = x11.XInternAtom(dpy, b"_NET_WM_STATE", 0)
    wm_h = x11.XInternAtom(dpy, b"_NET_WM_STATE_MAXIMIZED_HORZ", 0)
    wm_v = x11.XInternAtom(dpy, b"_NET_WM_STATE_MAXIMIZED_VERT", 0)
    ev = XClientMessageEvent()
    ev.type = 33
    ev.display = dpy
    ev.window = win
    ev.message_type = wm_state
    ev.format = 32
    ev.data[0] = 1
    ev.data[1] = wm_h
    ev.data[2] = wm_v
    ev.data[3] = 2
    x11.XSendEvent(dpy, root, 0, 0x180000, ctypes.byref(ev))

    # Set live taskbar + Alt+Tab + titlebar icon (_NET_WM_ICON)
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mesh-logo-64.png")
    if os.path.exists(icon_path):
        im = Image.open(icon_path).convert("RGBA")
        iw, ih = im.size
        vals = [iw, ih] + [
            (a << 24) | (r << 16) | (g << 8) | b
            for (r, g, b, a) in im.getdata()
        ]
        arr = (ctypes.c_ulong * len(vals))(*vals)
        wm_icon = x11.XInternAtom(dpy, b"_NET_WM_ICON", 0)
        x11.XChangeProperty(dpy, win, wm_icon, 6, 32, 0, arr, len(vals))

    x11.XFlush(dpy)
    x11.XCloseDisplay(dpy)
