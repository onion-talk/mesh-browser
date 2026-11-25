import os, sys
os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "1")
os.environ.setdefault("WEBKIT_DISABLE_COMPOSITING_MODE", "1")

import gi
gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import Gtk, WebKit2, GLib, Gdk

APP_DIR = os.path.dirname(os.path.abspath(__file__))
URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/ui.html"

GLib.set_prgname("mesh-desktop")
GLib.set_application_name("Mesh Browser")

win = Gtk.Window(title="Mesh Browser")
win.set_default_size(1440, 860)

icon_path = os.path.join(APP_DIR, "mesh-logo.png")
if os.path.exists(icon_path):
    try:
        win.set_icon_from_file(icon_path)
    except Exception:
        pass

ctx = WebKit2.WebContext.get_default()
ctx.set_cache_model(WebKit2.CacheModel.DOCUMENT_VIEWER)

webview = WebKit2.WebView.new_with_context(ctx)
rgba = Gdk.RGBA()
rgba.parse("#0b0f14")
webview.set_background_color(rgba)

settings = webview.get_settings()
settings.set_enable_javascript(True)
settings.set_javascript_can_access_clipboard(False)

def on_load_failed(wv, event, uri, err):
    print(f"[mesh-app] load failed: {uri} -> {err}", flush=True)
    return False

webview.connect("load-failed", on_load_failed)
webview.load_uri(URL)
win.add(webview)
win.connect("destroy", Gtk.main_quit)
win.show_all()
win.maximize()

Gtk.main()
