import os
import re
import stat

TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


class SafeUnixSocketDirectory:
    """Hardened websockify token plugin restricting lookups to 32-hex sockets inside source.

    Upstream websockify's UnixDomainSocketDirectory uses Path.absolute() / os.path.abspath()
    with string prefix matching, which can be bypassed on versions that do not resolve '..'
    or symlinks. This plugin enforces:
      1. Exact 32-character lowercase hex token (no '/', '..', '%', or NUL)
      2. Realpath containment inside realpath(source) with no symlink traversal
      3. Target is an AF_UNIX socket owned by the current UID
    """

    def __init__(self, src):
        self.source = src

    def lookup(self, token):
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            return None
        try:
            real_base = os.path.realpath(self.source)
            if not os.path.isdir(real_base):
                return None
            candidate = os.path.join(real_base, token)
            if os.path.islink(candidate):
                return None
            real_candidate = os.path.realpath(candidate)
            if os.path.dirname(real_candidate) != real_base:
                return None
            st = os.lstat(real_candidate)
            if not stat.S_ISSOCK(st.st_mode):
                return None
            if hasattr(os, "getuid") and st.st_uid != os.getuid():
                return None
        except OSError:
            return None
        return ["unix_socket", real_candidate]
