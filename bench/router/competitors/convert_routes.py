"""Turns API descriptions into colibri route tables: "METHOD /path" lines, {x} as :x.
convert.py <apis dir> <out dir>. Prints what each table needed changed."""
import json, re, sys, pathlib

METHODS = ["get", "put", "post", "delete", "patch", "head", "options"]
PCHAR = re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@]*$")

def from_openapi(path):
    spec = json.loads(pathlib.Path(path).read_text())
    for route, ops in spec["paths"].items():
        for method in METHODS:
            if method in ops:
                yield method.upper(), route

def from_go(path, var):
    text = pathlib.Path(path).read_text()
    body = text[text.index(var):]
    body = body[: body.index("\n}\n")]
    for line in body.splitlines():
        if line.strip().startswith("//"): continue
        m = re.search(r'\{"([A-Z]+)",\s*"([^"]+)"\}', line)
        if m: yield m.group(1), m.group(2)

def convert(routes):
    """Returns (lines, notes). Keeps colibri's rules: whole-segment parameters, one parameter
    name at each trie node, pchar literals."""
    notes = {"mixed_segment": 0, "duplicate": 0, "not_pchar": 0, "trailing_slash": 0}
    seen, lines = set(), []
    for method, route in routes:
        # A path that holds a query, such as OpenAI's "?beta=true" variants, is no route.
        if "?" in route:
            notes["query"] = notes.get("query", 0) + 1; continue
        route = re.sub(r"\{([^}/]+)\}", r":\1", route)
        if route == "/":
            line = f"{method} /"
            if line not in seen: seen.add(line); lines.append(line)
            continue
        if route != "/" and route.endswith("/"):
            notes["trailing_slash"] += 1; continue
        segments = route.split("/")[1:]
        out, prefix, ok, used = [], (), True, set()
        for seg in segments:
            if seg.startswith(":"):
                name = re.sub(r"[^A-Za-z0-9_]", "_", seg[1:])
                if ":" in seg[1:] or not name:
                    ok = False; notes["mixed_segment"] += 1; break
                # Decision 129: each route keeps its own names. A name a pattern repeats, such as
                # Stripe's {id} twice, takes a suffix there (parameter_repeated).
                held = name
                while held in used:
                    held = held + "_2"; notes["repeated"] = notes.get("repeated", 0) + 1
                used.add(held)
                out.append(":" + held); prefix += (":",)
            else:
                if ":" in seg or "{" in seg:
                    ok = False; notes["mixed_segment"] += 1; break
                if not PCHAR.match(seg) or seg == "":
                    ok = False; notes["not_pchar"] += 1; break
                out.append(seg); prefix += (seg,)
        if not ok: continue
        line = f"{method} /" + "/".join(out)
        if line in seen:
            notes["duplicate"] += 1; continue
        seen.add(line); lines.append(line)
    return lines, notes

apis, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
tables = {
    "stripe": from_openapi(apis / "stripe/spec3.json"),
    "kubernetes": from_openapi(apis / "kubernetes/swagger.json"),
    "openai": from_openapi(apis / "openai/openapi.json"),
    "parse": from_go(apis / "gohttp/parse_test.go", "parseAPI = []route{"),
    "gplus": from_go(apis / "gohttp/gplus_test.go", "gplusAPI = []route{"),
    "static": from_go(apis / "gohttp/static_test.go", "staticRoutes = []route{"),
}
for name, routes in tables.items():
    routes = list(routes)
    lines, notes = convert(routes)
    (out / f"{name}_routes.txt").write_text("\n".join(lines) + "\n")
    depth = max(l.count("/") for l in lines)
    params = sum(l.count(":") for l in lines)
    print(f"{name:11} described={len(routes):5} kept={len(lines):5} depth={depth:2} params={params:5} {notes}")
