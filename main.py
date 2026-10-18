"""SafeLink API: ბმულისა და შეტყობინების შემოწმება.

POST /api/check   {"text": "..."}  ->  {level, score, summary, reasons[], demo:false}
POST /api/report  {"text": "..."}  ->  {"ok": true}
GET  /api/health

არჩევითი გარემოს ცვლადები:
  ALLOWED_ORIGINS  მძიმით გამოყოფილი სია, მაგ. "https://safelink.pages.dev" (ნაგულისხმევი: *)
  GSB_API_KEY      Google Safe Browsing გასაღები (უფასოა), თუ გინდა საფრთხეების ბაზაში შემოწმება
  DB_PATH          მონიშვნების SQLite ფაილი (ნაგულისხმევი: reports.db)
  RATE_LIMIT       მოთხოვნა წუთში ერთ IP-ზე (ნაგულისხმევი: 30)
"""
import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx
import threats
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- config
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
DB_PATH = os.getenv("DB_PATH", "reports.db")
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))

BRANDS = ["bog.ge", "tbcbank.ge", "tbc.ge", "libertybank.ge", "post.ge", "wolt.com", "glovoapp.com",
          "extra.ge", "zoommer.ge", "ee.ge", "rs.ge", "magticom.ge", "silknet.com"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "goo.gl", "ow.ly"]
BAD_TLDS = ["xyz", "top", "icu", "click", "link", "tk", "ml", "ga", "cf", "cc", "live", "shop", "online", "site"]
URGENCY = ["დღესვე", "დაიბლოკ", "გაიყინ", "24 საათ", "ბოლო გაფრთხილ", "დაუყოვნებ", "სასწრაფო", "შეწყდება"]
SENSITIVE = ["ბარათ", "cvv", "პაროლ", "კოდი", "კოდს", "დაადასტურ", "პინ", "pin"]
PRIZE = ["მოგებ", "ჯილდ", "საჩუქა", "თანხა დაგიბრუნდ", "კომპენსაც"]

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:ge|com|net|org|info|xyz|top|icu|click|link|online|site|shop|live|cc|ru|tk|ml|ga|cf)\b(?:/[^\s]*)?",
    re.I,
)
TWO_PART = {"com.ge", "org.ge", "net.ge"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})
SOURCE_NAMES = {"openphish": "OpenPhish", "phishing.database": "Phishing.Database", "urlhaus": "URLhaus"}
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------- app
@asynccontextmanager
async def lifespan(_app: FastAPI):
    await threats.start()
    try:
        yield
    finally:
        await threats.stop()


app = FastAPI(title="SafeLink API", docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

_hits: dict[str, deque] = defaultdict(deque)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method == "POST":
        ip, now = client_ip(request), time.time()
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return JSONResponse({"detail": "too many requests"}, status_code=429)
        q.append(now)
        if len(_hits) > 5000:  # მეხსიერების დაცვა
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                _hits.pop(k, None)
    return await call_next(request)


class In(BaseModel):
    text: str = Field(min_length=1, max_length=1500)


# ---------------------------------------------------------------- helpers
def lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable(host: str) -> str:
    p = host.split(".")
    if len(p) > 2 and ".".join(p[-2:]) in TWO_PART:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def parse_host(raw: str) -> tuple[str | None, bool]:
    is_http = raw.lower().startswith("http://")
    try:
        u = urlparse(raw if re.match(r"https?://", raw, re.I) else "https://" + raw)
        host = (u.hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        return (host or None), is_http
    except ValueError:
        return None, is_http


def r(tone: str, title: str, detail: str = "") -> dict:
    d = {"tone": tone, "title": title}
    if detail:
        d["detail"] = detail
    return d


async def is_public_host(host: str) -> bool:
    """SSRF დაცვა: მხოლოდ საჯარო IP-ებზე ვუშვებთ მოთხოვნას."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return False
    try:
        return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)
    except ValueError:
        return False


async def expand(url: str) -> str | None:
    """შემოკლებული ბმულის რეალური მისამართი (მაქს. 5 გადამისამართება)."""
    if not re.match(r"https?://", url, re.I):
        url = "https://" + url
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=3.5,
                                     headers={"User-Agent": "SafeLinkBot/1.0"}) as c:
            cur = url
            for _ in range(5):
                host = urlparse(cur).hostname
                if urlparse(cur).scheme not in ("http", "https") or not host or not await is_public_host(host):
                    return None
                resp = await c.get(cur)
                loc = resp.headers.get("location")
                if resp.status_code in (301, 302, 303, 307, 308) and loc:
                    cur = urljoin(cur, loc)
                    continue
                return cur
            return cur
    except Exception:
        return None


async def domain_age_days(reg: str) -> int | None:
    try:
        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True) as c:
            resp = await c.get(f"https://rdap.org/domain/{reg}")
        if resp.status_code != 200:
            return None
        for ev in resp.json().get("events", []):
            if ev.get("eventAction") == "registration":
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None
    return None


async def safe_browsing_hit(url: str) -> bool | None:
    if not GSB_API_KEY:
        return None
    body = {
        "client": {"clientId": "safelink", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=3.5) as c:
            resp = await c.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                                params={"key": GSB_API_KEY}, json=body)
        if resp.status_code != 200:
            return None
        return bool(resp.json().get("matches"))
    except Exception:
        return None


# ---------------------------------------------------------------- analysis
def host_rules(host: str, is_http: bool) -> tuple[int, list[dict], bool]:
    """აბრუნებს (ქულა, მიზეზები, ოფიციალურია_თუ_არა)."""
    score, out = 0, []
    reg = registrable(host)
    label, tld = reg.split(".")[0], reg.split(".")[-1]

    if reg in BRANDS:
        return 0, [r("good", "ოფიციალური მისამართია", f"{reg} ცნობილი სერვისის ნამდვილი დომენია.")], True

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 40
        out.append(r("bad", "მისამართი ციფრებისგან შედგება", "ნამდვილი სერვისები ასე იშვიათად მუშაობენ."))
    if "xn--" in host:
        score += 35
        out.append(r("bad", "მისამართში დამალული სიმბოლოებია", "ასე ხშირად ბაძავენ ცნობილ საიტებს."))
    if reg in SHORTENERS:
        score += 25
        out.append(r("warn", "შემოკლებული ბმულია", "რეალური მისამართი დაფარულია, სანამ არ გახსნი."))
    if tld in BAD_TLDS:
        score += 20
        out.append(r("warn", f"უჩვეულო დაბოლოება .{tld}", "თაღლითები ხშირად იაფ დაბოლოებებს იყენებენ."))
    if is_http:
        score += 15
        out.append(r("warn", "კავშირი დაცული არ არის", "მისამართი http-ით იწყება, https-ის გარეშე."))

    hit = None
    flat = label.replace("-", "")
    norm = flat.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    for b in BRANDS:
        bl = b.split(".")[0]
        if (len(bl) >= 4 and 0 < lev(flat, bl) <= 2) or (len(bl) >= 3 and norm != flat and norm == bl):
            hit = b
            break
        if len(bl) >= 3 and bl in host:
            hit = b
            break
    if hit and reg not in SHORTENERS:
        score += 55
        out.append(r("bad", f"ჰგავს {hit}-ს, მაგრამ ის არ არის", f"ოფიციალური მისამართია {hit}, ეს კი {reg}."))

    if host.count("-") >= 2:
        score += 10
        out.append(r("warn", "მისამართში ბევრი ტირეა"))
    if len(host.split(".")) >= 5:
        score += 10
        out.append(r("warn", "მისამართი უჩვეულოდ გრძელია"))
    return score, out, False


async def analyze(text: str) -> dict:
    reasons: list[dict] = []
    score = 0
    low = text.lower()
    raw_urls = [m.group(0).rstrip(".,;:!?)»”") for m in URL_RE.finditer(text)][:3]

    for raw in raw_urls:
        host, is_http = parse_host(raw)
        if not host:
            continue
        s, rs, official = host_rules(host, is_http)
        score += s
        reasons += rs
        if official:
            continue

        reg = registrable(host)
        final_url = raw
        # შემოკლებული ბმულის გახსნა და საბოლოო მისამართის შემოწმება
        if reg in SHORTENERS:
            dest = await expand(raw)
            if dest:
                dhost, dhttp = parse_host(dest)
                if dhost and registrable(dhost) != reg:
                    final_url = dest
                    ds, drs, dofficial = host_rules(dhost, dhttp)
                    if not dofficial:
                        score += ds
                        reasons += drs
                    reasons.append(r("warn" if not dofficial else "good", "გადამისამართდება: " + dhost,
                                     "ეს არის ბმულის რეალური დანიშნულება."))
                    reg = registrable(dhost)
                    if dofficial:
                        continue
            else:
                score += 10
                reasons.append(r("warn", "რეალური მისამართი ვერ დავადგინეთ", "ბმული არ იხსნება ან დაცულია."))

        # გარე შემოწმებები (პარალელურად)
        age, gsb, th1, th2 = await asyncio.gather(
            domain_age_days(reg), safe_browsing_hit(final_url),
            threats.lookup(raw), threats.lookup(final_url) if final_url != raw else asyncio.sleep(0))
        th = th1 or th2
        if th:
            names = ", ".join(SOURCE_NAMES.get(s, s) for s in th["sources"])
            if th["match"] == "url":
                score += 80
                reasons.append(r("bad", "ცნობილი თაღლითური ბმულია", f"ზუსტად ეს ბმული ფიშინგის ბაზაშია ({names})."))
            else:
                score += 60
                reasons.append(r("bad", "მისამართი ფიშინგის ბაზაშია", f"ამ მისამართზე თაღლითური გვერდი ფიქსირდება ({names})."))
        if age is not None:
            if age < 30:
                score += 30
                reasons.append(r("bad", "დომენი ძალიან ახალია", f"რეგისტრირებულია {age} დღის წინ."))
            elif age < 180:
                score += 10
                reasons.append(r("warn", "დომენი შედარებით ახალია", f"რეგისტრირებულია {age} დღის წინ."))
        if gsb:
            score += 70
            reasons.append(r("bad", "საფრთხეების ბაზაში ფიქსირდება", "Google Safe Browsing ამ მისამართს საშიშად მიიჩნევს."))

    def has(words): return any(w in low for w in words)

    if has(URGENCY):
        score += 15
        reasons.append(r("warn", "გაჩქარებას გიწევს", "სასწრაფოობა თაღლითობის ყველაზე გავრცელებული ხერხია."))
    if has(SENSITIVE):
        score += 30
        reasons.append(r("bad", "მგრძნობიარე მონაცემებს ითხოვს",
                         "ბარათი, კოდი ან პაროლი. ნამდვილი ბანკი ამას შეტყობინებით არ გთხოვს."))
    if has(PRIZE):
        score += 25
        reasons.append(r("bad", "ჯილდოს ან თანხის დაპირება", "მოულოდნელი მოგება თითქმის ყოველთვის მახეა."))

    level = "bad" if score >= 55 else "warn" if score >= 25 else "safe"
    if not reasons:
        reasons.append(r("good", "საეჭვო ნიშნები ვერ ვიპოვეთ"))
    summary = {"safe": "ვერაფერი საეჭვო ვიპოვეთ.",
               "warn": "რამდენიმე ნიშანი გვაფრთხილებს.",
               "bad": "ბევრი ნიშანი თაღლითობაზე მიუთითებს."}[level]
    order = {"bad": 0, "warn": 1, "good": 2}
    reasons.sort(key=lambda x: order[x["tone"]])
    return {"level": level, "score": min(score, 100), "summary": summary, "reasons": reasons[:8], "demo": False}


# ---------------------------------------------------------------- routes
@app.get("/api/health")
async def health():
    return {"ok": True, "safe_browsing": bool(GSB_API_KEY), "threat_db": threats.total() > 0, "threats": threats.total()}


def _admin_ok(request: Request) -> bool:
    tok = request.headers.get("x-admin-token", "")
    return bool(threats.ADMIN_TOKEN) and hmac.compare_digest(tok, threats.ADMIN_TOKEN)


@app.get("/api/admin/status")
async def admin_status(request: Request):
    if not _admin_ok(request):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return {"feeds": threats.status(), "reports_db": threats.reports_enabled()}


@app.post("/api/admin/refresh")
async def admin_refresh(request: Request):
    if not _admin_ok(request):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    threats.trigger_refresh()
    return {"started": True}


@app.post("/api/check")
async def check(body: In):
    try:
        return await asyncio.wait_for(analyze(body.text.strip()), timeout=10)
    except asyncio.TimeoutError:
        return JSONResponse({"detail": "timeout"}, status_code=504)


def _save_report(domains: str, digest: str) -> None:
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, ts TEXT, domains TEXT, hash TEXT)")
        con.execute("INSERT INTO reports(ts, domains, hash) VALUES(?,?,?)",
                    (datetime.now(timezone.utc).isoformat(timespec="seconds"), domains, digest))
        con.commit()
    finally:
        con.close()


@app.post("/api/report")
async def report(body: In):
    # კონფიდენციალობა: სრულ ტექსტს არ ვინახავთ, მხოლოდ დომენებს და ჰეშს
    hosts = {registrable(h) for h, _ in (parse_host(m.group(0)) for m in URL_RE.finditer(body.text)) if h}
    digest = hashlib.sha256(body.text.strip().lower().encode()).hexdigest()[:16]
    if threats.reports_enabled():
        await threats.save_report(sorted(hosts), digest)
        return {"ok": True}
    try:
        await asyncio.to_thread(_save_report, ",".join(sorted(hosts))[:300], digest)
    except Exception:
        pass
    return {"ok": True}


# ფრონტის მომსახურება: static/index.html ან პირდაპირ index.html (მხოლოდ ეს ერთი ფაილი)
if os.path.isdir("static"):
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
elif os.path.isfile("index.html"):
    @app.get("/")
    async def index():
        return FileResponse("index.html")

