"""საფრთხეების ბაზა: საჯარო ფიშინგ-ფიდები, მეხსიერებაში.
 
ფიდებს (OpenPhish, Phishing.Database, არჩევითად URLhaus) GitHub-იდან/წყაროდან ვტვირთავთ
აპის გაშვებისას და მერე ყოველ რამდენიმე საათში. ბმულებს ჰეშებად ვინახავთ RAM-ში
(100 000 ბმული დაახლოებით 10 MB-ია), ამიტომ ბაზა ან გარე სერვისი არ გვჭირდება.
/api/check-ში ბმულს ამ სიებს ვადარებთ.
 
გარემოს ცვლადები (ყველა არჩევითია):
  ADMIN_TOKEN         /api/admin/* ბილიკებისთვის
  URLHAUS_AUTH_KEY    abuse.ch-ის უფასო გასაღები, URLhaus-ის ჩასართავად
  FEED_REFRESH_HOURS  განახლების პერიოდი საათებში (ნაგულისხმევი 6)
  MAX_PER_FEED        ერთი ფიდიდან მაქსიმუმ რამდენი ბმული (ნაგულისხმევი 100000)
  SUPABASE_URL, SUPABASE_KEY   მხოლოდ მომხმარებლების მონიშვნების მუდმივად შესანახად
"""
import asyncio
import csv
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
 
import httpx
 
log = logging.getLogger("safelink.threats")
 
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
URLHAUS_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
REFRESH_HOURS = float(os.getenv("FEED_REFRESH_HOURS", "6"))
MAX_PER_FEED = int(os.getenv("MAX_PER_FEED", "300000"))
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()
 
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
# ACTIVE-NOW ფაილი ხშირად ცარიელია, ამიტომ სრულ სიას ვიყენებთ; თუ ვერ ჩამოვიდა, დომენების სიას
PHISHDB_URLS = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
]
 
# საერთო პლატფორმები: მათზე მხოლოდ ზუსტი ბმულის დამთხვევა ითვლება, მისამართისა არა,
# თორემ ერთი ცუდი გვერდი მთელ docs.google.com-ს "გააფუჭებდა".
SHARED_HOSTS = {
    "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "forms.google.com",
    "storage.googleapis.com", "github.com", "raw.githubusercontent.com", "bit.ly", "t.co",
    "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "goo.gl", "ow.ly", "facebook.com", "m.facebook.com",
    "t.me", "wa.me", "youtube.com", "youtu.be", "linkedin.com", "dropbox.com", "onedrive.live.com",
    "1drv.ms", "canva.com", "notion.so", "medium.com", "blogspot.com", "wordpress.com", "weebly.com",
    "wixsite.com", "web.app", "firebaseapp.com", "pages.dev", "netlify.app", "vercel.app",
    "github.io", "herokuapp.com", "ipfs.io", "sharepoint.com", "typeform.com", "airtable.com",
    "jotform.com", "linktr.ee", "instagram.com", "x.com", "twitter.com",
}
 
# სახელი -> {"urls": set[int], "hosts": set[str], "count": int, "updated": datetime}
_state: dict[str, dict] = {}
_feed: httpx.AsyncClient | None = None
_db: httpx.AsyncClient | None = None      # Supabase, მხოლოდ მონიშვნებისთვის
_task: asyncio.Task | None = None
_manual: asyncio.Task | None = None
_lock = asyncio.Lock()
 
_HOST_OK = re.compile(r"^[a-z0-9.-]{1,253}$")
 
 
def _err(e: Exception) -> str:
    """ლოგში URL არ გავიტანოთ (URLhaus-ის გასაღები URL-შია)."""
    if isinstance(e, httpx.HTTPStatusError):
        return f"HTTP {e.response.status_code}"
    return type(e).__name__
 
 
# ---------------------------------------------------------------- ნორმალიზაცია
def key_of(raw: str) -> tuple[str, int] | None:
    """ბმულიდან (host, ჰეში). სქემა, www, #ფრაგმენტი და ბოლო / არ ითვლება."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 2000:
        return None
    if not re.match(r"[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if host and not host.isascii():
        try:
            host = host.encode("idna").decode()
        except UnicodeError:
            return None
    if host.startswith("www."):
        host = host[4:]
    if "." not in host or not _HOST_OK.match(host):
        return None
    k = host + p.path.rstrip("/") + ("?" + p.query if p.query else "")
    return host, int.from_bytes(hashlib.sha1(k.encode()).digest()[:8], "big")
 
 
# ---------------------------------------------------------------- ფიდების პარსერები
async def _plain(lines):
    async for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            yield line
 
 
async def _urlhaus(lines):
    cols = None
    async for line in lines:
        if not line.strip():
            continue
        if line.startswith("#"):
            head = line.lstrip("# ").strip()
            if head.startswith("id,") and "url" in head:
                cols = next(csv.reader([head]))
            continue
        row = next(csv.reader([line]))
        if cols and "url" in cols:
            d = dict(zip(cols, row))
            if d.get("url_status", "online") == "online":
                yield d["url"]
        elif len(row) > 2:
            yield row[2]
 
 
def _feeds() -> list[tuple[str, list[str], object]]:
    """(სახელი, [მისამართები რიგით: პირველი რომელიც იმუშავებს], პარსერი)"""
    feeds = [("openphish", [OPENPHISH_URL], _plain), ("phishing.database", PHISHDB_URLS, _plain)]
    if URLHAUS_KEY:
        feeds.append(("urlhaus", [f"https://urlhaus-api.abuse.ch/v2/files/exports/{URLHAUS_KEY}/recent.csv"], _urlhaus))
    return feeds
 
 
# ---------------------------------------------------------------- ჩატვირთვა
async def _ingest(name: str, url: str, parser) -> int:
    urls: set[int] = set()
    hosts: set[str] = set()
    seen = 0
    async with _feed.stream("GET", url) as resp:
        resp.raise_for_status()
        async for raw in parser(resp.aiter_lines()):
            k = key_of(raw)
            if not k:
                continue
            hosts.add(k[0])
            urls.add(k[1])
            seen += 1
            if seen % 5000 == 0:
                await asyncio.sleep(0)  # სხვა მოთხოვნებსაც მივცეთ დრო
            if len(urls) >= MAX_PER_FEED:
                break
    if not urls:
        raise RuntimeError("ფიდი ცარიელია")  # ძველ მონაცემებს არ ვკარგავთ
    _state[name] = {"urls": urls, "hosts": hosts, "count": len(urls), "updated": datetime.now(timezone.utc)}
    return len(urls)
 
 
async def refresh(force: bool = False) -> None:
    if _feed is None:
        return
    async with _lock:
        now = datetime.now(timezone.utc)
        for name, urls, parser in _feeds():
            s = _state.get(name)
            if not force and s and now - s["updated"] < timedelta(hours=REFRESH_HOURS):
                continue
            for i, url in enumerate(urls, 1):
                try:
                    n = await _ingest(name, url, parser)
                    log.info("ფიდი %s განახლდა: %d ბმული (წყარო %d/%d)", name, n, i, len(urls))
                    break
                except Exception as e:
                    reason = "ცარიელია" if isinstance(e, RuntimeError) else _err(e)
                    log.warning("ფიდი %s, წყარო %d/%d ვერ განახლდა: %s", name, i, len(urls), reason)
 
 
async def _loop() -> None:
    await asyncio.sleep(3)
    while True:
        try:
            await refresh()
        except Exception as e:  # ციკლი არ უნდა გაჩერდეს
            log.warning("განახლების ციკლი: %s", _err(e))
        await asyncio.sleep(3600)
 
 
def trigger_refresh() -> None:
    global _manual
    _manual = asyncio.create_task(refresh(force=True))
 
 
def status() -> dict:
    return {n: {"count": s["count"], "updated_at": s["updated"].isoformat(timespec="seconds")}
            for n, s in _state.items()}
 
 
def total() -> int:
    return sum(s["count"] for s in _state.values())
 
 
async def start() -> None:
    global _feed, _db, _task
    _feed = httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": "SafeLink/1.0"},
                              timeout=httpx.Timeout(60, connect=10))
    if reports_enabled():
        _db = httpx.AsyncClient(base_url=SUPABASE_URL + "/rest/v1", timeout=10)
    _task = asyncio.create_task(_loop())
 
 
async def stop() -> None:
    for t in (_task, _manual):
        if t:
            t.cancel()
    for c in (_feed, _db):
        if c:
            await c.aclose()
 
 
# ---------------------------------------------------------------- ძებნა
async def lookup(raw: str) -> dict | None:
    """აბრუნებს {"match": "url"|"host", "sources": [...]} ან None."""
    k = key_of(raw)
    if not k or not _state:
        return None
    host, h = k
    exact = sorted(n for n, s in _state.items() if h in s["urls"])
    if exact:
        return {"match": "url", "sources": exact}
    if host not in SHARED_HOSTS:
        by_host = sorted(n for n, s in _state.items() if host in s["hosts"])
        if by_host:
            return {"match": "host", "sources": by_host}
    return None
 
 
# ---------------------------------------------------------------- მონიშვნები (არჩევითი Supabase)
def reports_enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_KEY)
 
 
async def save_report(hosts: list[str], text_hash: str) -> bool:
    if _db is None or not hosts:
        return False
    headers = {"apikey": SUPABASE_KEY, "Content-Type": "application/json", "Prefer": "return=minimal"}
    if SUPABASE_KEY.startswith("eyJ"):  # ძველი JWT გასაღები; ახალი sb_secret_ მხოლოდ apikey-ს უნდა
        headers["Authorization"] = f"Bearer {SUPABASE_KEY}"
    try:
        r = await _db.post("/reports", timeout=5, headers=headers,
                           json=[{"host": h[:253], "text_hash": text_hash} for h in hosts[:3]])
        return r.status_code in (200, 201, 204)
    except Exception:
        return False
 

