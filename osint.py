import os
import re
import math
import time
import json
import socket
import random
import hashlib
import webbrowser
import html as htmllib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

VER = "4.1"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

R  = "\033[0m"
B  = "\033[1m"
C  = "\033[96m"
G  = "\033[92m"
Y  = "\033[93m"
RD = "\033[91m"
M  = "\033[95m"
D  = "\033[90m"

FINDINGS = []


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def hdr(t):
    print(f"\n{D}┌─╼╾──────────────────────────────────────────╾╼─┐{R}")
    print(f"{B}{M}│  {t}{R}")
    print(f"{D}└─╼╾──────────────────────────────────────────╾╼─┘{R}\n")


def log(msg):
    try:
        with open("osint_report.txt", "a") as f:
            f.write("[%s] %s\n" % (datetime.now().strftime("%H:%M:%S"), msg))
    except:
        pass


def add(kind, **kw):
    kw["kind"] = kind
    FINDINGS.append(kw)
    return kw


def esc(s):
    return htmllib.escape(str(s), quote=True)

def levenshtein(a, b):
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def norm_lev(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return 1.0 - levenshtein(a.lower(), b.lower()) / max(len(a), len(b))


def jaro(s1, s2):
    if s1 == s2:
        return 1.0
    l1, l2 = len(s1), len(s2)
    if not l1 or not l2:
        return 0.0
    win = max(max(l1, l2) // 2 - 1, 0)
    f1 = [False] * l1
    f2 = [False] * l2
    m = 0
    for i in range(l1):
        for j in range(max(0, i - win), min(i + win + 1, l2)):
            if f2[j] or s1[i] != s2[j]:
                continue
            f1[i] = f2[j] = True
            m += 1
            break
    if not m:
        return 0.0
    t = 0
    k = 0
    for i in range(l1):
        if not f1[i]:
            continue
        while not f2[k]:
            k += 1
        if s1[i] != s2[k]:
            t += 1
        k += 1
    t //= 2
    return (m / l1 + m / l2 + (m - t) / m) / 3.0


def jaro_winkler(s1, s2):
    s1, s2 = s1.lower(), s2.lower()
    j = jaro(s1, s2)
    p = 0
    for a, b in zip(s1[:4], s2[:4]):
        if a != b:
            break
        p += 1
    return j + p * 0.1 * (1.0 - j)


def ngrams(s, n=3):
    s = re.sub(r"\s+", "", s.lower())
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def jaccard(a, b):
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    u = len(a | b)
    return len(a & b) / u if u else 0.0


SOUNDEX_MAP = {"B": "1", "F": "1", "P": "1", "V": "1",
               "C": "2", "G": "2", "J": "2", "K": "2", "Q": "2", "S": "2", "X": "2", "Z": "2",
               "D": "3", "T": "3", "L": "4", "M": "5", "N": "5", "R": "6"}


def soundex(name):
    name = re.sub(r"[^a-zA-Z]", "", name).upper()
    if not name:
        return ""
    out = name[0]
    last = ""
    for ch in name[1:]:
        code = SOUNDEX_MAP.get(ch)
        if code:
            if code != last:
                out += code
            last = code
        else:
            last = ""
    return (out + "000")[:4]


def name_match(a, b):
    if not a or not b:
        return 0.0
    a, b = a.strip().lower(), b.strip().lower()
    if a == b:
        return 1.0
    ta = set(re.split(r"[\s._-]+", a))
    tb = set(re.split(r"[\s._-]+", b))
    lev = norm_lev(a, b)
    sd = 1.0 if (soundex(a) and soundex(a) == soundex(b)) else 0.0
    jw = jaro_winkler(a, b)
    return max(lev, jw, jaccard(ta, tb) * 0.95, sd * 0.85)


STOP = {"the", "a", "an", "and", "or", "of", "in", "on", "at", "to", "for", "is", "are", "am",
        "i", "my", "me", "we", "our", "you", "your", "it", "its", "with", "by", "from", "as",
        "that", "this", "but", "not", "so", "if", "then", "than", "be", "been", "was", "were",
        "do", "does", "did", "have", "has", "had", "will", "would", "can", "could", "just",
        "about", "into", "over", "under", "up", "down", "out", "get", "got", "no", "yes",
        "all", "any", "some", "more", "most", "very", "too", "also", "when", "who", "what",
        "im", "ive", "dont", "doesnt", "aint", "u", "ur", "lol", "via", "like", "one", "two"}


def tokenize(text):
    if not text:
        return []
    return [t for t in re.findall(r"[a-z0-9#+']+", (text or "").lower()) if t not in STOP and len(t) > 2]


def build_idf(docs):
    idf = {}
    n = max(len(docs), 1)
    for doc in docs:
        for t in set(doc):
            idf[t] = idf.get(t, 0) + 1
    return {t: math.log(n / c) + 1.0 for t, c in idf.items()}


def tfidf_vector(tokens, idf):
    if not tokens:
        return {}
    tf = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    return {t: (c / len(tokens)) * idf.get(t, 1.5) for t, c in tf.items()}


def cosine(v1, v2):
    if not v1 or not v2:
        return 0.0
    dot = sum(v1[t] * v2.get(t, 0) for t in v1)
    n1 = math.sqrt(sum(x * x for x in v1.values()))
    n2 = math.sqrt(sum(x * x for x in v2.values()))
    return dot / (n1 * n2) if n1 and n2 else 0.0


def sigmoid(x):
    if x > 30:
        return 1.0
    if x < -30:
        return 0.0
    return 1.0 / (1.0 + math.exp(-x))

EVIDENCE_WEIGHTS = {
    "handle_match": 1.30, "handle_variant": 0.55, "full_name_match": 2.10,
    "name_partial": 0.70, "gravatar_confirmed": 1.60, "bio_crosslink": 2.60,
    "location_match": 0.90, "email_on_profile": 2.20, "site_overlap": 0.35,
    "style_match": 0.45, "avatar_same_hash": 2.80, "time_correlation": 0.25,
}


def score_identity(evidence_list, prior_odds=-1.6):
    odds = prior_odds
    for kind, mult in evidence_list:
        odds += EVIDENCE_WEIGHTS.get(kind, 0.3) * mult
    return sigmoid(odds)


def conf_label(p):
    if p >= 0.85:
        return "very high", "#22c55e"
    if p >= 0.65:
        return "high", "#84cc16"
    if p >= 0.40:
        return "medium", "#eab308"
    if p >= 0.20:
        return "low", "#f97316"
    return "very low", "#ef4444"


LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def leetspeak(s):
    out = "".join(LEET.get(c, c) for c in s.lower())
    return out if out != s.lower() else None


def username_permutations(first, last=None):
    first = re.sub(r"[^a-z0-9]", "", first.lower())
    last = re.sub(r"[^a-z0-9]", "", (last or "").lower())
    cands = []
    if first and last:
        cands += [first + last, last + first, first + "_" + last, first + "." + last,
                  first + "-" + last, first[0] + last, first + last[0],
                  first + "." + last[0], first + "_" + last[0]]
    cands += [first, first + "x", first + "_", "its" + first, "im" + first,
              "real" + first, "the" + first, first + "official", "just" + first,
              "mr" + first, first + "hd", first + "yt", first + "1", first + "99"]
    cands = [c for c in cands if c and len(c) >= 3]
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    for base in out[:3]:
        l = leetspeak(base)
        if l and l not in seen:
            out.append(l)
    return out[:20]


def handle_relation(a, b):
    if not a or not b:
        return None, 0.0
    a, b = a.lower(), b.lower()
    if a == b:
        return "identical", 1.0
    la, lb = leetspeak(a), leetspeak(b)
    if (la and la == b) or (lb and lb == a):
        return "leetspeak", 0.92
    if (a in b or b in a) and abs(len(a) - len(b)) <= 4:
        return "substring", 0.80
    if a.rstrip("0123456789_") == b.rstrip("0123456789_") and a != b:
        return "numeric variant", 0.85
    best = max(jaro_winkler(a, b), jaccard(ngrams(a), ngrams(b)))
    if best > 0.88:
        return "near match", best
    return None, best


def extract_meta(body):
    # only the head matters, and capped. the old whole-page regex
    if not body:
        return "", "", ""
    head = body[:20000]
    title = desc = og = ""
    m = re.search(r"<title[^>]*>([^<]{0,200})</title>", head, re.I)
    if m:
        title = htmllib.unescape(m.group(1)).strip()
    for tag in re.findall(r"<meta[^>]+>", head, re.I):
        low = tag.lower()
        if 'og:title' in low:
            m = re.search(r'content=["\']([^"\']*)["\']', tag, re.I)
            if m:
                og = htmllib.unescape(m.group(1)).strip()[:200]
        if 'og:description' in low or 'name="description"' in low or "name='description'" in low:
            if not desc:
                m = re.search(r'content=["\']([^"\']*)["\']', tag, re.I)
                if m:
                    desc = htmllib.unescape(m.group(1)).strip()[:400]
    return title, desc, og


SITES = {
"Instagram":"https://www.instagram.com/{}/","X":"https://x.com/{}","Reddit":"https://www.reddit.com/user/{}",
"Pinterest":"https://www.pinterest.com/{}/","TikTok":"https://www.tiktok.com/@{}","Twitch":"https://www.twitch.tv/{}",
"Telegram":"https://t.me/{}","Tumblr":"https://{}.tumblr.com/","Threads":"https://www.threads.com/@{}",
"Mastodon":"https://mastodon.social/@{}","Bluesky":"https://bsky.app/profile/{}.bsky.social",
"Quora":"https://www.quora.com/profile/{}","Disqus":"https://disqus.com/by/{}","About.me":"https://about.me/{}",
"Linktree":"https://linktr.ee/{}","Gravatar":"https://gravatar.com/{}","Snapchat":"https://www.snapchat.com/add/{}",
"Vero":"https://vero.co/{}","Lemmy":"https://lemmy.world/u/{}","Kbin":"https://kbin.social/u/{}",
"GitHub":"https://github.com/{}","GitLab":"https://gitlab.com/{}","Codeberg":"https://codeberg.org/{}",
"Bitbucket":"https://bitbucket.org/{}","SourceForge":"https://sourceforge.net/u/{}/","Replit":"https://replit.com/@{}",
"CodePen":"https://codepen.io/{}","Dev.to":"https://dev.to/{}","Stack Overflow":"https://stackoverflow.com/users/{}",
"HackerRank":"https://www.hackerrank.com/profile/{}","HackerEarth":"https://www.hackerearth.com/@{}",
"Codeforces":"https://codeforces.com/profile/{}","CodeChef":"https://www.codechef.com/users/{}",
"AtCoder":"https://atcoder.jp/users/{}","LeetCode":"https://leetcode.com/u/{}/","Topcoder":"https://www.topcoder.com/members/{}",
"Exercism":"https://exercism.org/profiles/{}","WakaTime":"https://wakatime.com/@{}","Kaggle":"https://www.kaggle.com/{}",
"Hugging Face":"https://huggingface.co/{}","Docker Hub":"https://hub.docker.com/u/{}","npm":"https://www.npmjs.com/~{}",
"PyPI":"https://pypi.org/user/{}/","Stack Exchange":"https://stackexchange.com/users/{}",
"Super User":"https://superuser.com/users/{}","Server Fault":"https://serverfault.com/users/{}",
"Ask Ubuntu":"https://askubuntu.com/users/{}","Pastebin":"https://pastebin.com/u/{}",
"GitHub Gist":"https://gist.github.com/{}","CodeSandbox":"https://codesandbox.io/u/{}","Glitch":"https://glitch.com/@{}",
"Behance":"https://www.behance.net/{}","Dribbble":"https://dribbble.com/{}","ArtStation":"https://www.artstation.com/{}",
"DeviantArt":"https://www.deviantart.com/{}","Flickr":"https://www.flickr.com/people/{}","500px":"https://500px.com/p/{}",
"Unsplash":"https://unsplash.com/@{}","Sketchfab":"https://sketchfab.com/{}","VSCO":"https://vsco.co/{}/gallery",
"Pixabay":"https://pixabay.com/users/{}","EyeEm":"https://www.eyeem.com/u/{}","Ello":"https://ello.co/{}",
"Cargo":"https://{}.cargo.site/","Crevado":"https://{}.crevado.com/","YouTube":"https://www.youtube.com/@{}",
"Vimeo":"https://vimeo.com/{}","Dailymotion":"https://www.dailymotion.com/{}","Rumble":"https://rumble.com/user/{}",
"Kick":"https://kick.com/{}","Odysee":"https://odysee.com/@{}","Bitchute":"https://www.bitchute.com/channel/{}",
"DTube":"https://d.tube/c/{}","SoundCloud":"https://soundcloud.com/{}","Last.fm":"https://www.last.fm/user/{}",
"Bandcamp":"https://bandcamp.com/{}","Mixcloud":"https://www.mixcloud.com/{}/","Audiomack":"https://audiomack.com/{}",
"HearThis":"https://hearthis.at/{}/","ReverbNation":"https://www.reverbnation.com/{}",
"Discogs":"https://www.discogs.com/user/{}","Rate Your Music":"https://rateyourmusic.com/~{}",
"Steam":"https://steamcommunity.com/id/{}","Chess.com":"https://www.chess.com/member/{}",
"Lichess":"https://lichess.org/@/{}","Speedrun.com":"https://www.speedrun.com/users/{}",
"Modrinth":"https://modrinth.com/user/{}","CurseForge":"https://www.curseforge.com/members/{}",
"Itch.io":"https://{}.itch.io/","Game Jolt":"https://gamejolt.com/@{}","Osu":"https://osu.ppy.sh/users/{}",
"Newgrounds":"https://{}.newgrounds.com/","Scratch":"https://scratch.mit.edu/users/{}/",
"Medium":"https://medium.com/@{}","Wattpad":"https://www.wattpad.com/user/{}","Substack":"https://{}.substack.com/",
"Write.as":"https://write.as/{}","Telegra.ph":"https://telegra.ph/{}","Vocal":"https://vocal.media/authors/{}",
"Scribd":"https://www.scribd.com/{}","Goodreads":"https://www.goodreads.com/{}","Letterboxd":"https://letterboxd.com/{}/",
"MyAnimeList":"https://myanimelist.net/profile/{}","AniList":"https://anilist.co/user/{}","Kitsu":"https://kitsu.io/users/{}",
"Patreon":"https://www.patreon.com/{}","Ko-fi":"https://ko-fi.com/{}","Buy Me a Coffee":"https://www.buymeacoffee.com/{}",
"Gumroad":"https://{}.gumroad.com/","Payhip":"https://payhip.com/{}","Liberapay":"https://liberapay.com/{}",
"Open Collective":"https://opencollective.com/{}","Keybase":"https://keybase.io/{}",
"Fandom":"https://community.fandom.com/wiki/User:{}","Instructables":"https://www.instructables.com/member/{}/",
"Thingiverse":"https://www.thingiverse.com/{}","OpenStreetMap":"https://www.openstreetmap.org/user/{}",
"Internet Archive":"https://archive.org/details/@{}","ResearchGate":"https://www.researchgate.net/profile/{}",
"Trello":"https://trello.com/u/{}","Figma":"https://www.figma.com/@{}","Product Hunt":"https://www.producthunt.com/@{}",
"Speaker Deck":"https://speakerdeck.com/{}","SlideShare":"https://www.slideshare.net/{}",
"Printables":"https://www.printables.com/@{}","MyMiniFactory":"https://www.myminifactory.com/users/{}",
"Cults3D":"https://cults3d.com/en/users/{}","GrabCAD":"https://grabcad.com/{}",
"Wikipedia":"https://en.wikipedia.org/wiki/User:{}","VK":"https://vk.com/{}",
"Douban":"https://www.douban.com/people/{}","Zhihu":"https://www.zhihu.com/people/{}",
"Bilibili":"https://space.bilibili.com/{}","Etsy":"https://www.etsy.com/shop/{}",
"Shopify":"https://{}.myshopify.com/","BigCartel":"https://{}.bigcartel.com/",
"WordPress":"https://{}.wordpress.com/","Blogspot":"https://{}.blogspot.com/","Ghost":"https://{}.ghost.io/",
}

# these 200 on literally anything, needs the title to mention the handle
FLAKY = {"Instagram", "TikTok", "Threads", "Quora", "Fandom", "Kick", "Rumble", "Replit", "Vero"}

# fast reliable ones for permutation sweeps, no point hammering 139 sites x 20 guesses
QUICK = {k: SITES[k] for k in ("GitHub", "Reddit", "Steam", "SoundCloud", "Twitch", "YouTube",
        "Medium", "Dev.to", "GitLab", "Pinterest", "Tumblr", "Bandcamp", "Last.fm", "Letterboxd",
        "Chess.com", "Lichess", "Kaggle", "Replit", "Patreon", "Ko-fi", "Flickr", "Unsplash",
        "Linktree", "About.me", "Vimeo") if k in SITES}

DIAL = {
"1":("USA/Canada (NANP)","US","North America","Washington/Ottawa","USD/CAD","UTC-4 to UTC-10",(10,10)),
"7":("Russia/Kazakhstan","RU","Europe/Asia","Moscow/Astana","RUB/KZT","UTC+2 to UTC+12",(10,10)),
"20":("Egypt","EG","Africa","Cairo","EGP","UTC+2",(9,10)),"27":("South Africa","ZA","Africa","Pretoria","ZAR","UTC+2",(9,9)),
"30":("Greece","GR","Europe","Athens","EUR","UTC+2",(10,10)),"31":("Netherlands","NL","Europe","Amsterdam","EUR","UTC+1",(9,9)),
"32":("Belgium","BE","Europe","Brussels","EUR","UTC+1",(8,9)),"33":("France","FR","Europe","Paris","EUR","UTC+1",(9,9)),
"34":("Spain","ES","Europe","Madrid","EUR","UTC+1",(9,9)),"36":("Hungary","HU","Europe","Budapest","HUF","UTC+1",(8,9)),
"39":("Italy","IT","Europe","Rome","EUR","UTC+1",(9,11)),"40":("Romania","RO","Europe","Bucharest","RON","UTC+2",(9,9)),
"41":("Switzerland","CH","Europe","Bern","CHF","UTC+1",(9,9)),"43":("Austria","AT","Europe","Vienna","EUR","UTC+1",(4,13)),
"44":("United Kingdom","GB","Europe","London","GBP","UTC+0",(9,10)),"45":("Denmark","DK","Europe","Copenhagen","DKK","UTC+1",(8,8)),
"46":("Sweden","SE","Europe","Stockholm","SEK","UTC+1",(7,9)),"47":("Norway","NO","Europe","Oslo","NOK","UTC+1",(8,8)),
"48":("Poland","PL","Europe","Warsaw","PLN","UTC+1",(9,9)),"49":("Germany","DE","Europe","Berlin","EUR","UTC+1",(6,11)),
"51":("Peru","PE","South America","Lima","PEN","UTC-5",(8,9)),"52":("Mexico","MX","North America","Mexico City","MXN","UTC-6",(10,10)),
"53":("Cuba","CU","North America","Havana","CUP","UTC-5",(8,8)),"54":("Argentina","AR","South America","Buenos Aires","ARS","UTC-3",(10,11)),
"55":("Brazil","BR","South America","Brasilia","BRL","UTC-3",(10,11)),"56":("Chile","CL","South America","Santiago","CLP","UTC-4",(9,9)),
"57":("Colombia","CO","South America","Bogota","COP","UTC-5",(10,10)),"58":("Venezuela","VE","South America","Caracas","VES","UTC-4",(10,10)),
"60":("Malaysia","MY","Asia","Kuala Lumpur","MYR","UTC+8",(9,10)),"61":("Australia","AU","Oceania","Canberra","AUD","UTC+8 to UTC+10",(9,9)),
"62":("Indonesia","ID","Asia","Jakarta","IDR","UTC+7 to UTC+9",(9,12)),"63":("Philippines","PH","Asia","Manila","PHP","UTC+8",(10,10)),
"64":("New Zealand","NZ","Oceania","Wellington","NZD","UTC+12",(8,10)),"65":("Singapore","SG","Asia","Singapore","SGD","UTC+8",(8,8)),
"66":("Thailand","TH","Asia","Bangkok","THB","UTC+7",(8,9)),"81":("Japan","JP","Asia","Tokyo","JPY","UTC+9",(9,10)),
"82":("South Korea","KR","Asia","Seoul","KRW","UTC+9",(8,10)),"84":("Vietnam","VN","Asia","Hanoi","VND","UTC+7",(9,10)),
"86":("China","CN","Asia","Beijing","CNY","UTC+8",(10,12)),"90":("Turkey","TR","Asia/Europe","Ankara","TRY","UTC+3",(10,10)),
"91":("India","IN","Asia","New Delhi","INR","UTC+5:30",(10,10)),"92":("Pakistan","PK","Asia","Islamabad","PKR","UTC+5",(9,10)),
"93":("Afghanistan","AF","Asia","Kabul","AFN","UTC+4:30",(9,9)),"94":("Sri Lanka","LK","Asia","Colombo","LKR","UTC+5:30",(9,9)),
"95":("Myanmar","MM","Asia","Naypyidaw","MMK","UTC+6:30",(8,10)),"98":("Iran","IR","Asia","Tehran","IRR","UTC+3:30",(10,10)),
"211":("South Sudan","SS","Africa","Juba","SSP","UTC+2",(9,9)),"212":("Morocco","MA","Africa","Rabat","MAD","UTC+1",(9,9)),
"213":("Algeria","DZ","Africa","Algiers","DZD","UTC+1",(9,9)),"216":("Tunisia","TN","Africa","Tunis","TND","UTC+1",(8,8)),
"218":("Libya","LY","Africa","Tripoli","LYD","UTC+2",(9,10)),"220":("Gambia","GM","Africa","Banjul","GMD","UTC+0",(7,7)),
"221":("Senegal","SN","Africa","Dakar","XOF","UTC+0",(9,9)),"222":("Mauritania","MR","Africa","Nouakchott","MRU","UTC+0",(8,8)),
"223":("Mali","ML","Africa","Bamako","XOF","UTC+0",(8,8)),"224":("Guinea","GN","Africa","Conakry","GNF","UTC+0",(8,9)),
"225":("Ivory Coast","CI","Africa","Yamoussoukro","XOF","UTC+0",(10,10)),"226":("Burkina Faso","BF","Africa","Ouagadougou","XOF","UTC+0",(8,8)),
"227":("Niger","NE","Africa","Niamey","XOF","UTC+1",(8,8)),"228":("Togo","TG","Africa","Lome","XOF","UTC+0",(8,8)),
"229":("Benin","BJ","Africa","Porto-Novo","XOF","UTC+1",(8,8)),"230":("Mauritius","MU","Africa","Port Louis","MUR","UTC+4",(7,8)),
"231":("Liberia","LR","Africa","Monrovia","LRD","UTC+0",(7,8)),"232":("Sierra Leone","SL","Africa","Freetown","SLL","UTC+0",(8,8)),
"233":("Ghana","GH","Africa","Accra","GHS","UTC+0",(9,9)),"234":("Nigeria","NG","Africa","Abuja","NGN","UTC+1",(10,10)),
"235":("Chad","TD","Africa","N'Djamena","XAF","UTC+1",(7,8)),"236":("Central African Rep.","CF","Africa","Bangui","XAF","UTC+1",(8,8)),
"237":("Cameroon","CM","Africa","Yaounde","XAF","UTC+1",(8,9)),"238":("Cape Verde","CV","Africa","Praia","CVE","UTC-1",(7,7)),
"239":("Sao Tome","ST","Africa","Sao Tome","STN","UTC+0",(7,7)),"240":("Eq. Guinea","GQ","Africa","Malabo","XAF","UTC+1",(9,9)),
"241":("Gabon","GA","Africa","Libreville","XAF","UTC+1",(7,8)),"242":("Congo Rep.","CG","Africa","Brazzaville","XAF","UTC+1",(9,9)),
"243":("Congo DR","CD","Africa","Kinshasa","CDF","UTC+1",(9,9)),"244":("Angola","AO","Africa","Luanda","AOA","UTC+1",(9,9)),
"245":("Guinea-Bissau","GW","Africa","Bissau","XOF","UTC+0",(7,7)),"248":("Seychelles","SC","Africa","Victoria","SCR","UTC+4",(7,7)),
"249":("Sudan","SD","Africa","Khartoum","SDG","UTC+2",(9,9)),"250":("Rwanda","RW","Africa","Kigali","RWF","UTC+2",(9,9)),
"251":("Ethiopia","ET","Africa","Addis Ababa","ETB","UTC+3",(9,9)),"252":("Somalia","SO","Africa","Mogadishu","SOS","UTC+3",(7,9)),
"253":("Djibouti","DJ","Africa","Djibouti","DJF","UTC+3",(8,8)),"254":("Kenya","KE","Africa","Nairobi","KES","UTC+3",(9,9)),
"255":("Tanzania","TZ","Africa","Dodoma","TZS","UTC+3",(9,9)),"256":("Uganda","UG","Africa","Kampala","UGX","UTC+3",(9,9)),
"257":("Burundi","BI","Africa","Gitega","BIF","UTC+2",(8,8)),"258":("Mozambique","MZ","Africa","Maputo","MZN","UTC+2",(9,9)),
"260":("Zambia","ZM","Africa","Lusaka","ZMW","UTC+2",(9,9)),"261":("Madagascar","MG","Africa","Antananarivo","MGA","UTC+3",(9,9)),
"262":("Reunion/Mayotte","RE","Africa","Saint-Denis","EUR","UTC+4",(9,9)),"263":("Zimbabwe","ZW","Africa","Harare","ZWL","UTC+2",(9,9)),
"264":("Namibia","NA","Africa","Windhoek","NAD","UTC+2",(9,9)),"265":("Malawi","MW","Africa","Lilongwe","MWK","UTC+2",(7,9)),
"266":("Lesotho","LS","Africa","Maseru","LSL","UTC+2",(8,8)),"267":("Botswana","BW","Africa","Gaborone","BWP","UTC+2",(8,8)),
"268":("Eswatini","SZ","Africa","Mbabane","SZL","UTC+2",(8,8)),"269":("Comoros","KM","Africa","Moroni","KMF","UTC+3",(7,7)),
"290":("St Helena","SH","Africa","Jamestown","SHP","UTC+0",(4,4)),"291":("Eritrea","ER","Africa","Asmara","ERN","UTC+3",(7,7)),
"297":("Aruba","AW","South America","Oranjestad","AWG","UTC-4",(7,7)),"298":("Faroe Islands","FO","Europe","Torshavn","DKK","UTC+0",(6,6)),
"299":("Greenland","GL","North America","Nuuk","DKK","UTC-2",(6,6)),"350":("Gibraltar","GI","Europe","Gibraltar","GIP","UTC+1",(8,8)),
"351":("Portugal","PT","Europe","Lisbon","EUR","UTC+0",(9,9)),"352":("Luxembourg","LU","Europe","Luxembourg","EUR","UTC+1",(5,11)),
"353":("Ireland","IE","Europe","Dublin","EUR","UTC+0",(9,9)),"354":("Iceland","IS","Europe","Reykjavik","ISK","UTC+0",(7,7)),
"355":("Albania","AL","Europe","Tirana","ALL","UTC+1",(9,9)),"356":("Malta","MT","Europe","Valletta","EUR","UTC+1",(8,8)),
"357":("Cyprus","CY","Europe","Nicosia","EUR","UTC+2",(8,8)),"358":("Finland","FI","Europe","Helsinki","EUR","UTC+2",(5,12)),
"359":("Bulgaria","BG","Europe","Sofia","EUR","UTC+2",(8,9)),"370":("Lithuania","LT","Europe","Vilnius","EUR","UTC+2",(8,8)),
"371":("Latvia","LV","Europe","Riga","EUR","UTC+2",(8,8)),"372":("Estonia","EE","Europe","Tallinn","EUR","UTC+2",(7,10)),
"373":("Moldova","MD","Europe","Chisinau","MDL","UTC+2",(8,8)),"374":("Armenia","AM","Asia","Yerevan","AMD","UTC+4",(8,8)),
"375":("Belarus","BY","Europe","Minsk","BYN","UTC+3",(9,9)),"376":("Andorra","AD","Europe","Andorra la Vella","EUR","UTC+1",(6,6)),
"377":("Monaco","MC","Europe","Monaco","EUR","UTC+1",(8,9)),"378":("San Marino","SM","Europe","San Marino","EUR","UTC+1",(6,10)),
"380":("Ukraine","UA","Europe","Kyiv","UAH","UTC+2",(9,9)),"381":("Serbia","RS","Europe","Belgrade","RSD","UTC+1",(8,9)),
"382":("Montenegro","ME","Europe","Podgorica","EUR","UTC+1",(8,8)),"383":("Kosovo","XK","Europe","Pristina","EUR","UTC+1",(8,8)),
"385":("Croatia","HR","Europe","Zagreb","EUR","UTC+1",(8,9)),"386":("Slovenia","SI","Europe","Ljubljana","EUR","UTC+1",(8,8)),
"387":("Bosnia","BA","Europe","Sarajevo","BAM","UTC+1",(8,8)),"389":("North Macedonia","MK","Europe","Skopje","MKD","UTC+1",(8,8)),
"420":("Czech Republic","CZ","Europe","Prague","CZK","UTC+1",(9,9)),"421":("Slovakia","SK","Europe","Bratislava","EUR","UTC+1",(9,9)),
"423":("Liechtenstein","LI","Europe","Vaduz","CHF","UTC+1",(7,7)),"500":("Falkland Islands","FK","South America","Stanley","FKP","UTC-4",(5,5)),
"501":("Belize","BZ","North America","Belmopan","BZD","UTC-6",(7,7)),"502":("Guatemala","GT","North America","Guatemala City","GTQ","UTC-6",(8,8)),
"503":("El Salvador","SV","North America","San Salvador","USD","UTC-6",(8,8)),"504":("Honduras","HN","North America","Tegucigalpa","HNL","UTC-6",(8,8)),
"505":("Nicaragua","NI","North America","Managua","NIO","UTC-6",(8,8)),"506":("Costa Rica","CR","North America","San Jose","CRC","UTC-6",(8,8)),
"507":("Panama","PA","North America","Panama City","PAB","UTC-5",(7,8)),"509":("Haiti","HT","North America","Port-au-Prince","HTG","UTC-5",(8,8)),
"590":("Guadeloupe","GP","North America","Basse-Terre","EUR","UTC-4",(9,9)),"591":("Bolivia","BO","South America","La Paz","BOB","UTC-4",(8,8)),
"592":("Guyana","GY","South America","Georgetown","GYD","UTC-4",(7,7)),"593":("Ecuador","EC","South America","Quito","USD","UTC-5",(8,9)),
"594":("French Guiana","GF","South America","Cayenne","EUR","UTC-3",(9,9)),"595":("Paraguay","PY","South America","Asuncion","PYG","UTC-4",(8,9)),
"597":("Suriname","SR","South America","Paramaribo","SRD","UTC-3",(7,7)),"598":("Uruguay","UY","South America","Montevideo","UYU","UTC-3",(8,8)),
"599":("Curacao","CW","South America","Willemstad","ANG","UTC-4",(7,8)),"670":("East Timor","TL","Asia","Dili","USD","UTC+9",(7,8)),
"673":("Brunei","BN","Asia","Bandar Seri Begawan","BND","UTC+8",(7,7)),"674":("Nauru","NR","Oceania","Yaren","AUD","UTC+12",(7,7)),
"675":("Papua New Guinea","PG","Oceania","Port Moresby","PGK","UTC+10",(7,8)),"676":("Tonga","TO","Oceania","Nuku'alofa","TOP","UTC+13",(5,5)),
"677":("Solomon Islands","SB","Oceania","Honiara","SBD","UTC+11",(5,7)),"678":("Vanuatu","VU","Oceania","Port Vila","VUV","UTC+11",(5,7)),
"679":("Fiji","FJ","Oceania","Suva","FJD","UTC+12",(7,7)),"680":("Palau","PW","Oceania","Ngerulmud","USD","UTC+9",(7,7)),
"685":("Samoa","WS","Oceania","Apia","WST","UTC+13",(5,7)),"686":("Kiribati","KI","Oceania","Tarawa","AUD","UTC+12",(5,5)),
"687":("New Caledonia","NC","Oceania","Noumea","XPF","UTC+11",(6,6)),"688":("Tuvalu","TV","Oceania","Funafuti","AUD","UTC+12",(5,6)),
"689":("French Polynesia","PF","Oceania","Papeete","XPF","UTC-10",(6,8)),"691":("Micronesia","FM","Oceania","Palikir","USD","UTC+10",(7,7)),
"692":("Marshall Islands","MH","Oceania","Majuro","USD","UTC+12",(7,7)),"850":("North Korea","KP","Asia","Pyongyang","KPW","UTC+9",(8,10)),
"852":("Hong Kong","HK","Asia","Hong Kong","HKD","UTC+8",(8,8)),"853":("Macau","MO","Asia","Macau","MOP","UTC+8",(8,8)),
"855":("Cambodia","KH","Asia","Phnom Penh","KHR","UTC+7",(8,9)),"856":("Laos","LA","Asia","Vientiane","LAK","UTC+7",(8,10)),
"880":("Bangladesh","BD","Asia","Dhaka","BDT","UTC+6",(10,10)),"886":("Taiwan","TW","Asia","Taipei","TWD","UTC+8",(9,9)),
"960":("Maldives","MV","Asia","Male","MVR","UTC+5",(7,7)),"961":("Lebanon","LB","Asia","Beirut","LBP","UTC+2",(7,8)),
"962":("Jordan","JO","Asia","Amman","JOD","UTC+3",(8,9)),"963":("Syria","SY","Asia","Damascus","SYP","UTC+3",(9,9)),
"964":("Iraq","IQ","Asia","Baghdad","IQD","UTC+3",(10,10)),"965":("Kuwait","KW","Asia","Kuwait City","KWD","UTC+3",(8,8)),
"966":("Saudi Arabia","SA","Asia","Riyadh","SAR","UTC+3",(8,9)),"967":("Yemen","YE","Asia","Sanaa","YER","UTC+3",(9,9)),
"968":("Oman","OM","Asia","Muscat","OMR","UTC+4",(8,8)),"970":("Palestine","PS","Asia","Ramallah","ILS","UTC+2",(9,9)),
"971":("UAE","AE","Asia","Abu Dhabi","AED","UTC+4",(8,9)),"972":("Israel","IL","Asia","Jerusalem","ILS","UTC+2",(8,9)),
"973":("Bahrain","BH","Asia","Manama","BHD","UTC+3",(8,8)),"974":("Qatar","QA","Asia","Doha","QAR","UTC+3",(8,8)),
"975":("Bhutan","BT","Asia","Thimphu","BTN","UTC+6",(8,8)),"976":("Mongolia","MN","Asia","Ulaanbaatar","MNT","UTC+8",(8,8)),
"977":("Nepal","NP","Asia","Kathmandu","NPR","UTC+5:45",(10,10)),"992":("Tajikistan","TJ","Asia","Dushanbe","TJS","UTC+5",(9,9)),
"993":("Turkmenistan","TM","Asia","Ashgabat","TMT","UTC+5",(8,9)),"994":("Azerbaijan","AZ","Asia","Baku","AZN","UTC+4",(9,9)),
"995":("Georgia","GE","Asia","Tbilisi","GEL","UTC+4",(9,9)),"996":("Kyrgyzstan","KG","Asia","Bishkek","KGS","UTC+6",(9,9)),
"998":("Uzbekistan","UZ","Asia","Tashkent","UZS","UTC+5",(9,9)),
}

NANP_STATES = {
"Alabama":"205 251 256 334 659 938","Alaska":"907","Arizona":"480 520 602 623 928","Arkansas":"479 501 870 327",
"California":"209 213 279 310 323 341 408 415 424 442 510 530 559 562 619 626 628 650 657 661 669 707 714 747 760 805 818 820 831 840 858 909 916 925 949 951",
"Colorado":"303 719 720 970 983","Connecticut":"203 475 860 959","Delaware":"302","District of Columbia":"202",
"Florida":"239 305 321 352 386 407 561 689 727 754 772 786 813 850 863 904 941 954",
"Georgia":"229 404 470 478 678 706 762 770 912 943","Hawaii":"808","Idaho":"208 986",
"Illinois":"217 224 309 312 331 464 618 630 708 730 773 779 815 847 872",
"Indiana":"219 260 317 463 574 765 812 930","Iowa":"319 515 563 641 712","Kansas":"316 620 785 913",
"Kentucky":"270 364 502 606 859","Louisiana":"225 318 337 504 985","Maine":"207",
"Maryland":"240 301 410 443 667","Massachusetts":"339 351 413 508 617 774 781 857 978",
"Michigan":"231 248 269 313 517 586 616 734 810 906 947 989","Minnesota":"218 320 507 612 651 763 952",
"Mississippi":"228 601 662 769","Missouri":"314 417 557 573 636 660 816 975","Montana":"406",
"Nebraska":"308 402 531","Nevada":"702 725 775","New Hampshire":"603",
"New Jersey":"201 551 609 640 732 848 856 862 908 973","New Mexico":"505 575",
"New York":"212 315 332 347 516 518 585 607 631 646 680 716 718 838 845 914 917 929 934",
"North Carolina":"252 336 704 743 828 910 919 980 984","North Dakota":"701",
"Ohio":"216 220 234 283 326 330 380 419 440 513 567 614 740 937","Oklahoma":"405 539 572 580 918",
"Oregon":"458 503 541 971","Pennsylvania":"215 223 267 272 412 445 484 570 582 610 717 724 814 878",
"Rhode Island":"401","South Carolina":"803 839 843 854 864","South Dakota":"605",
"Tennessee":"423 615 629 731 865 901 931","Texas":"210 214 254 281 325 346 361 409 430 432 469 512 682 713 726 737 806 817 830 832 903 915 936 940 945 956 972 979",
"Utah":"385 435 801","Vermont":"802","Virginia":"276 434 540 571 703 757 804 826 948",
"Washington":"206 253 360 425 509 564","West Virginia":"304 681","Wisconsin":"262 274 414 534 608 715 920","Wyoming":"307",
}
NANP_CANADA = {
"Ontario":"226 249 289 343 382 416 437 519 647 683 705 807 905",
"Quebec":"263 354 367 418 438 450 468 514 579 581 819 873",
"British Columbia":"236 250 604 672 778","Alberta":"368 403 587 825",
"Manitoba":"204 431 584","Saskatchewan":"306 474 639","Nova Scotia/PEI":"782 902",
"New Brunswick":"506","Newfoundland":"709","Northern Territories":"867",
}
NANP_CARIB = {
"Bahamas":"242","Barbados":"246","Anguilla":"264","Antigua":"268","BVI":"284","USVI":"340",
"Cayman":"345","Bermuda":"441","Grenada":"473","Turks/Caicos":"649","Montserrat":"664",
"N. Mariana":"670","Guam":"671","American Samoa":"684","Sint Maarten":"721","St Lucia":"758",
"Dominica":"767","St Vincent":"784","Puerto Rico":"787 939","Dominican Rep":"809 829 849",
"Trinidad/Tobago":"868","St Kitts":"869","Jamaica":"876 658",
}
NANP_METROS = {
"New York City":"212 646 332 917 718 347 929","Los Angeles":"213 323 310 424 818 747",
"Chicago":"312 773 872","Houston":"713 832 281 346","Dallas-Ft Worth":"214 469 972 945 430",
"Miami":"305 786","Atlanta":"404 470 678 770 943","Boston":"617 857 781","Washington DC":"202 771",
"Seattle":"206 425 564","Phoenix":"602 480 623","Philadelphia":"215 267 445 610",
"Detroit":"313 248 734 586","SF Bay Area":"415 628 510 925 408 669","San Diego":"619 858 760",
"Denver":"303 720 983","Las Vegas":"702 725","Toronto":"416 647 437","Montreal":"514 438",
"Vancouver":"604 778 236 672",
}
NANP_AREA, NANP_METRO = {}, {}
for _s in NANP_STATES:
    for _c in NANP_STATES[_s].split(): NANP_AREA[_c] = _s + ", USA"
for _s in NANP_CANADA:
    for _c in NANP_CANADA[_s].split(): NANP_AREA[_c] = _s + ", Canada"
for _s in NANP_CARIB:
    for _c in NANP_CARIB[_s].split(): NANP_AREA[_c] = _s
for _c in NANP_METROS:
    for _a in NANP_METROS[_c].split(): NANP_METRO[_a] = _c

NANP_MONEY = {"Bahamas":"BSD","Barbados":"BBD","Bermuda":"BMD","Cayman":"KYD","Dominican Rep":"DOP",
"Jamaica":"JMD","Puerto Rico":"USD","Trinidad/Tobago":"TTD","Guam":"USD"}

REG = {
"GB":{"20":"London","113":"Leeds","114":"Sheffield","115":"Nottingham","116":"Leicester","117":"Bristol",
"118":"Reading","121":"Birmingham","131":"Edinburgh","141":"Glasgow","151":"Liverpool","161":"Manchester",
"191":"Newcastle/Sunderland","1865":"Oxford","1223":"Cambridge","1273":"Brighton","1274":"Bradford",
"1382":"Dundee","1392":"Exeter","28":"Northern Ireland"},
"IN":{"11":"Delhi","22":"Mumbai","33":"Kolkata","44":"Chennai","20":"Pune","40":"Hyderabad","79":"Ahmedabad",
"80":"Bengaluru","141":"Jaipur","161":"Ludhiana","172":"Chandigarh","183":"Amritsar","194":"Srinagar",
"253":"Nashik","261":"Surat","265":"Vadodara","361":"Guwahati","422":"Coimbatore","452":"Madurai",
"471":"Thiruvananthapuram","484":"Kochi","512":"Kanpur","522":"Lucknow","562":"Agra","612":"Patna",
"651":"Ranchi","671":"Bhubaneswar","712":"Nagpur","731":"Indore","751":"Gwalior","755":"Bhopal",
"771":"Raipur","821":"Mysuru","866":"Vijayawada","891":"Visakhapatnam","135":"Dehradun"},
"DE":{"30":"Berlin","40":"Hamburg","69":"Frankfurt","89":"Munich","221":"Cologne","211":"Dusseldorf",
"231":"Dortmund","201":"Essen","711":"Stuttgart","621":"Mannheim","511":"Hanover","351":"Dresden",
"341":"Leipzig","911":"Nuremberg","721":"Karlsruhe","421":"Bremen"},
"FR":{"1":"Paris/Ile-de-France","2":"northwest","3":"northeast","4":"southeast","5":"southwest"},
"IT":{"02":"Milan","06":"Rome","011":"Turin","081":"Naples","055":"Florence","041":"Venice","051":"Bologna",
"091":"Palermo","010":"Genoa","045":"Verona","070":"Cagliari","080":"Bari"},
"ES":{"91":"Madrid","93":"Barcelona","96":"Valencia","95":"Seville","94":"Bilbao","981":"A Coruna",
"971":"Balearics","922":"Tenerife","928":"Las Palmas","952":"Malaga","976":"Zaragoza"},
"PT":{"21":"Lisbon","22":"Porto","289":"Faro","239":"Coimbra"},"NL":{"20":"Amsterdam","10":"Rotterdam",
"70":"The Hague","30":"Utrecht","40":"Eindhoven","50":"Groningen"},
"BE":{"2":"Brussels","3":"Antwerp","9":"Ghent","16":"Leuven"},"CH":{"44":"Zurich","22":"Geneva","31":"Bern","61":"Basel"},
"AT":{"1":"Vienna","316":"Graz","662":"Salzburg","463":"Linz"},"SE":{"8":"Stockholm","31":"Gothenburg","40":"Malmo"},
"NO":{"2":"Oslo","5":"Bergen","51":"Stavanger","73":"Trondheim"},"DK":{"33":"Copenhagen","86":"Aarhus"},
"FI":{"9":"Helsinki","3":"Tampere","2":"Turku"},"IE":{"1":"Dublin","21":"Cork","91":"Galway"},
"PL":{"22":"Warsaw","12":"Krakow","61":"Poznan","71":"Wroclaw","58":"Gdansk","42":"Lodz"},
"CZ":{"2":"Prague","5":"Brno"},"SK":{"2":"Bratislava","55":"Kosice"},"HU":{"1":"Budapest"},
"RO":{"21":"Bucharest","264":"Cluj-Napoca","256":"Timisoara"},"BG":{"2":"Sofia","32":"Plovdiv"},
"GR":{"21":"Athens","2310":"Thessaloniki"},"HR":{"1":"Zagreb","21":"Split"},"RS":{"11":"Belgrade","21":"Novi Sad"},
"UA":{"44":"Kyiv","32":"Lviv","48":"Odesa","57":"Kharkiv","56":"Dnipro"},"BY":{"17":"Minsk"},
"LT":{"5":"Vilnius","37":"Kaunas"},"LV":{"67":"Riga"},"EE":{"6":"Tallinn","7":"Tartu"},
"RU":{"495":"Moscow","499":"Moscow","812":"St Petersburg","343":"Yekaterinburg","383":"Novosibirsk",
"843":"Kazan","863":"Rostov-on-Don","846":"Samara","351":"Chelyabinsk","831":"Nizhny Novgorod"},
"KZ":{"727":"Almaty","717":"Astana"},"TR":{"212":"Istanbul (european)","216":"Istanbul (asian)","312":"Ankara",
"232":"Izmir","242":"Antalya","322":"Adana"},
"CN":{"10":"Beijing","21":"Shanghai","20":"Guangzhou","755":"Shenzhen","28":"Chengdu","27":"Wuhan",
"25":"Nanjing","22":"Tianjin","29":"Xian","571":"Hangzhou","592":"Xiamen","24":"Shenyang","531":"Jinan"},
"JP":{"3":"Tokyo","6":"Osaka","52":"Nagoya","11":"Sapporo","92":"Fukuoka","45":"Yokohama","75":"Kyoto","78":"Kobe"},
"KR":{"2":"Seoul","51":"Busan","53":"Daegu","32":"Incheon"},"TW":{"2":"Taipei","7":"Kaohsiung","4":"Taichung"},
"MY":{"3":"Kuala Lumpur","4":"Penang"},"TH":{"2":"Bangkok","53":"Chiang Mai","76":"Phuket"},
"VN":{"24":"Hanoi","28":"Ho Chi Minh City"},"ID":{"21":"Jakarta","22":"Bandung","31":"Surabaya","61":"Medan","361":"Bali"},
"PH":{"2":"Metro Manila","32":"Cebu","82":"Davao"},"PK":{"21":"Karachi","42":"Lahore","51":"Islamabad/Rawalpindi",
"61":"Multan","41":"Faisalabad","91":"Peshawar","81":"Quetta"},
"BD":{"2":"Dhaka","31":"Chattogram","821":"Sylhet"},"LK":{"11":"Colombo"},"IR":{"21":"Tehran","51":"Isfahan","71":"Shiraz"},
"IQ":{"1":"Baghdad","71":"Basra"},"SA":{"11":"Riyadh","12":"Jeddah/Makkah","13":"Dammam/Eastern","14":"Madinah"},
"AE":{"2":"Abu Dhabi","4":"Dubai","6":"Sharjah/Ajman","3":"Al Ain"},"IL":{"2":"Jerusalem","3":"Tel Aviv","4":"Haifa"},
"EG":{"2":"Cairo/Giza","3":"Alexandria"},"MA":{"522":"Casablanca","537":"Rabat","528":"Agadir","539":"Tangier"},
"DZ":{"21":"Algiers","41":"Oran"},"TN":{"71":"Tunis","73":"Sousse"},"LY":{"21":"Tripoli","91":"Benghazi"},
"NG":{"1":"Lagos/Abuja","9":"Lagos region"},"GH":{"30":"Accra","32":"Kumasi"},"KE":{"20":"Nairobi","41":"Mombasa"},
"ET":{"11":"Addis Ababa"},"TZ":{"22":"Dar es Salaam","27":"Arusha","24":"Zanzibar"},"UG":{"41":"Kampala"},
"ZA":{"11":"Johannesburg","21":"Cape Town","31":"Durban","12":"Pretoria","41":"Gqeberha"},
"BR":{"11":"Sao Paulo","21":"Rio de Janeiro","31":"Belo Horizonte","41":"Curitiba","51":"Porto Alegre",
"61":"Brasilia","71":"Salvador","81":"Recife","85":"Fortaleza","92":"Manaus","19":"Campinas"},
"MX":{"55":"CDMX","33":"Guadalajara","81":"Monterrey","222":"Puebla","664":"Tijuana","998":"Cancun"},
"AR":{"11":"Buenos Aires (AMBA)","351":"Cordoba","341":"Rosario","261":"Mendoza"},
"CL":{"2":"Santiago","32":"Valparaiso","41":"Concepcion"},"CO":{"1":"Bogota","4":"Medellin","2":"Cali"},
"PE":{"1":"Lima/Callao","84":"Cusco","54":"Arequipa"},"VE":{"212":"Caracas","261":"Maracaibo"},
"EC":{"2":"Quito","4":"Guayaquil"},"BO":{"2":"La Paz/El Alto","4":"Santa Cruz"},"PY":{"21":"Asuncion"},
"UY":{"2":"Montevideo"},"AU":{"2":"NSW/ACT","3":"VIC/TAS","7":"QLD","8":"SA/WA/NT"},
"NZ":{"9":"Auckland","4":"Wellington","3":"Christchurch"},
}

MOB = {
"GB":"74 75 76 77 78 79","IN":"6 7 8 9","PK":"3","BD":"1","NG":"80 81 90 91","KE":"7 11","GH":"2 5",
"ZA":"6 7 8","EG":"1","MA":"6 7","DZ":"5 6 7","TN":"2 5 9","LY":"9","ET":"9","TZ":"7 6","UG":"7",
"CM":"6","SN":"7","CI":"01 05 07","CD":"8 9","AO":"9","MZ":"8","ZM":"9","ZW":"71 73 77 78",
"BF":"5 6 7","ML":"6 7 8 9","BJ":"9","TG":"9","GN":"6","LR":"5 7 8","SL":"76 77 78",
"DE":"15 16 17","FR":"6 7","IT":"3","ES":"6 7","PT":"9","NL":"6","BE":"4","CH":"7","AT":"6",
"SE":"7","NO":"4 9","FI":"4 5","IE":"8","PL":"45 50 51 53 57 60 66 69 72 73 78 79 88","CZ":"6 7",
"SK":"9","HU":"20 30 31 70","RO":"7","BG":"4 8","GR":"6","HR":"9","RS":"6",
"UA":"39 50 63 66 67 68 73 91 92 93 94 95 96 97 98 99","BY":"25 29 33 44","LT":"6","LV":"2","EE":"5",
"MD":"6 7","UZ":"88 90 91 93 94 95 97 98 99","GE":"4 5 9","AM":"4 5 9","AZ":"4 5 6 7 9","TR":"5",
"IR":"9","IQ":"7 9","JO":"7","LB":"3 7 8","YE":"7","OM":"7 9","KW":"5 6 9","QA":"3 5 6 7","BH":"3 6",
"SA":"5","AE":"5","IL":"5","PS":"5","AF":"7","LK":"7","NP":"97 98","MM":"9","TH":"6 8 9",
"VN":"3 5 7 8 9","KH":"1 6 7 8 9","MY":"1","SG":"8 9","ID":"8","PH":"9",
"CN":"13 14 15 16 17 18 19","HK":"5 6 7 9","JP":"70 80 90","KR":"10","TW":"9","MN":"5 6 7 8 9",
"AU":"4","NZ":"20 21 22 27 28 29","CO":"3","VE":"4","CL":"9","PE":"9","EC":"9","BO":"6 7",
"PY":"9","UY":"9","CR":"5 6 7 8","PA":"6","GT":"3 4 5","SV":"7","HN":"3 7 8 9","NI":"5 7 8","CU":"5",
}
FREE = {
"GB":"80 808","IN":"1800 1860 1861","DE":"800","FR":"800 805 809","ES":"800 900","IT":"800 803",
"NL":"800","BE":"800","CH":"800","AT":"800","IE":"1800","PL":"800","PT":"800","SE":"20","NO":"800",
"DK":"80","FI":"800","GR":"800","CZ":"800","HU":"80","RO":"800","TR":"800","UA":"800","IL":"1800",
"AE":"800","SA":"800","PK":"800","CN":"400 800","JP":"120 800","KR":"800","TW":"800","SG":"800 1800",
"MY":"1800","TH":"1800","VN":"1800","PH":"1800","ID":"800","AU":"1800","NZ":"800 508","BR":"800",
"MX":"800","AR":"800","ZA":"800",
}
PREM = {"GB":"90 91","DE":"900","FR":"89","IT":"899 892","ES":"803 806 807 905","NL":"900","CH":"900",
"AT":"93","AU":"190","NZ":"900","RU":"809","CN":"16","JP":"990"}
# mnp ruined carrier lookups everywhere, treat all of this as a guess at best
CARRIERS = {
"NG":{"MTN":"803 806 810 813 814 816 903 906 913 916","Airtel":"802 808 812 701 708 901 902 904 907 912",
"Glo":"805 807 811 815 705 703 706 905 915","9mobile":"809 817 818 908 909"},
"PK":{"Jazz":"30 32","Zong":"31","Ufone":"33","Telenor":"34"},
"BD":{"Grameenphone":"13 17","Banglalink":"14 19","Robi":"16 18","Teletalk":"15"},
"RU":{"MTS":"91 98","Beeline":"903 906 961 962 963 968","MegaFon":"92 93","Tele2":"95"},
"TR":{"Turkcell":"53","Vodafone":"54","TurkTelekom":"55"},
"UA":{"Kyivstar":"67 68 96 97 98","Vodafone":"50 66 95 99","lifecell":"63 73 93"},
"VN":{"Viettel":"96 97 98 86","VinaPhone":"91 94 83 84","MobiFone":"89 90 93"},
}
UK_TERR = {"7624":"Isle of Man (mobile)","1481":"Guernsey","7781":"Guernsey (mobile)",
"1534":"Jersey","7797":"Jersey (mobile)","1624":"Isle of Man"}
EMERGENCY = {
"112":"EU standard, works on most gsm networks","911":"US, Canada, Mexico, Argentina, Philippines",
"999":"UK, Ireland, Malaysia, Singapore, Hong Kong","000":"Australia","111":"New Zealand",
"110":"Japan/China/Germany police","119":"Japan fire+ambulance","100":"India police, Israel police",
"101":"India/Ukraine fire","102":"India ambulance, Ukraine police","103":"Ukraine ambulance",
"15":"France medical","17":"France police","18":"France fire","190":"Brazil police",
"192":"Brazil ambulance","193":"Brazil fire","113":"Vietnam police","115":"Vietnam ambulance",
}
GLOBAL_CODES = {"800":"international toll-free (UIFN)","808":"shared cost service","870":"Inmarsat satellite",
"881":"global mobile satellite","882":"international network","883":"international network"}
NOTES = {"IN":"portability since 2015, prefixes no longer map to carriers",
"MX":"10 digits everywhere now, type is invisible from digits alone",
"BR":"mobiles got a 9 prepended a while back","AR":"the 9 right after country code marks mobile",
"IT":"italy keeps the leading 0 in intl format, that is normal",
"CN":"13x-19x mobile, landlines carry the city code"}

THROWAWAY = {"mailinator.com","guerrillamail.com","10minutemail.com","tempmail.com","yopmail.com",
"trashmail.com","getnada.com","sharklasers.com","dispostable.com","maildrop.cc","tempinbox.com",
"grr.la","throwawaymail.com","mintemail.com","temp-mail.org","burnermail.io","fakeinbox.com",
"mytemp.email","mohmal.com","dropmail.me"}

WHOIS_SRV = {"com":"whois.verisign-grs.com","net":"whois.verisign-grs.com","org":"whois.pir.org",
"io":"whois.nic.io","co":"whois.nic.co","me":"whois.nic.me","info":"whois.afilias.net",
"dev":"whois.nic.google","app":"whois.nic.google","xyz":"whois.nic.xyz","gg":"whois.nic.gg"}

SUBS = ("www","mail","ftp","api","dev","staging","blog","admin","vpn","old","portal","app","cdn",
"ns1","ns2","smtp","pop","imap","webmail","git","jenkins","jira","wiki","docs","status","support",
"shop","store","beta","test","remote","gateway","proxy","sso","auth","backup","db","sql","monitor",
"grafana","kibana","prometheus","internal","corp","intranet","assets","static","img","images","media",
"downloads","files","cpanel","whm","phpmyadmin","dashboard","metrics","logs","chat","community","forum")

PORTS = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",443:"https",
445:"smb",993:"imaps",995:"pop3s",1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgres",5900:"vnc",
6379:"redis",8080:"http-alt",8443:"https-alt",27017:"mongodb",9200:"elasticsearch",11211:"memcached"}

INTERESTS = {
"development": {"code","coding","developer","dev","software","engineer","programming","programmer",
    "python","javascript","typescript","rust","golang","java","cpp","backend","frontend","fullstack",
    "full-stack","webdev","github","opensource","open","source","api","linux","terminal","vim","neovim",
    "docker","kubernetes","k8s","git","build","building","ship","shipping"},
"gaming": {"gamer","gaming","games","game","twitch","streamer","stream","fps","rpg","mmo","minecraft",
    "valorant","csgo","counter","strike","dota","lol","league","legends","fortnite","roblox","steam",
    "playstation","xbox","nintendo","speedrun","speedrunner","speedrunning","osu","rhythm","esports",
    "gamedev","player","clutch","ranked","smurf","noob"},
"music": {"music","musician","producer","dj","beatmaker","guitar","guitarist","pianist","piano",
    "drums","drummer","singer","vocalist","spotify","soundcloud","bandcamp","vinyl","audiophile",
    "hip","hop","rap","metal","rock","punk","jazz","classical","edm","techno","house","lofi","lo-fi",
    "beats","listener","playlist"},
"art_design": {"artist","illustrator","illustration","designer","design","graphic","ui","ux","painter",
    "painting","drawing","sketch","sketchbook","photographer","photography","photos","canon","nikon",
    "lightroom","photoshop","blender","3d","pixel","artstation","dribbble","behance","commissions",
    "art","draw","anime","digitalart","concept"},
"crypto_finance": {"crypto","bitcoin","btc","ethereum","eth","blockchain","web3","defi","nft","nfts",
    "solana","trading","trader","stocks","forex","investor","investing","hodl","mining","miner",
    "altcoin","coinbase","binance","token","dao","fintech","markets","charts","technical","analysis"},
"security": {"hacker","hacking","hackerone","bugbounty","pentest","pentester","penetration","red",
    "team","blue","ctf","cybersecurity","infosec","security","malware","reverse","engineering",
    "exploit","owasp","kali","0day","vulnerability","hackthebox","tryhackme","offsec"},
"science": {"science","physics","math","mathematics","researcher","research","phd","student",
    "astronomy","astrophysics","quantum","biology","chemistry","neuroscience","ai","ml","machine",
    "learning","datascience","data","neural","network","llm","deep","papers","academic","university"},
"sports_fitness": {"football","soccer","basketball","nba","nfl","cricket","tennis","gym","fitness",
    "bodybuilding","powerlifting","runner","running","cycling","cyclist","swimmer","boxing","mma",
    "ufc","yoga","athlete","training","workout","crossfit","lift","gains","calisthenics"},
"travel": {"travel","traveling","traveler","wanderlust","backpacker","nomad","expat","adventure",
    "hiking","hiker","mountains","surfing","surfer","climbing","vanlife","roadtrip","flights",
    "passport","world","abroad","travelling"},
"food": {"foodie","food","chef","cooking","cook","baker","baking","barista","coffee","pizza","vegan",
    "vegetarian","recipes","foodporn","sommelier","wine","beer","whisky","homecook","kitchen","bbq"},
"anime": {"anime","manga","otaku","weeb","waifu","cosplay","cosplayer","nihongo","senpai","kawaii",
    "vocaloid","isekai","shonen","ghibli","figure","collection","subbed","dubbed"},
"writing": {"writer","author","writing","novelist","poet","poetry","blogger","blog","journalist",
    "journalism","editor","copywriter","storyteller","fiction","screenwriter","novel","books",
    "reader","bookworm","amwriting","wip"},
"film": {"film","films","filmmaker","cinema","movie","movies","director","screenplay","cinephile",
    "letterboxd","horror","scifi","actor","actress","filmphotography","camera","videographer",
    "video","editing","premiere","davinci","shorts"},
"business": {"entrepreneur","founder","ceo","startup","startups","business","saas","marketing",
    "growth","freelancer","freelance","consultant","agency","ecommerce","dropshipping","branding",
    "sales","b2b","indie","hacker","maker","bootstrapped","solopreneur"},
}



def _scan_one(job):
    site, url, user = job
    link = url.format(user)
    try:
        time.sleep(random.uniform(0, 0.25))
        r = requests.get(link, timeout=8, headers={"User-Agent": UA}, allow_redirects=True)
        body = r.text or ""
        # pull metas here in the thread, doing it after was slow as hell
        if r.status_code == 200:
            title, desc, og = extract_meta(body)
            return (site, link, 200, len(body), title, desc, og)
        return (site, link, r.status_code, len(body), "", "", "")
    except requests.exceptions.Timeout:
        return (site, link, 0, 0, "", "", "")
    except Exception:
        return (site, link, -1, 0, "", "", "")


def _sweep(sitelist, user, quiet=False, label=""):
    if not quiet:
        hdr(f"USERNAME SWEEP {label}  ({len(sitelist)} sites)")
    jobs = [(s, u, user) for s, u in sitelist.items()]
    results = {}
    total = len(jobs)
    n = 0
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_scan_one, j) for j in jobs]
        for f in as_completed(futs):
            try:
                site, link, code, size, title, desc, og = f.result(timeout=15)
            except Exception:
                continue
            results[site] = (link, code, size, title, desc, og)
            n += 1
            if not quiet:
                filled = int(26 * n / total)
                print(f"\r  {D}[{'█'*filled}{'░'*(26-filled)}]{R} {n}/{total}", end="", flush=True)
    if not quiet:
        print("\n")

    hits, maybe = [], []
    for site in sitelist:
        if site not in results:
            continue
        link, code, size, title, desc, og = results[site]
        if code == 200:
            big = size > (2400 if site in FLAKY else 1200)
            mentions = user.lower() in (title + og).lower()
            if big and (mentions or site not in FLAKY):
                hits.append((site, link, title, desc))
                add("platform", platform=site, handle=user, url=link, title=title, desc=desc,
                    conf=0.85 if mentions else 0.7)
            elif big:
                maybe.append((site, link, title))
                add("platform_maybe", platform=site, handle=user, url=link, title=title, conf=0.4)
        elif code in (403, 429):
            maybe.append((site, link, ""))

    if not quiet:
        if hits:
            print(f"  {G}FOUND ({len(hits)}):{R}")
            for site, link, title, desc in hits:
                t = f" {D}- {title[:60]}{R}" if title else ""
                print(f"   {G}●{R} {B}{site}{R}{t}")
                print(f"      {D}{link}{R}")
        else:
            print(f"  {RD}nothing solid{R}")
        if maybe:
            print(f"\n  {Y}uncertain ({len(maybe)}){R} {D}blocked or empty pages{R}")
            for site, link, _ in maybe[:12]:
                print(f"   {Y}?{R} {site:<18} {D}{link}{R}")
            if len(maybe) > 12:
                print(f"   {D}...and {len(maybe)-12} more{R}")
        print(f"\n  {D}done in {time.time()-t0:.1f}s{R}")
    log(f"username {user}: {len(hits)} hits of {total}")
    return hits


def check_username(user, quiet=False):
    return _sweep(SITES, user, quiet)


def quick_sweep(user):
    return _sweep(QUICK, user, quiet=True)


def find_region(iso, sub):
    tbl = REG.get(iso)
    if not tbl:
        return None
    for n in range(5, 0, -1):
        if len(sub) >= n and sub[:n] in tbl:
            return tbl[sub[:n]]
    return None


def find_type(iso, sub):
    for p in FREE.get(iso, "").split():
        if sub.startswith(p):
            return "toll-free"
    for p in PREM.get(iso, "").split():
        if sub.startswith(p):
            return "premium rate"
    for p in MOB.get(iso, "").split():
        if sub.startswith(p):
            return "mobile"
    return None


def find_carrier(iso, sub):
    tbl = CARRIERS.get(iso)
    if not tbl:
        return None
    for name in tbl:
        for p in tbl[name].split():
            if sub.startswith(p):
                return name
    return None


def local_time(tz):
    if " to " in tz:
        return None
    m = re.match(r"UTC([+-])(\d{1,2})(?::(\d{2}))?$", tz)
    if not m:
        return None
    mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
    if m.group(1) == "-":
        mins = -mins
    now = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=mins)
    return now.strftime("%H:%M")


def check_phone(number, quiet=False):
    if not quiet:
        hdr("PHONE ANALYSIS (offline)")
    s = re.sub(r"[xX]\s*\d+$", "", number.strip())
    s = re.sub(r"[\s\-().]", "", s)
    if s.startswith("00"):
        s = s[2:]
    elif s.startswith("011") and len(s) > 11:
        s = s[3:]
    s = s.lstrip("+")

    if not s or not s.isdigit():
        print(f"{RD}✗ not a phone number{R}")
        return None
    if s in EMERGENCY:
        print(f"{Y}⚠ {s} is an emergency number - {EMERGENCY[s]}{R}")
        return None
    if len(s) == 11 and s[0] == "1":
        s = s[1:]

    code = None
    for n in (3, 2, 1):
        if s[:n] in DIAL:
            code = s[:n]
            break
    if code is None:
        if len(s) == 10 and s[:3] in NANP_AREA:
            print(f"{Y}! no country code, guessing +1{R}\n")
            code = "1"
        else:
            print(f"{RD}✗ no country code found, try +447911123456 style{R}")
            return None

    sub = s[len(code):]
    country = DIAL[code]
    lo, hi = country[6]
    if code not in ("39", "44") and sub.startswith("0") and len(sub) == hi + 1:
        sub = sub[1:]
    if code == "44" and sub.startswith("0") and len(sub) == 11:
        sub = sub[1:]

    ptype = region = carrier = None
    money = country[4] if code not in ("1", "7") else None
    notes = []

    if code == "1" and len(sub) == 10:
        area = sub[:3]
        if area in ("800", "833", "844", "855", "866", "877", "888"):
            ptype = "toll-free"
        elif area == "900":
            ptype = "premium rate"
        elif area in ("500", "533", "566", "577", "588"):
            ptype = "personal/VoIP"
        else:
            ptype = "geographic"
        state = NANP_AREA.get(area, "unassigned area code")
        metro = NANP_METRO.get(area)
        region = f"{metro} ({state})" if metro else state
        money = "USD" if region.endswith(", USA") else ("CAD" if region.endswith(", Canada") else NANP_MONEY.get(region.split(" (")[0], "varies"))
    elif code == "7":
        if sub.startswith("800"):
            ptype, money = "toll-free", "RUB"
        elif sub[:1] == "9":
            ptype, money = "mobile", "RUB"
            carrier = find_carrier("RU", sub)
        elif sub[:1] == "7":
            money = "KZT"
            ptype = "mobile" if len(sub) > 1 and sub[1] in "04567" else "landline"
            region = find_region("KZ", sub)
        else:
            ptype, money = "landline", "RUB"
            region = find_region("RU", sub)
    elif code == "44":
        terr = next((UK_TERR[p] for p in UK_TERR if sub.startswith(p)), None)
        if terr:
            region = terr
            ptype = "mobile" if "mobile" in terr else "landline"
        elif sub[:2] in ("74", "75", "76", "77", "78", "79"):
            ptype = "mobile"
        elif sub[:2] == "70":
            ptype = "personal follow-me"
        elif sub[:2] == "80":
            ptype = "freephone"
        elif sub[:2] in ("84", "87"):
            ptype = "revenue share"
        elif sub[:2] in ("90", "91"):
            ptype = "premium rate"
        else:
            ptype = "landline"
            region = find_region("GB", sub)
    else:
        iso = country[1]
        if iso == "BR":
            region = find_region("BR", sub)
            ptype = "mobile" if len(sub) == 11 and sub[2] == "9" else ("landline" if len(sub) == 10 else None)
        elif iso == "AR":
            ptype = "mobile" if sub[:1] == "9" else "landline"
            region = find_region("AR", sub[1:] if sub[:1] == "9" else sub)
        else:
            ptype = find_type(iso, sub)
            if ptype is None:
                region = find_region(iso, sub)
                if region:
                    ptype = "landline (probably)"
            elif ptype == "mobile":
                carrier = find_carrier(iso, sub)
            else:
                region = find_region(iso, sub)
        if iso in NOTES:
            notes.append(NOTES[iso])

    if carrier:
        notes.append(f"carrier historically {carrier}, mnp exists")

    out = {"input": number, "country": country[0], "iso": country[1], "continent": country[2],
           "capital": country[3], "tz": country[5], "type": ptype, "region": region,
           "currency": money, "digits": len(sub), "e164": f"+{code}{sub}",
           "notes": notes, "carrier": carrier}

    if not quiet:
        print(f"  {C}Country     {R}: {country[0]} [{country[1]}]")
        print(f"  {C}Continent   {R}: {country[2]}")
        print(f"  {C}Capital     {R}: {country[3]}")
        lt = local_time(country[5])
        print(f"  {C}Timezone    {R}: {country[5]}" + (f"  {D}(~{lt} there now){R}" if lt else ""))
        if ptype:
            print(f"  {C}Line type   {R}: {ptype}")
        if region:
            print(f"  {C}Region      {R}: {region}")
        if money:
            print(f"  {C}Currency    {R}: {money}")
        if code == "1" and len(sub) == 10:
            print(f"  {C}Formatted   {R}: ({sub[:3]}) {sub[3:6]}-{sub[6:]}")
        ok = lo <= len(sub) <= hi
        print(f"  {C}Digits      {R}: {len(sub)} (typical {lo}-{hi}) " + (f"{G}✓{R}" if ok else f"{RD}✗ off{R}"))
        print(f"  {C}E.164       {R}: +{code}{sub}")
        for nt in notes:
            print(f"  {D}note: {nt}{R}")
        print(f"\n{D}  owner lookup by hand: truecaller.com/search/global/{code}{sub}{R}")
    add("phone", **out)
    log(f"phone {number} -> {country[0]} {ptype} {region}")
    return out


def email_recon(addr, quiet=False):
    if not quiet:
        hdr("EMAIL RECON")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", addr):
        print(f"{RD}✗ not an email{R}")
        return None

    local, _, dom = addr.partition("@")
    out = {"email": addr, "local": local, "domain": dom,
           "throwaway": dom.lower() in THROWAWAY, "gravatar": None,
           "smtp": False, "domain_ip": None}

    if not quiet:
        print(f"  {C}Local       {R}: {local}")
        print(f"  {C}Domain      {R}: {dom}")
        if out["throwaway"]:
            print(f"  {Y}! throwaway domain{R}")

    try:
        h = hashlib.md5(addr.lower().strip().encode()).hexdigest()
        r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404", timeout=8)
        if r.status_code == 200:
            out["gravatar"] = {"hash": h, "avatar": f"https://www.gravatar.com/avatar/{h}"}
            if not quiet:
                print(f"  {G}● gravatar exists{R} {D}(email used publicly somewhere){R}")
            try:
                p = requests.get(f"https://gravatar.com/{h}.json", timeout=8).json()
                ent = p.get("entry", [{}])[0]
                if ent.get("displayName"):
                    out["gravatar"]["name"] = ent.get("displayName")
                if ent.get("aboutMe"):
                    out["gravatar"]["bio"] = str(ent.get("aboutMe"))[:300]
                if ent.get("profileUrl"):
                    out["gravatar"]["url"] = ent.get("profileUrl")
                accs = (ent.get("accounts") or [])[:6]
                out["gravatar"]["accounts"] = [{"service": a.get("shortname"), "url": a.get("url")} for a in accs]
                if not quiet and out["gravatar"].get("name"):
                    print(f"  {C}Display name {R}: {out['gravatar']['name']}")
                    if out["gravatar"].get("bio"):
                        print(f"  {C}Bio         {R}: {out['gravatar']['bio'][:80]}")
                    for a in accs[:5]:
                        print(f"  {C}Linked acct {R}: {a.get('shortname')} -> {a.get('url')}")
            except Exception:
                pass
        elif not quiet:
            print(f"  {D}○ no gravatar{R}")
    except Exception:
        if not quiet:
            print(f"  {D}○ gravatar check failed{R}")

    try:
        ip = socket.gethostbyname(dom)
        out["domain_ip"] = ip
        if not quiet:
            print(f"  {G}● domain resolves{R} -> {ip}")
    except Exception:
        if not quiet:
            print(f"  {RD}✗ domain dead, email probably fake{R}")

    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(3)
        rc = sk.connect_ex((dom, 25))
        sk.close()
        out["smtp"] = (rc == 0)
        if not quiet:
            print(f"  {G}● smtp open{R}" if rc == 0 else f"  {D}○ smtp closed/filtered{R}")
    except Exception:
        pass

    add("email", **out)
    log(f"email {addr} gravatar={bool(out['gravatar'])}")
    return out


def gh_recon(user, quiet=False):
    if not quiet:
        hdr("GITHUB RECON")
    try:
        r = requests.get(f"https://api.github.com/users/{user}", headers={"User-Agent": UA}, timeout=8)
    except Exception:
        print(f"{RD}✗ github unreachable{R}")
        return None
    if r.status_code == 404:
        if not quiet:
            print(f"{RD}✗ no such user{R}")
        return None
    if r.status_code == 403:
        if not quiet:
            print(f"{Y}! rate limited (60/hr per ip){R}")
        return None
    if r.status_code != 200:
        return None

    d = r.json()
    out = {"login": d.get("login"), "name": d.get("name"), "bio": d.get("bio"),
           "company": d.get("company"), "location": d.get("location"), "email": d.get("email"),
           "blog": d.get("blog"), "twitter": d.get("twitter_username"),
           "repos": d.get("public_repos"), "followers": d.get("followers"),
           "created": d.get("created_at"), "url": d.get("html_url"), "recent": []}

    if not quiet:
        for k, lb in (("login", "Login"), ("name", "Name"), ("bio", "Bio"), ("company", "Company"),
                      ("location", "Location"), ("email", "Email"), ("blog", "Blog"), ("twitter", "Twitter"),
                      ("followers", "Followers"), ("created", "Joined")):
            if out.get(k):
                print(f"  {C}{lb:<11}{R}: {out[k]}")
        print(f"  {C}Profile     {R}: {out['url']}")

    try:
        rr = requests.get(f"https://api.github.com/users/{user}/repos?sort=updated&per_page=5",
                          headers={"User-Agent": UA}, timeout=8)
        for repo in rr.json()[:5]:
            out["recent"].append({"name": repo.get("name"), "lang": repo.get("language"),
                                  "stars": repo.get("stargazers_count"), "desc": repo.get("description")})
        if not quiet and out["recent"]:
            print(f"\n  {C}recent repos{R}")
            for rp in out["recent"]:
                print(f"   {G}●{R} {rp['name']:<22} {D}★{rp['stars']} {rp['lang'] or ''}{R}")
    except Exception:
        pass

    add("github", **out)
    log(f"github {user}: {out.get('followers')} followers")
    return out


def check_ip(ip_addr, quiet=False):
    if not quiet:
        hdr("IP INTEL")
    try:
        ip_addr = socket.gethostbyname(ip_addr)
    except Exception:
        pass
    try:
        d = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=6).json()
    except Exception:
        print(f"{RD}✗ ip-api unreachable{R}")
        return None
    if d.get("status") != "success":
        print(f"{RD}✗ {d.get('message', 'failed')}{R}")
        return None
    out = {"ip": d.get("query"), "country": d.get("country"), "cc": d.get("countryCode"),
           "region": d.get("regionName"), "city": d.get("city"), "zip": d.get("zip"),
           "tz": d.get("timezone"), "isp": d.get("isp"), "org": d.get("org"), "as": d.get("as"),
           "lat": d.get("lat"), "lon": d.get("lon")}
    if not quiet:
        for k in ("ip", "country", "region", "city", "tz", "isp", "org", "as"):
            if out.get(k):
                print(f"  {C}{k:<11}{R}: {out[k]}")
        if out["lat"] and out["lon"]:
            print(f"  {C}Map        {R}: {D}https://maps.google.com/?q={out['lat']},{out['lon']}{R}")
        try:
            print(f"  {C}PTR         {R}: {socket.gethostbyaddr(out['ip'])[0]}")
        except Exception:
            pass
    add("ip", **out)
    log(f"ip {ip_addr}: {out['country']} {out['city']}")
    return out


def check_domain(dom, quiet=False):
    if not quiet:
        hdr("DOMAIN")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$", dom):
        print(f"{RD}✗ not a domain{R}")
        return None
    try:
        _, _, addrs = socket.gethostbyname_ex(dom)
    except Exception:
        print(f"{RD}✗ does not resolve{R}")
        return None
    out = {"domain": dom, "ips": addrs, "ptrs": [], "ipv6": None, "web": None}
    for a in addrs:
        try:
            out["ptrs"].append(socket.gethostbyaddr(a)[0])
        except Exception:
            pass
    try:
        out["ipv6"] = socket.getaddrinfo(dom, None, socket.AF_INET6)[0][4][0]
    except Exception:
        pass
    for proto in ("https", "http"):
        try:
            r = requests.get(f"{proto}://{dom}", timeout=6, headers={"User-Agent": UA})
            out["web"] = {"proto": proto, "status": r.status_code}
            break
        except Exception:
            continue
    if not quiet:
        print(f"  {G}● resolves{R}")
        for a in addrs:
            print(f"  {C}A           {R}: {a}")
        for p in out["ptrs"]:
            print(f"  {C}PTR         {R}: {p}")
        if out["ipv6"]:
            print(f"  {C}AAAA        {R}: {out['ipv6']}")
        if out["web"]:
            print(f"  {C}Web         {R}: {out['web']['proto']} up (status {out['web']['status']})")
    add("domain", **out)
    log(f"domain {dom} -> {addrs}")
    return out


def do_whois(dom, quiet=False):
    if not quiet:
        hdr("WHOIS")
    tld = dom.split(".")[-1].lower()
    server = WHOIS_SRV.get(tld, "whois.iana.org")
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(10)
        sk.connect((server, 43))
        sk.sendall((dom + "\r\n").encode())
    except Exception:
        print(f"{RD}✗ couldnt reach {server}{R}")
        return None
    raw = b""
    try:
        while True:
            ch = sk.recv(4096)
            if not ch:
                break
            raw += ch
    except socket.timeout:
        pass
    finally:
        sk.close()
    if not raw:
        print(f"{RD}✗ empty response{R}")
        return None
    text = raw.decode("utf-8", errors="ignore")
    keep = ("Domain Name", "Registrar", "Creation Date", "Updated Date", "Registry Expiry",
            "Registrant", "Name Server", "Domain Status", "Registrant Country")
    lines = [l.strip() for l in text.splitlines() if l.strip() and any(k in l for k in keep)][:25]
    out = {"domain": dom, "server": server, "lines": lines,
           "created": next((l.split(":", 1)[1].strip() for l in lines if "Creation Date" in l), None),
           "registrar": next((l.split(":", 1)[1].strip() for l in lines if "Registrar:" in l), None)}
    if not quiet:
        for l in lines:
            print(f"  {l}")
        if not lines:
            print(f"{D}nothing parsed, run 'whois {dom}' yourself{R}")
    add("whois", **out)
    log(f"whois {dom}")
    return out


def _resolve(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def dnsrecon(dom, quiet=False):
    if not quiet:
        hdr("DNS RECON")
    try:
        _, _, addrs = socket.gethostbyname_ex(dom)
    except Exception:
        print(f"{RD}✗ dead domain{R}")
        return None
    if not quiet:
        print(f"  {C}A records   {R}: {', '.join(addrs)}\n")
        print(f"  {C}subdomain sweep ({len(SUBS)} words){R}")
    found = {}
    with ThreadPoolExecutor(max_workers=25) as ex:
        for host, ip in ex.map(_resolve, [f"{s}.{dom}" for s in SUBS]):
            if ip:
                found[host] = ip
                if not quiet:
                    print(f"   {G}●{R} {host:<34} {ip}")
    if not found and not quiet:
        print(f"   {D}(none answered){R}")
    add("dns", domain=dom, ips=addrs, subdomains=found)
    log(f"dns {dom}: {len(found)} subs")
    return {"domain": dom, "ips": addrs, "subs": found}


def wayback(url, quiet=False):
    if not url.startswith("http"):
        url = "https://" + url
    if not quiet:
        hdr("WAYBACK")
    try:
        r = requests.get("https://archive.org/wayback/available", params={"url": url}, timeout=8)
        snap = r.json().get("archived_snapshots", {}).get("closest")
    except Exception:
        print(f"{RD}✗ archive.org unreachable{R}")
        return None
    if not snap:
        if not quiet:
            print(f"{D}○ no snapshots{R}")
        return None
    out = {"url": url, "snap": snap.get("url"), "ts": snap.get("timestamp"), "status": snap.get("status")}
    if not quiet:
        print(f"  {G}● snapshot{R}\n  {C}URL       {R}: {out['snap']}\n  {C}Timestamp {R}: {out['ts']}")
    add("wayback", **out)
    return out


def check_headers(url, quiet=False):
    if not url.startswith("http"):
        url = "https://" + url
    if not quiet:
        hdr("HTTP HEADERS")
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": UA})
    except Exception:
        print(f"{RD}✗ couldnt connect{R}")
        return None
    security = ("strict-transport-security", "content-security-policy", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy")
    out = {"url": url, "status": r.status_code, "final": r.url, "security": {}, "tech": {}}
    for h in security:
        out["security"][h] = r.headers.get(h)
    for h in ("server", "x-powered-by", "via", "x-cache", "x-generator"):
        out["tech"][h] = r.headers.get(h)
    if not quiet:
        print(f"  {C}Status      {R}: {r.status_code}\n\n  {C}security{R}")
        for h in security:
            v = r.headers.get(h)
            print(f"   {G}●{R} {h}: {v[:60]}" if v else f"   {RD}✗{R} {h}: {D}missing{R}")
        print(f"\n  {C}tech{R}")
        for h in ("server", "x-powered-by", "via", "x-cache"):
            v = r.headers.get(h)
            if v:
                print(f"   {Y}·{R} {h}: {v[:60]}")
    add("headers", **out)
    return out


def _portchk(args):
    ip, p = args
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(1.5)
        if sk.connect_ex((ip, p)) == 0:
            banner = ""
            try:
                if p in (80, 8080):
                    sk.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sk.recv(128)
                banner = data.decode(errors="ignore").split("\r\n")[0].strip()[:60]
            except Exception:
                pass
            sk.close()
            return p, True, banner
        sk.close()
    except Exception:
        pass
    return p, False, ""


def portscan(ip, quiet=False):
    if not quiet:
        hdr("PORT SCAN")
    try:
        ip = socket.gethostbyname(ip)
    except Exception:
        print(f"{RD}✗ cant resolve{R}")
        return None
    if not quiet:
        print(f"  {D}scanning {ip}...{R}\n")
    open_ports = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        for p, ok, banner in ex.map(_portchk, [(ip, p) for p in PORTS]):
            if ok:
                open_ports.append({"port": p, "svc": PORTS[p], "banner": banner})
                if not quiet:
                    b = f"  {D}{banner}{R}" if banner else ""
                    print(f"   {G}●{R} {p}/tcp {B}{PORTS[p]:<10}{R}{b}")
    if not open_ports and not quiet:
        print(f"   {RD}nothing open{R}")
    if not quiet:
        print(f"\n  {D}{len(PORTS)} scanned, {len(open_ports)} open{R}")
    add("ports", host=ip, open=open_ports)
    log(f"portscan {ip}: {[p['port'] for p in open_ports]}")
    return open_ports


def check_mac(mac_addr, quiet=False):
    if not quiet:
        hdr("MAC VENDOR")
    mac_addr = mac_addr.strip().replace("-", ":").upper()
    if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac_addr):
        print(f"{RD}✗ bad mac{R}")
        return None
    try:
        r = requests.get(f"https://api.macvendors.com/{mac_addr}", timeout=6)
        v = r.text.strip() if r.status_code == 200 else None
    except Exception:
        v = None
    if not quiet:
        print(f"  {C}OUI     {R}: {mac_addr[:8]}")
        print(f"  {C}Vendor  {R}: {G}{v}{R}" if v else f"  {D}no vendor found{R}")
    add("mac", mac=mac_addr, vendor=v)
    return v


def dorks(target, quiet=False):
    if not quiet:
        hdr("DORK LINKS")
    q = quote(f'"{target}"')
    gh = target.split("@")[0] if "@" in target else target
    links = [
        ("google exact", f"https://www.google.com/search?q={q}"),
        ("socials", f"https://www.google.com/search?q={q}+site:instagram.com+OR+site:tiktok.com+OR+site:x.com"),
        ("pastebin", f"https://www.google.com/search?q={q}+site:pastebin.com"),
        ("github users", f"https://github.com/search?q={gh}&type=users"),
        ("github code", f"https://github.com/search?q=%22{quote(gh)}%22&type=code"),
        ("reddit", f"https://www.reddit.com/search/?q=%22{quote(gh)}%22"),
        ("telegram", f"https://t.me/s/{gh}"),
        ("images", f"https://www.google.com/search?q={q}&tbm=isch"),
        ("whatsmyname", f"https://whatsmyname.app/?q={quote(gh)}"),
    ]
    if not quiet:
        for name, url in links:
            print(f"   {C}{name:<14}{R} {D}{url}{R}")
    add("dorks", target=target, links=links)
    return links


# ── analysis ───────────────────────────────────────────────────

class DSU:
    def __init__(self, n):
        self.p = list(range(n))
    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def collect_profiles():
    profs = []
    for f in FINDINGS:
        k = f["kind"]
        if k == "platform":
            profs.append({"platform": f["platform"], "handle": f["handle"], "url": f["url"],
                          "title": f.get("title") or "", "bio": f.get("desc") or "", "source": "sweep"})
        elif k == "github" and f.get("login"):
            profs.append({"platform": "GitHub", "handle": f["login"], "url": f.get("url") or "",
                          "title": f.get("name") or "", "bio": f.get("bio") or "",
                          "location": f.get("location"), "company": f.get("company"),
                          "email": f.get("email"), "blog": f.get("blog"),
                          "twitter": f.get("twitter"), "joined": f.get("created"),
                          "source": "github-api"})
        elif k == "email" and f.get("gravatar"):
            gv = f["gravatar"]
            profs.append({"platform": "Gravatar", "handle": f["local"],
                          "url": gv.get("url") or gv.get("avatar") or "",
                          "title": gv.get("name") or "", "bio": gv.get("bio") or "",
                          "accounts": gv.get("accounts") or [], "email": f["email"],
                          "source": "gravatar"})
    return profs


def _norm_url(u):
    return (u or "").split("//")[-1].rstrip("/").lower()


def link_profiles(profs):
    edges, evidence = [], []
    n = len(profs)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = profs[i], profs[j]
            ev = []

            for key in ("url", "blog", "twitter"):
                va, vb = a.get(key), b.get(key)
                if va and vb and _norm_url(va) == _norm_url(vb):
                    ev.append(("bio_crosslink", 1.0))
                    break

            accs_a = {_norm_url(x.get("url")) for x in a.get("accounts", []) if x.get("url")}
            accs_b = {_norm_url(x.get("url")) for x in b.get("accounts", []) if x.get("url")}
            if (_norm_url(b.get("url")) and _norm_url(b.get("url")) in accs_a) or \
               (_norm_url(a.get("url")) and _norm_url(a.get("url")) in accs_b):
                ev.append(("bio_crosslink", 0.9))

            rel, strength = handle_relation(a.get("handle"), b.get("handle"))
            if rel == "identical":
                ev.append(("handle_match", 1.0))
            elif rel:
                ev.append(("handle_variant", strength))

            nm = name_match(a.get("title") or "", b.get("title") or "")
            if nm > 0.85:
                ev.append(("full_name_match", nm))
            elif nm > 0.65:
                ev.append(("name_partial", nm))

            la, lb = (a.get("location") or ""), (b.get("location") or "")
            if la and lb and jaro_winkler(la, lb) > 0.85:
                ev.append(("location_match", 0.8))

            if a.get("email") and b.get("email") and a["email"] == b["email"]:
                ev.append(("email_on_profile", 1.0))

            if ev:
                edges.append((i, j))
                evidence.append((i, j, ev))
    return edges, evidence


def cluster_profiles(profs, edges):
    dsu = DSU(len(profs))
    for i, j in edges:
        dsu.union(i, j)
    groups = {}
    for i in range(len(profs)):
        groups.setdefault(dsu.find(i), []).append(i)
    return sorted(groups.values(), key=len, reverse=True)


def profile_interests(profs):
    docs = [tokenize(p.get("bio") or "") for p in profs]
    docs = [d for d in docs if d]
    if not docs:
        return {}, {}
    scores, keywords = {}, {}
    for label, bucket in INTERESTS.items():
        hits = []
        for doc in docs:
            hits += [t for t in doc if t in bucket]
        if hits:
            scores[label] = len(hits)
            keywords[label] = list(dict.fromkeys(hits))[:8]
    top = dict(sorted(scores.items(), key=lambda x: -x[1])[:6])
    return top, {k: v for k, v in keywords.items() if k in top}


def bio_similarity_matrix(profs):
    docs = [tokenize(p.get("bio") or "") for p in profs]
    if len(docs) < 2:
        return []
    idf = build_idf(docs)
    vecs = [tfidf_vector(d, idf) for d in docs]
    sims = []
    for i in range(len(vecs)):
        for j in range(i + 1, len(vecs)):
            if docs[i] and docs[j]:
                c = cosine(vecs[i], vecs[j])
                if c > 0.25:
                    sims.append((i, j, c))
    return sims


def geo_triangulate(profs, phone_data, ip_data):
    votes = {}
    def vote(place, w):
        if place:
            votes[place.strip()] = votes.get(place.strip(), 0) + w
    for p in profs:
        vote(p.get("location"), 2.0)
    if phone_data:
        vote(phone_data.get("country"), 1.5)
        vote(phone_data.get("region"), 2.5)
    if ip_data:
        vote(ip_data.get("city"), 1.0)
        vote(ip_data.get("country"), 0.8)
    return sorted(votes.items(), key=lambda x: -x[1])[:6]


def build_timeline():
    events = []
    for f in FINDINGS:
        k = f["kind"]
        if k == "github" and f.get("created"):
            try:
                dt = datetime.strptime(f["created"][:10], "%Y-%m-%d")
                events.append((dt, f"GitHub account created ({f.get('login')})", "github"))
            except Exception:
                pass
        if k == "whois" and f.get("created"):
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%d-%b-%Y", "%Y.%m.%d", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(f["created"].split(" ")[0], fmt)
                    events.append((dt, f"Domain {f['domain']} registered", "whois"))
                    break
                except Exception:
                    continue
        if k == "wayback" and f.get("ts"):
            try:
                dt = datetime.strptime(f["ts"][:8], "%Y%m%d")
                events.append((dt, f"Wayback snapshot of {f['url'].split('//')[-1][:40]}", "archive"))
            except Exception:
                pass
    events.sort(key=lambda x: x[0])
    return events


def analyze(seed, phone_data=None, ip_data=None):
    profs = collect_profiles()
    edges, evidence = link_profiles(profs)
    clusters = cluster_profiles(profs, edges)
    interests, keywords = profile_interests(profs)
    biosim = bio_similarity_matrix(profs)
    geo = geo_triangulate(profs, phone_data, ip_data)
    timeline = build_timeline()

    for i, j, c in biosim:
        evidence.append((i, j, [("style_match", c)]))

    primary = []
    if clusters:
        primary = [profs[i] for i in clusters[0]]
    if len(primary) == 1 and primary[0]["source"] == "sweep":
        for cl in clusters[1:]:
            for i in cl:
                if profs[i]["source"] != "sweep":
                    primary = [profs[i]]
                    break
            else:
                continue
            break

    idx = {id(p) for p in primary}
    pidx = {i for i, p in enumerate(profs) if id(p) in idx}
    ev_list = []
    for i, j, ev in evidence:
        if i in pidx and j in pidx:
            ev_list.extend(ev)
    conf = score_identity(ev_list) if ev_list else (0.55 if len(primary) >= 2 else 0.3)

    names, handles = {}, {}
    for p in profs:
        if p.get("title"):
            names[p["title"]] = names.get(p["title"], 0) + 1
        handles[p["handle"]] = handles.get(p["handle"], 0) + 1
    real_name = max(names.items(), key=lambda x: x[1])[0] if names else None
    main_handle = max(handles.items(), key=lambda x: x[1])[0] if handles else seed

    return {"seed": seed, "profiles": profs, "edges": edges, "evidence": evidence,
            "clusters": clusters, "primary": primary, "confidence": conf,
            "interests": interests, "keywords": keywords, "geo": geo,
            "timeline": timeline, "real_name": real_name, "main_handle": main_handle,
            "biosim": biosim, "phone": phone_data, "ip": ip_data}


def narrate(an):
    s = []
    seed, conf = an["seed"], an["confidence"]
    label, _ = conf_label(conf)
    n_prof = len(an["profiles"])
    n_primary = len(an["primary"])

    if n_primary >= 3:
        s.append(f"The evidence ties {n_primary} of the {n_prof} profiles found into a single identity "
                 f"centered on the handle \"{an['main_handle']}\".")
    elif n_primary == 2:
        s.append(f"Two profiles appear to belong to the same person, both tied to \"{an['main_handle']}\".")
    elif n_primary == 1:
        p = an["primary"][0]
        s.append(f"One confirmed profile surfaced: {p['platform']} ({p['handle']}).")
    else:
        s.append("No confirmed public profiles were found for this target.")

    s.append(f"Identity confidence is {label} ({conf*100:.0f}%), based on {len(an['evidence'])} "
             f"correlation signal(s) across name, handle, bio and location matching.")

    if an["real_name"]:
        s.append(f"The name \"{an['real_name']}\" appeared consistently across sources and is the best "
                 f"candidate for the subject's real name.")

    if an["interests"]:
        top = list(an["interests"])[:3]
        kw = ", ".join(an["keywords"].get(top[0], [])[:5])
        line = f"Interest profiling of available bio text points to {', '.join(top)}."
        if kw:
            line += f" The strongest markers were: {kw}."
        s.append(line)

    if an["geo"]:
        top_place = an["geo"][0]
        others = [g[0] for g in an["geo"][1:3]]
        line = f"Geographic signals converge on {top_place[0]} ({top_place[1]:.1f} vote-weighted points)"
        if others:
            line += f", with weaker traces in {', '.join(others)}"
        s.append(line + ".")

    if an["timeline"]:
        first, last = an["timeline"][0], an["timeline"][-1]
        span = (last[0] - first[0]).days
        s.append(f"The oldest datable event is {first[0].strftime('%B %Y')} ({first[1]}), spanning "
                 f"{span} days of recorded activity up to {last[0].strftime('%B %Y')}.")
        ages = sorted({(datetime.now() - e[0]).days // 365 for e in an["timeline"]})
        if ages and ages[0] >= 5:
            s.append(f"The primary accounts are at least {ages[0]} years old, which usually indicates "
                     f"an established identity rather than a throwaway.")

    if an["phone"]:
        ph = an["phone"]
        bit = f"a {ph.get('type') or 'unclassified'} line in {ph.get('country')}"
        if ph.get("region"):
            bit += f" ({ph['region']})"
        s.append(f"The phone number analyzed is {bit}.")

    opsec = []
    for f in FINDINGS:
        if f["kind"] == "email":
            if f.get("gravatar"):
                opsec.append("the email has a public gravatar attached, meaning it was used to sign up "
                             "for publicly visible services at some point")
            if f.get("throwaway"):
                opsec.append("the email domain is a known throwaway provider, suggesting deliberate anonymity")
    if len(an["profiles"]) > 8:
        opsec.append(f"the same handle appears on {len(an['profiles'])} platforms - high footprint, easy to track")
    if opsec:
        s.append("OPSEC observations: " + "; ".join(opsec) + ".")
    return " ".join(s)


# ── report ─────────────────────────────────────────────────────

REPORT_CSS = """
:root{--bg:#0b0e14;--card:#131824;--card2:#0f1420;--line:#232b3b;--tx:#dbe2f0;--dim:#7a869e;
--acc:#22d3ee;--grn:#22c55e;--ylw:#eab308;--red:#ef4444;--mag:#c084fc}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--tx);font:15px/1.65 -apple-system,'Segoe UI',Roboto,sans-serif;padding:0 0 80px}
.wrap{max-width:1000px;margin:0 auto;padding:0 24px}
header{padding:56px 0 36px;border-bottom:1px solid var(--line);background:linear-gradient(160deg,#0b0e14 60%,#101726)}
h1{font-size:34px;letter-spacing:-.5px;font-weight:800}
h1 span{color:var(--acc)}
.sub{color:var(--dim);margin-top:8px;font-size:14px}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700;margin:4px 6px 0 0}
h2{font-size:20px;margin:48px 0 16px;padding-bottom:10px;border-bottom:1px solid var(--line);letter-spacing:-.2px}
h2 .n{color:var(--acc);font-family:ui-monospace,monospace;margin-right:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:14px}
.kv b{color:var(--dim);font-weight:500}
.kv span{word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{color:var(--dim);text-align:left;font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:9px 10px;border-bottom:1px solid var(--card2);vertical-align:top}
tr:hover td{background:#161d2e}
a{color:var(--acc);text-decoration:none}
a:hover{text-decoration:underline}
.tag{display:inline-block;background:#1a2334;color:var(--acc);border-radius:5px;padding:1px 8px;font-size:11.5px;font-family:ui-monospace,monospace;margin:2px 4px 2px 0}
.tag.g{color:var(--grn);background:#12241a}.tag.y{color:var(--ylw);background:#27200d}.tag.r{color:var(--red);background:#2a1414}
.narr{font-size:15.5px;line-height:1.8;color:#c6d0e4}
details{background:var(--card2);border:1px solid var(--line);border-radius:10px;margin:10px 0}
summary{cursor:pointer;padding:12px 16px;font-weight:600;font-size:13.5px;color:var(--dim)}
details[open] summary{border-bottom:1px solid var(--line);color:var(--tx)}
.dbody{padding:12px 16px}
.mono{font-family:ui-monospace,'Cascadia Code',monospace;font-size:12.5px}
footer{margin-top:60px;color:var(--dim);font-size:12px;text-align:center;border-top:1px solid var(--line);padding-top:24px}
.big{font-size:44px;font-weight:800;letter-spacing:-1px}
.stat{text-align:center;padding:22px 10px}
.stat .lab{color:var(--dim);font-size:11.5px;text-transform:uppercase;letter-spacing:1px;margin-top:6px}
.filter{width:100%;background:var(--card2);border:1px solid var(--line);color:var(--tx);padding:10px 14px;border-radius:8px;font-size:14px;margin-bottom:12px;outline:none}
.filter:focus{border-color:var(--acc)}
@media print{body{background:#fff;color:#111}.card,details{border-color:#ccc;background:#fff}}
"""

REPORT_JS = """
function flt(){
  var q=document.getElementById('fq').value.toLowerCase();
  document.querySelectorAll('#ftable tbody tr').forEach(function(r){
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
function copyAll(){
  var t=[];
  document.querySelectorAll('#ftable tbody tr').forEach(function(r){
    if(r.style.display!=='none'){var a=r.querySelector('a');if(a)t.push(a.href);}
  });
  navigator.clipboard.writeText(t.join('\\n')).then(function(){alert(t.length+' links copied');});
}
"""


def svg_radar(pairs, size=300):
    if not pairs:
        return "<div class='kv'><b>no interest data</b></div>"
    cx = cy = size / 2
    rmax = size / 2 - 48
    n = len(pairs)
    rings, pts, labels = [], [], []
    for ring in (0.33, 0.66, 1.0):
        rp = []
        for i in range(n):
            ang = -math.pi / 2 + 2 * math.pi * i / n
            rp.append(f"{cx + rmax*ring*math.cos(ang):.1f},{cy + rmax*ring*math.sin(ang):.1f}")
        rings.append(f"<polygon points='{' '.join(rp)}' fill='none' stroke='#232b3b'/>")
    maxv = max(v for _, v in pairs) or 1
    for i, (lab, val) in enumerate(pairs):
        ang = -math.pi / 2 + 2 * math.pi * i / n
        rr = rmax * (val / maxv)
        pts.append(f"{cx + rr*math.cos(ang):.1f},{cy + rr*math.sin(ang):.1f}")
        lx = cx + (rmax + 22) * math.cos(ang)
        ly = cy + (rmax + 22) * math.sin(ang)
        anchor = "middle"
        if math.cos(ang) > 0.3:
            anchor = "start"
        elif math.cos(ang) < -0.3:
            anchor = "end"
        labels.append(f"<text x='{lx:.1f}' y='{ly:.1f}' fill='#7a869e' font-size='10.5' "
                      f"text-anchor='{anchor}' dominant-baseline='middle'>{esc(lab)}</text>")
    poly = " ".join(pts)
    return (f"<svg viewBox='0 0 {size} {size}' style='width:100%;max-width:{size}px;display:block;margin:auto'>"
            + " ".join(rings)
            + f"<polygon points='{poly}' fill='rgba(34,211,238,.18)' stroke='#22d3ee' stroke-width='2'/>"
            + "".join(f"<circle cx='{p.split(',')[0]}' cy='{p.split(',')[1]}' r='3' fill='#22d3ee'/>" for p in pts)
            + "".join(labels) + "</svg>")


def svg_bars(items, w=560):
    if not items:
        return "<div class='kv'><b>no data</b></div>"
    bh, gap, left = 26, 9, 170
    h = len(items) * (bh + gap) + gap
    rows = []
    for i, (lab, val, col) in enumerate(items):
        y = gap + i * (bh + gap)
        bw = max(3, (w - left - 46) * max(0, min(1, val)))
        rows.append(f"<text x='{left-10}' y='{y+bh*0.72}' fill='#7a869e' font-size='11.5' "
                    f"text-anchor='end'>{esc(lab[:24])}</text>"
                    f"<rect x='{left}' y='{y}' width='{w-left-30}' height='{bh}' rx='4' fill='#131824'/>"
                    f"<rect x='{left}' y='{y}' width='{bw:.0f}' height='{bh}' rx='4' fill='{col}'/>"
                    f"<text x='{left+bw+8:.0f}' y='{y+bh*0.72}' fill='#dbe2f0' font-size='11' "
                    f"font-family='monospace'>{val*100:.0f}%</text>")
    return f"<svg viewBox='0 0 {w} {h}' style='width:100%'>" + "".join(rows) + "</svg>"


def svg_timeline(events, w=860):
    if not events:
        return "<div class='kv'><b>no datable events</b></div>"
    h = max(150, len(events) * 30 + 30)
    d0 = events[0][0] - timedelta(days=30)
    d1 = events[-1][0] + timedelta(days=30)
    span = max((d1 - d0).days, 1)
    y0 = h - 46
    out = [f"<line x1='20' y1='{y0}' x2='{w-20}' y2='{y0}' stroke='#232b3b' stroke-width='2'/>"]
    for i, (dt, label, src) in enumerate(events):
        x = 20 + (w - 40) * ((dt - d0).days / span)
        yy = 20 + i * 30
        col = {"github": "#22d3ee", "whois": "#c084fc", "archive": "#22c55e"}.get(src, "#eab308")
        out.append(f"<circle cx='{x:.1f}' cy='{y0}' r='5' fill='{col}'/>"
                   f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{yy+6}' stroke='{col}' stroke-opacity='.35'/>"
                   f"<text x='{x:.1f}' y='{yy}' fill='#c6d0e4' font-size='10.5' text-anchor='middle'>"
                   f"{esc(dt.strftime('%Y'))} · {esc(label[:52])}</text>")
    return f"<svg viewBox='0 0 {w} {h}' style='width:100%'>{''.join(out)}</svg>"


def svg_graph(profs, edges, w=520):
    if not profs:
        return ""
    n = len(profs)
    h = w
    cx, cy, r = w / 2, h / 2, min(w, h) / 2 - 60
    pos = []
    for i in range(n):
        ang = -math.pi / 2 + 2 * math.pi * i / n
        pos.append((cx + r * math.cos(ang), cy + r * math.sin(ang)))
    out = []
    for i, j in edges:
        x1, y1 = pos[i]
        x2, y2 = pos[j]
        out.append(f"<line x1='{x1:.0f}' y1='{y1:.0f}' x2='{x2:.0f}' y2='{y2:.0f}' "
                   f"stroke='#22c55e' stroke-opacity='.4' stroke-width='1.5'/>")
    for i, p in enumerate(profs):
        x, y = pos[i]
        out.append(f"<circle cx='{x:.0f}' cy='{y:.0f}' r='6' fill='#22d3ee'/>"
                   f"<text x='{x:.0f}' y='{y-13:.0f}' fill='#dbe2f0' font-size='10' "
                   f"text-anchor='middle'>{esc(p['platform'][:14])}</text>")
    return (f"<svg viewBox='0 0 {w} {h}' style='width:100%;max-width:{w}px;display:block;margin:auto'>"
            + "".join(out) + "</svg>")


def report_html(an, narrative):
    seed = an["seed"]
    conf = an["confidence"]
    clabel, ccol = conf_label(conf)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    n_prof = len(an["profiles"])
    n_ev = len(an["evidence"])
    n_plat = len({p["platform"] for p in an["profiles"]})

    rows = []
    for p in an["profiles"]:
        src_tag = {"sweep": "y", "github-api": "g", "gravatar": "g"}.get(p["source"], "")
        rows.append(f"<tr><td><span class='tag {src_tag}'>{esc(p['platform'])}</span></td>"
                    f"<td class='mono'>{esc(p['handle'])}</td><td>{esc(p.get('title') or '—')}</td>"
                    f"<td class='mono' style='color:var(--dim)'>{esc((p.get('bio') or '')[:120])}</td>"
                    f"<td><a href='{esc(p['url'])}' target='_blank'>open</a></td></tr>")
    table = ("<input class='filter' id='fq' placeholder='filter results...' oninput='flt()'>"
             "<table id='ftable'><thead><tr><th>platform</th><th>handle</th><th>name</th>"
             f"<th>bio excerpt</th><th></th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
             "<button onclick='copyAll()' style='margin-top:10px;background:#1a2334;color:#22d3ee;"
             "border:1px solid #232b3b;border-radius:8px;padding:9px 16px;cursor:pointer'>copy all links</button>")

    ev_rows = []
    for i, j, ev in an["evidence"][:60]:
        a, b = an["profiles"][i], an["profiles"][j]
        for kind, mult in ev:
            ev_rows.append(f"<tr><td class='mono'>{esc(a['platform'])}:{esc(a['handle'])}</td>"
                           f"<td class='mono'>{esc(b['platform'])}:{esc(b['handle'])}</td>"
                           f"<td><span class='tag'>{esc(kind)}</span></td>"
                           f"<td class='mono'>{mult:.2f}</td></tr>")
    ev_table = ("<table><thead><tr><th>profile a</th><th>profile b</th><th>signal</th>"
                f"<th>strength</th></tr></thead><tbody>{''.join(ev_rows)}</tbody></table>"
                if ev_rows else "<div class='kv'><b>no cross-profile signals fired</b></div>")

    radar_items = [(k, v / max(an["interests"].values())) for k, v in an["interests"].items()] \
        if an["interests"] else []
    kw_html = "".join(f"<span class='tag'>{esc(k)}</span>" for k in list(an["interests"])[:6]) \
        or "<b style='color:var(--dim)'>none detected</b>"

    bar_items = [(f"{p['platform']} / {p['handle'][:14]}",
                  0.9 if p["source"] != "sweep" else 0.72, "#22d3ee")
                 for p in an["primary"][:10]]

    geo_rows = "".join(f"<tr><td>{esc(g)}</td><td class='mono'>{v:.1f}</td></tr>"
                       for g, v in an["geo"]) or "<tr><td colspan=2>no location signals</td></tr>"

    tl_rows = "".join(f"<tr><td class='mono'>{e[0].strftime('%Y-%m-%d')}</td><td>{esc(e[1])}</td>"
                      f"<td><span class='tag'>{esc(e[2])}</span></td></tr>" for e in an["timeline"]) \
        or "<tr><td colspan=3>no datable events found</td></tr>"

    ph = an.get("phone")
    if ph:
        phone_html = "<div class='kv'>" + "".join(
            f"<b>{esc(k)}</b><span>{esc(v)}</span>"
            for k, v in (("number", ph.get("input")), ("country", ph.get("country")),
                         ("region", ph.get("region") or "—"), ("line type", ph.get("type") or "unknown"),
                         ("carrier hint", ph.get("carrier") or "—"), ("timezone", ph.get("tz")),
                         ("e164", ph.get("e164"))) if v) + "</div>"
        phone_html += "".join(f"<span class='tag y' style='margin:4px 4px 0 0'>{esc(n)}</span>"
                              for n in ph.get("notes", []))
    else:
        phone_html = "<div class='kv'><b>no phone analyzed</b></div>"

    raw_rows = []
    for f in FINDINGS:
        compact = {k: v for k, v in f.items() if k != "_t" and v}
        raw_rows.append(f"<tr><td><span class='tag'>{esc(f['kind'])}</span></td>"
                        f"<td class='mono' style='font-size:11px;color:var(--dim)'>"
                        f"{esc(json.dumps(compact)[:180])}</td></tr>")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT report - {esc(seed)}</title>
<style>{REPORT_CSS}</style></head>
<body>
<header><div class="wrap">
<h1>OSINT <span>report</span></h1>
<div class="sub">target <b class="mono" style="color:var(--tx)">{esc(seed)}</b>
&nbsp;·&nbsp; generated {now} &nbsp;·&nbsp; osint lab v{VER}</div>
<div style="margin-top:14px">
<span class="badge" style="background:{ccol}22;color:{ccol}">identity confidence: {clabel} · {conf*100:.0f}%</span>
<span class="badge" style="background:#22d3ee22;color:#22d3ee">{n_prof} profiles</span>
<span class="badge" style="background:#c084fc22;color:#c084fc">{n_ev} correlation signals</span>
<span class="badge" style="background:#22c55e22;color:#22c55e">{n_plat} platforms</span>
</div></div></header>

<div class="wrap">

<h2><span class="n">01</span>executive summary</h2>
<div class="card narr">{esc(narrative)}</div>

<div class="grid">
<div class="card stat"><div class="big" style="color:{ccol}">{conf*100:.0f}%</div><div class="lab">identity confidence</div></div>
<div class="card stat"><div class="big" style="color:#22d3ee">{n_prof}</div><div class="lab">profiles found</div></div>
<div class="card stat"><div class="big" style="color:#c084fc">{n_ev}</div><div class="lab">signals analyzed</div></div>
<div class="card stat"><div class="big" style="color:#22c55e">{len(an['timeline'])}</div><div class="lab">timeline events</div></div>
</div>

<h2><span class="n">02</span>profile inventory</h2>
<div class="card">{table}</div>

<h2><span class="n">03</span>correlation matrix</h2>
<div class="card">{ev_table}</div>

<h2><span class="n">04</span>identity cluster</h2>
<div class="card">
<div class="kv">
<b>primary handle</b><span class="mono">{esc(an['main_handle'])}</span>
<b>best real name</b><span>{esc(an['real_name'] or 'not determined')}</span>
<b>cluster size</b><span>{len(an['primary'])} profile(s) of {n_prof}</span>
</div>
<div style="margin-top:18px">{svg_graph(an['profiles'], an['edges'])}</div>
</div>
<div class="card">{svg_bars(bar_items)}</div>

<h2><span class="n">05</span>interest profile</h2>
<div class="grid">
<div class="card">{svg_radar(radar_items)}</div>
<div class="card">
<div style="margin-bottom:14px">{kw_html}</div>
<div class="kv">
<b>method</b><span>bio text tokenized, stopworded, matched against
{len(INTERESTS)} keyword buckets, weighted by hit frequency</span>
<b>source docs</b><span>{sum(1 for p in an['profiles'] if p.get('bio'))} bio(s) available</span>
</div>
</div>
</div>

<h2><span class="n">06</span>geographic signals</h2>
<div class="card">
<table><thead><tr><th>candidate location</th><th>vote weight</th></tr></thead>
<tbody>{geo_rows}</tbody></table>
</div>

<h2><span class="n">07</span>timeline</h2>
<div class="card">{svg_timeline(an['timeline'])}</div>
<div class="card"><table><thead><tr><th>date</th><th>event</th><th>source</th></tr></thead>
<tbody>{tl_rows}</tbody></table></div>

<h2><span class="n">08</span>phone analysis</h2>
<div class="card">{phone_html}</div>

<h2><span class="n">09</span>raw findings</h2>
<details><summary>show all {len(FINDINGS)} raw finding records</summary>
<div class="dbody"><table><thead><tr><th>type</th><th>data</th></tr></thead>
<tbody>{''.join(raw_rows)}</tbody></table></div></details>

<footer>generated locally by osint lab v{VER} · public data only ·
confidence figures are statistical estimates, not proof</footer>
</div>
<script>{REPORT_JS}</script>
</body></html>"""


def write_report(an, narrative):
    safe = re.sub(r"[^a-zA-Z0-9]", "_", an["seed"])[:40]
    fname = f"osint_report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(report_html(an, narrative))
        print(f"\n  {G}● report written:{R} {B}{fname}{R}")
        try:
            webbrowser.open("file://" + os.path.abspath(fname))
        except Exception:
            pass
        return fname
    except Exception as e:
        print(f"{RD}✗ couldnt write report: {e}{R}")
        return None


# ── pipeline ───────────────────────────────────────────────────

def deep_recon(target):
    FINDINGS.clear()
    hdr(f"DEEP RECON > {target}")
    phone_data = ip_data = None
    is_email = "@" in target and "." in target.split("@")[-1]
    is_phone = bool(re.match(r"^\+?[\d\s\-(). x]{7,}$", target)) and re.sub(r"\D", "", target)
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    is_dom = bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$", target)) and not is_email

    stage = 0
    def nxt(label):
        nonlocal stage
        stage += 1
        print(f"\n{M}  [{stage}] {label}{R}")
        print(f"{M}  {'─'*44}{R}")

    if is_email:
        nxt("email recon")
        em = email_recon(target)
        user = target.split("@")[0]
        nxt("username sweep")
        check_username(user)
        if em and em.get("gravatar") and em["gravatar"].get("name"):
            gname = em["gravatar"]["name"]
            parts = gname.split()
            nxt(f"permutation sweep on '{gname}'")
            perms = username_permutations(parts[0], parts[-1] if len(parts) > 1 else None)
            newhits = 0
            for pm in perms[:6]:
                hits = quick_sweep(pm)
                if hits:
                    newhits += len(hits)
                    for site, link, title, desc in hits[:4]:
                        print(f"   {G}●{R} {pm} on {B}{site}{R} {D}{link}{R}")
            if newhits:
                print(f"\n  {G}{newhits} extra hits from {len(perms[:6])} permutations{R}")
            else:
                print(f"  {D}permutations came up empty{R}")
        nxt("github")
        gh_recon(user)
        nxt("dork links")
        dorks(target)

    elif is_phone:
        nxt("phone analysis")
        phone_data = check_phone(target)

    elif is_ip:
        nxt("ip intel")
        ip_data = check_ip(target)
        nxt("port scan")
        portscan(target)
        nxt("headers")
        check_headers(target)

    elif is_dom:
        nxt("domain")
        check_domain(target)
        nxt("whois")
        do_whois(target)
        nxt("dns recon")
        dnsrecon(target)
        nxt("wayback")
        wayback(target)
        nxt("headers")
        check_headers(target)

    else:
        nxt("username sweep")
        check_username(target)
        nxt("github")
        gh_recon(target)
        nxt("dork links")
        dorks(target)

    nxt("analysis engine")
    print(f"  {D}clustering · scoring evidence · building vectors{R}")
    an = analyze(target, phone_data, ip_data)
    narrative = narrate(an)

    print(f"\n{B}{M}  SUMMARY{R}")
    for chunk in re.split(r"(?<=[.!?]) ", narrative):
        print(f"  {C}»{R} {chunk}")
    clabel, _ = conf_label(an["confidence"])
    print(f"\n  identity confidence: {B}{an['confidence']*100:.0f}% ({clabel}){R}")

    nxt("html report")
    write_report(an, narrative)
    log(f"deep recon {target}: {len(an['profiles'])} profiles, conf {an['confidence']:.2f}")


# ── cli ────────────────────────────────────────────────────────

BANNER = f"""{C}
    ██████╗ ███████╗██╗███╗   ██╗████████╗
   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
   ██║   ██║███████╗██║██╔██╗ ██║   ██║
   ██║   ██║╚════██║██║██║╚██╗██║   ██║
   ╚██████╔╝███████║██║██║ ╚████║   ██║
    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝{R}

  {B}{M}O S I N T   L A B{R} {D}v{VER} · {len(SITES)} sites · local analysis · html reports{R}
"""

HELP = f"""
{C}the one command{R}
  {Y}recon <target>{R}      auto-detect email/phone/ip/domain/username, run the full
                    pipeline, correlate, write an html report

{singles if False else ''}{C}singles{R}
  {Y}username <name>{R}    sweep {len(SITES)} sites
  {Y}phone <number>{R}     offline analysis: country, region, carrier, timezone
  {Y}email <addr>{R}       gravatar + domain + smtp
  {Y}github <user>{R}      profile + recent repos
  {Y}ip <addr>{R}          geo + isp + ptr
  {Y}domain <name>{R}      resolve + web check
  {Y}whois <domain>{R}     registration info
  {Y}dns <domain>{R}       records + {len(SUBS)} word subdomain sweep
  {Y}wayback <url>{R}      archived snapshots
  {Y}headers <url>{R}      security + tech headers
  {Y}portscan <ip>{R}      {len(PORTS)} ports + banner grab
  {Y}mac <addr>{R}         vendor lookup
  {Y}dorks <target>{R}     prebuilt search links
  {Y}perms <first> [last]{R} username permutation ideas

{C}other{R}
  {Y}help{R} {Y}clear{R} {Y}exit{R}

{D}analysis is fully local, no api keys. ctrl+c aborts a scan without
killing the tool T_T{R}
"""

SIMPLE = {
"username": check_username, "phone": check_phone, "email": email_recon,
"github": gh_recon, "ip": check_ip, "domain": check_domain, "whois": do_whois,
"dns": dnsrecon, "wayback": wayback, "headers": check_headers,
"portscan": portscan, "mac": check_mac, "dorks": dorks,
}


def main():
    clear_screen()
    print(BANNER)
    while True:
        try:
            line = input(f"{C}{B}osintlab{R} > ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Y}bye{R}")
            break
        if not line:
            continue
        parts = line.split(" ", 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("exit", "quit", "q"):
            print(f"{RD}bye{R}")
            break
        elif cmd == "help":
            print(HELP)
        elif cmd == "clear":
            clear_screen()
            print(BANNER)
        elif cmd == "perms":
            bits = arg.split()
            if not bits:
                print(f"{RD}[-] perms <first> [last]{R}")
            else:
                for p in username_permutations(bits[0], bits[1] if len(bits) > 1 else None):
                    print(f"  {C}·{R} {p}")
        elif cmd == "recon":
            if not arg:
                print(f"{RD}[-] recon <target>{R}")
            else:
                try:
                    deep_recon(arg)
                except KeyboardInterrupt:
                    print(f"\n{Y}[!] scan aborted{R}")
                except Exception as e:
                    print(f"{RD}[-] pipeline died: {e}{R}")
        elif cmd in SIMPLE:
            if not arg:
                print(f"{RD}[-] {cmd} needs an argument{R}")
            else:
                try:
                    SIMPLE[cmd](arg)
                except KeyboardInterrupt:
                    print(f"\n{Y}[!] aborted{R}")
                except Exception as e:
                    print(f"{RD}[-] {e}{R}")
        else:
            print(f"{RD}[-] unknown command '{cmd}', try help{R}")


main()
