import os
import json
import socket
import requests


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

clear_screen()

SITES = {
    "Instagram": "https://www.instagram.com/{}/",
    "X": "https://x.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Telegram": "https://t.me/{}",
    "Tumblr": "https://{}.tumblr.com/",
    "Threads": "https://www.threads.com/@{}",
    "Mastodon": "https://mastodon.social/@{}",
    "Bluesky": "https://bsky.app/profile/{}.bsky.social",
    "Quora": "https://www.quora.com/profile/{}",
    "Disqus": "https://disqus.com/by/{}",
    "About.me": "https://about.me/{}",
    "Linktree": "https://linktr.ee/{}",
    "Gravatar": "https://gravatar.com/{}",
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Codeberg": "https://codeberg.org/{}",
    "Bitbucket": "https://bitbucket.org/{}",
    "SourceForge": "https://sourceforge.net/u/{}/",
    "Replit": "https://replit.com/@{}",
    "CodePen": "https://codepen.io/{}",
    "Dev.to": "https://dev.to/{}",
    "Stack Overflow": "https://stackoverflow.com/users/{}",
    "HackerRank": "https://www.hackerrank.com/profile/{}",
    "HackerEarth": "https://www.hackerearth.com/@{}",
    "Codeforces": "https://codeforces.com/profile/{}",
    "CodeChef": "https://www.codechef.com/users/{}",
    "AtCoder": "https://atcoder.jp/users/{}",
    "LeetCode": "https://leetcode.com/u/{}/",
    "Topcoder": "https://www.topcoder.com/members/{}",
    "Exercism": "https://exercism.org/profiles/{}",
    "WakaTime": "https://wakatime.com/@{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "Hugging Face": "https://huggingface.co/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "npm": "https://www.npmjs.com/~{}",
    "PyPI": "https://pypi.org/user/{}/",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "ArtStation": "https://www.artstation.com/{}",
    "DeviantArt": "https://www.deviantart.com/{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "500px": "https://500px.com/p/{}",
    "Unsplash": "https://unsplash.com/@{}",
    "Sketchfab": "https://sketchfab.com/{}",
    "VSCO": "https://vsco.co/{}/gallery",
    "Pixabay": "https://pixabay.com/users/{}",
    "EyeEm": "https://www.eyeem.com/u/{}",
    "Ello": "https://ello.co/{}",
    "Cargo": "https://{}.cargo.site/",
    "Crevado": "https://{}.crevado.com/",
    "YouTube": "https://www.youtube.com/@{}",
    "Vimeo": "https://vimeo.com/{}",
    "Dailymotion": "https://www.dailymotion.com/{}",
    "Rumble": "https://rumble.com/user/{}",
    "Kick": "https://kick.com/{}",
    "PeerTube": "https://peertube.social/a/{}",
    "Odysee": "https://odysee.com/@{}",
    "Bitchute": "https://www.bitchute.com/channel/{}",
    "DTube": "https://d.tube/c/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Last.fm": "https://www.last.fm/user/{}",
    "Bandcamp": "https://bandcamp.com/{}",
    "Mixcloud": "https://www.mixcloud.com/{}/",
    "Audiomack": "https://audiomack.com/{}",
    "HearThis": "https://hearthis.at/{}/",
    "ReverbNation": "https://www.reverbnation.com/{}",
    "Discogs": "https://www.discogs.com/user/{}",
    "Rate Your Music": "https://rateyourmusic.com/~{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Chess.com": "https://www.chess.com/member/{}",
    "Lichess": "https://lichess.org/@/{}",
    "Speedrun.com": "https://www.speedrun.com/users/{}",
    "Modrinth": "https://modrinth.com/user/{}",
    "CurseForge": "https://www.curseforge.com/members/{}",
    "Itch.io": "https://{}.itch.io/",
    "Game Jolt": "https://gamejolt.com/@{}",
    "Osu": "https://osu.ppy.sh/users/{}",
    "Newgrounds": "https://{}.newgrounds.com/",
    "Scratch": "https://scratch.mit.edu/users/{}/",
    "Roblox": "https://www.roblox.com/users/profile?username={}",
    "Medium": "https://medium.com/@{}",
    "Wattpad": "https://www.wattpad.com/user/{}",
    "Substack": "https://{}.substack.com/",
    "Write.as": "https://write.as/{}",
    "Telegra.ph": "https://telegra.ph/{}",
    "Vocal": "https://vocal.media/authors/{}",
    "Scribd": "https://www.scribd.com/{}",
    "Goodreads": "https://www.goodreads.com/{}",
    "Letterboxd": "https://letterboxd.com/{}/",
    "MyAnimeList": "https://myanimelist.net/profile/{}",
    "AniList": "https://anilist.co/user/{}",
    "Kitsu": "https://kitsu.io/users/{}",
    "Patreon": "https://www.patreon.com/{}",
    "Ko-fi": "https://ko-fi.com/{}",
    "Buy Me a Coffee": "https://www.buymeacoffee.com/{}",
    "Gumroad": "https://{}.gumroad.com/",
    "Payhip": "https://payhip.com/{}",
    "Liberapay": "https://liberapay.com/{}",
    "Open Collective": "https://opencollective.com/{}",
    "Crowdfunder": "https://www.crowdfunder.co.uk/{}",
    "Keybase": "https://keybase.io/{}",
    "Fandom": "https://community.fandom.com/wiki/User:{}",
    "Instructables": "https://www.instructables.com/member/{}/",
    "Thingiverse": "https://www.thingiverse.com/{}",
    "OpenStreetMap": "https://www.openstreetmap.org/user/{}",
    "Internet Archive": "https://archive.org/details/@{}",
    "ResearchGate": "https://www.researchgate.net/profile/{}",
    "ORCID": "https://orcid.org/{}",
    "Trello": "https://trello.com/u/{}",
    "Figma": "https://www.figma.com/@{}",
    "Canva": "https://www.canva.com/p/{}",
    "Product Hunt": "https://www.producthunt.com/@{}",
    "Speaker Deck": "https://speakerdeck.com/{}",
    "SlideShare": "https://www.slideshare.net/{}",
    "Printables": "https://www.printables.com/@{}",
    "MakerWorld": "https://makerworld.com/en/@{}",
    "MyMiniFactory": "https://www.myminifactory.com/users/{}",
    "Cults3D": "https://cults3d.com/en/users/{}",
    "GrabCAD": "https://grabcad.com/{}",
    "Stack Exchange": "https://stackexchange.com/users/{}",
    "Ask Ubuntu": "https://askubuntu.com/users/{}",
    "Super User": "https://superuser.com/users/{}",
    "Server Fault": "https://serverfault.com/users/{}",
    "Math StackExchange": "https://math.stackexchange.com/users/{}",
    "Superprof": "https://www.superprof.com/{}",
    "SlideServe": "https://www.slideserve.com/{}",
    "Issuu": "https://issuu.com/{}",
    "Flipboard": "https://flipboard.com/@{}",
    "Pearltrees": "https://www.pearltrees.com/{}",
    "Diigo": "https://www.diigo.com/profile/{}",
    "Pastebin": "https://pastebin.com/u/{}",
    "GitHub Gist": "https://gist.github.com/{}",
    "CodeSandbox": "https://codesandbox.io/u/{}",
    "Glitch": "https://glitch.com/@{}",
    "Firebase": "https://console.firebase.google.com/u/0/{}",
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{}",
    "Wiktionary": "https://en.wiktionary.org/wiki/User:{}",
    "VK": "https://vk.com/{}",
    "Weibo": "https://weibo.com/{}",
    "Baidu": "https://baike.baidu.com/item/{}",
    "Douban": "https://www.douban.com/people/{}",
    "Zhihu": "https://www.zhihu.com/people/{}",
    "Bilibili": "https://space.bilibili.com/{}",
    "AliExpress": "https://www.aliexpress.com/store/{}",
    "Etsy": "https://www.etsy.com/shop/{}",
    "Shopify": "https://{}.myshopify.com/",
    "BigCartel": "https://{}.bigcartel.com/",
    "SquareSpace": "https://{}.squarespace.com/",
    "Wix": "https://{}.wixsite.com/{}",
    "WordPress": "https://{}.wordpress.com/",
    "Blogspot": "https://{}.blogspot.com/",
    "Ghost": "https://{}.ghost.io/",
    "Joomla": "https://{}.joomla.com/",
    "Drupal": "https://{}.drupal.org/user/{}",
    "phpBB": "https://www.phpbb.com/community/memberlist.php?mode=viewprofile&u={}",
    "vBulletin": "https://www.vbulletin.com/forum/member.php?{}",
    "SMF": "https://www.simplemachines.org/community/index.php?action=profile;u={}",
    "XenForo": "https://xenforo.com/community/members/{}",
    "Skype": "skype:{}",
    "RocketChat": "https://open.rocket.chat/direct/{}",
    "Mattermost": "https://mattermost.com/{}",
    "Zulip": "https://zulip.com/{}",
    "Matrix": "https://matrix.to/#/@{}:matrix.org",
    "Signal": "https://signal.me/#p/{}",
    "Wire": "https://wire.com/@{}",
    "Threema": "https://threema.id/{}",
    "Viber": "viber://chat?number={}",
    "Kik": "https://kik.me/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "BeReal": "https://bere.al/{}",
    "Vero": "https://vero.co/{}",
    "Pleroma": "https://pleroma.site/{}",
    "Friendica": "https://friendi.ca/profile/{}",
    "Misskey": "https://misskey.io/@{}",
    "Pixelfed": "https://pixelfed.org/{}",
    "WriteFreely": "https://writefreely.org/{}",
    "Lemmy": "https://lemmy.world/u/{}",
    "Kbin": "https://kbin.social/u/{}"
}

def check_username(username):
    print(f"\n\033[96m🔍 Searching for '{username}' across the web...\033[0m\n")
    found = 0
    not_found = 0
    errors = 0
    
    for site, url in SITES.items():
        link = url.format(username)
        try:
            req = requests.get(link, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if req.status_code == 200:
                print(f"\033[92m✓ {site}\033[0m - Found at {link}")
                found += 1
            elif req.status_code == 404:
                print(f"\033[91m✗ {site}\033[0m - Not found")
                not_found += 1
            elif req.status_code == 429:
                print(f"\033[93m⏱ {site}\033[0m - Too many requests (rate limited)")
                errors += 1
            else:
                print(f"\033[93m⚠ {site}\033[0m - Unexpected response ({req.status_code})")
                errors += 1
        except:
            # weak error handling just pass
            print(f"\033[91m✗ {site}\033[0m - Connection error")
            errors += 1
            
    print(f"\n\033[96m📊 Results: {found} found, {not_found} not found, {errors} errors\033[0m")

def check_phone(number):
    print(f"\n\033[96m🔍 Looking up {number}...\033[0m\n")
    api_key = None
    
    try:
        f = open("osint_config.json", "r")
        cfg = json.load(f)
        api_key = cfg.get("phone_api")
        f.close()
    except:
        pass

    if not api_key:
        print("\033[91m✗ No Phone API configured.\033[0m")
        print("\033[93mType 'note' and add your Phone API key first.\033[0m")
        return

    try:
        req = requests.get(
            "https://api.veriphone.io/v3/verify",
            params={"phone": number},
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        if req.status_code != 200:
            print(f"\033[91m✗ API error: {req.status_code}\033[0m")
            return
        data = req.json()
        if data.get("status") != "success":
            print("\033[91m✗ Phone lookup failed.\033[0m")
            if data.get("message"):
                print(data["message"])
            return
        print("\033[92m✓ Phone information found\033[0m\n")
        print(f"Valid       : {data.get('phone_valid')}")
        print(f"Country     : {data.get('country')}")
        print(f"Country Code: {data.get('country_code')}")
        print(f"Dial Code   : +{data.get('country_prefix')}")
        print(f"Region      : {data.get('phone_region')}")
        print(f"Type        : {data.get('phone_type')}")
        print(f"Carrier     : {data.get('carrier')}")
        print(f"International: {data.get('international_number')}")
        print(f"Local       : {data.get('local_number')}")
        print(f"E164        : {data.get('e164')}")
        tz = data.get("timezone")
        if tz:
            print(f"Timezone    : {', '.join(tz)}")
    except:
        print("\033[91m✗ Could not connect to phone API.\033[0m")

def check_ip(ip_addr):
    print(f"\n\033[96m🔍 Looking up IP {ip_addr}...\033[0m\n")
    try:
        req = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=5)
        data = req.json()
        if data.get("status") == "success":
            print("\033[92m✓ IP information found\033[0m\n")
            print(f"IP          : {data.get('query')}")
            print(f"Country     : {data.get('country')}")
            print(f"City        : {data.get('city')}")
            print(f"Region      : {data.get('regionName')}")
            print(f"ISP         : {data.get('isp')}")
            print(f"Org         : {data.get('org')}")
            print(f"Timezone    : {data.get('timezone')}")
        else:
            print(f"\033[91m✗ Lookup failed: {data.get('message', 'Unknown error')}\033[0m")
    except:
        print("\033[91m✗ Could not fetch IP info.\033[0m")

def check_domain(domain):
    print(f"\n\033[96m🔍 Resolving domain {domain}...\033[0m\n")
    try:
        ip = socket.gethostbyname(domain)
        print(f"\033[92m✓ Domain resolved\033[0m\n")
        print(f"Domain      : {domain}")
        print(f"IP Address  : {ip}")
    
        try:
            host_info = socket.gethostbyaddr(ip)
            print(f"Host Name   : {host_info[0]}")
        except:
            pass
            
    except:
        print("\033[91m✗ Could not resolve domain.\033[0m")

def check_email(mail):
    print(f"\n\033[96m🔍 Checking email {mail}...\033[0m\n")
    if "@" not in mail:
        print("\033[91m✗ Invalid email format.\033[0m")
        return
        
    parts = mail.split("@")
    if len(parts) != 2:
        print("\033[91m✗ Invalid email format.\033[0m")
        return
        
    domain = parts[1]
    print(f"Domain      : {domain}")

    try:
        ip = socket.gethostbyname(domain)
        print(f"IP Address  : {ip}")
    except:
        print("\033[91m✗ Could not resolve email domain.\033[0m")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((domain, 25))
        if result == 0:
            print("SMTP Port 25: Open")
        else:
            print("SMTP Port 25: Closed or filtered")
        sock.close()
    except:
        print("SMTP Port 25: Error checking")

def check_mac(mac_addr):
    print(f"\n\033[96m🔍 Looking up MAC {mac_addr}...\033[0m\n")
    # simple check
    if len(mac_addr) != 17:
        print("\033[91m✗ MAC address looks wrong.\033[0m")
        return

    oui = mac_addr.replace("-", ":").upper()[:8]
    print(f"OUI         : {oui}")

    try:
        req = requests.get(f"https://api.macvendors.com/{oui}", timeout=5)
        if req.status_code == 200:
            print(f"Vendor      : {req.text}")
        else:
            print("\033[91m✗ Vendor not found.\033[0m")
    except:
        print("\033[91m✗ Error getting MAC vendor.\033[0m")

def check_headers(url):
    print(f"\n\033[96m🔍 Getting headers for {url}...\033[0m\n")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    try:
        req = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        print("\033[92m✓ Headers found\033[0m\n")
        print(f"Server      : {req.headers.get('Server', 'None')}")
        print(f"Content-Type: {req.headers.get('Content-Type', 'None')}")
        print(f"Status Code : {req.status_code}")
        print(f"X-Powered-By: {req.headers.get('X-Powered-By', 'None')}")
        print(f"X-Frame-Options: {req.headers.get('X-Frame-Options', 'None')}")
        print(f"Strict-Transport-Security: {req.headers.get('Strict-Transport-Security', 'None')}")
        print(f"Cache-Control: {req.headers.get('Cache-Control', 'None')}")
    except:
        print("\033[91m✗ Could not get headers.\033[0m")

def scan_ports(ip):
    print(f"\n\033[96m🔍 Scanning common ports on {ip}...\033[0m\n")
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080, 8443, 3306, 5432, 6379, 27017]
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, p))
            if result == 0:
                print(f"\033[92m✓ Port {p}\033[0m - Open")
            else:
                print(f"\033[91m✗ Port {p}\033[0m - Closed")
            sock.close()
        except:
            print(f"\033[91m✗ Port {p}\033[0m - Error")

def configure_api():
    print("""
\033[96m╔══════════════════════════════════════════════════════════════╗
║                    API CONFIGURATION                         ║
╚══════════════════════════════════════════════════════════════╝\033[0m

  1. Phone API
  2. Username API
  3. View saved APIs
  4. Delete saved APIs
  5. Back
""")
    choice = input("\033[96mAPI Config > \033[0m").strip()
    saved_apis = {}
    
    # load config
    try:
        f = open("osint_config.json", "r")
        saved_apis = json.load(f)
        f.close()
    except:
        saved_apis = {}

    if choice == "1":
        key = input("\033[93mEnter Phone API key: \033[0m").strip()
        if key:
            saved_apis["phone_api"] = key
            f = open("osint_config.json", "w")
            f.write(json.dumps(saved_apis, indent=4))
            f.close()
            print("\033[92m[+] Phone API key saved.\033[0m")
            
    elif choice == "2":
        key = input("\033[93mEnter Username API key: \033[0m").strip()
        if key:
            saved_apis["username_api"] = key
            f = open("osint_config.json", "w")
            f.write(json.dumps(saved_apis, indent=4))
            f.close()
            print("\033[92m[+] Username API key saved.\033[0m")
            
    elif choice == "3":
        if saved_apis:
            print("\n\033[96mSaved APIs:\033[0m")
            for name in saved_apis:
                print(f"  ✓ {name}")
        else:
            print("\033[91m[-] No APIs saved yet.\033[0m")
            
    elif choice == "4":
        try:
            os.remove("osint_config.json")
            print("\033[92m[+] Saved APIs deleted.\033[0m")
        except:
            print("\033[91m[-] No saved APIs found.\033[0m")
            
    elif choice == "5":
        return
    else:
        print("\033[91m[-] Invalid option.\033[0m")

print("""
\033[96m╔══════════════════════════════════════════════════════════════╗\033[0m
\033[96m║\033[0m                                                              \033[96m║\033[0m
\033[96m║\033[0m          \033[95m██████╗ ███████╗██╗███╗   ██╗████████╗\033[0m          \033[96m    ║\033[0m
\033[96m║\033[0m         \033[95m██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝\033[0m          \033[96m    ║\033[0m
\033[96m║\033[0m         \033[95m██║   ██║███████╗██║██╔██╗ ██║   ██║\033[0m             \033[96m    ║\033[0m
\033[96m║\033[0m         \033[95m██║   ██║╚════██║██║██║╚██╗██║   ██║\033[0m             \033[96m    ║\033[0m
\033[96m║\033[0m         \033[95m╚██████╔╝███████║██║██║ ╚████║   ██║\033[0m             \033[96m    ║\033[0m
\033[96m║\033[0m          \033[95m╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝\033[0m             \033[96m    ║\033[0m
\033[96m║\033[0m                                                              \033[96m║\033[0m
\033[96m║\033[0m                  \033[93mO S I N T  L A B\033[0m                        \033[96m    ║\033[0m
\033[96m║\033[0m          \033[90mOpen Source Intelligence Toolkit\033[0m                  \033[96m  ║\033[0m
\033[96m║\033[0m                                                              \033[96m║\033[0m
\033[96m╚══════════════════════════════════════════════════════════════╝\033[0m

        \033[96mType 'help' to view available commands.\033[0m
""")

while True:
    cmd = input("\033[96mOsintLab > \033[0m").strip()
    if not cmd:
        continue
        
    cmd_lower = cmd.lower()
    
    if cmd_lower.startswith("username "):
        user = cmd[9:].strip()
        if user:
            check_username(user)
        else:
            print("\033[91m[-] Please enter a username.\033[0m")

    elif cmd_lower.startswith("phone "):
        num = cmd[6:].strip()
        if num:
            check_phone(num)
        else:
            print("\033[91m[-] Please enter a phone number.\033[0m")

    elif cmd_lower.startswith("ip "):
        ip = cmd[3:].strip()
        if ip:
            check_ip(ip)
        else:
            print("\033[91m[-] Please enter an IP address.\033[0m")

    elif cmd_lower.startswith("domain "):
        dom = cmd[7:].strip()
        if dom:
            check_domain(dom)
        else:
            print("\033[91m[-] Please enter a domain.\033[0m")

    elif cmd_lower.startswith("email "):
        mail = cmd[6:].strip()
        if mail:
            check_email(mail)
        else:
            print("\033[91m[-] Please enter an email.\033[0m")

    elif cmd_lower.startswith("mac "):
        mac = cmd[4:].strip()
        if mac:
            check_mac(mac)
        else:
            print("\033[91m[-] Please enter a MAC address.\033[0m")

    elif cmd_lower.startswith("headers "):
        url = cmd[8:].strip()
        if url:
            check_headers(url)
        else:
            print("\033[91m[-] Please enter a URL.\033[0m")

    elif cmd_lower.startswith("portscan "):
        ip = cmd[9:].strip()
        if ip:
            scan_ports(ip)
        else:
            print("\033[91m[-] Please enter an IP address.\033[0m")

    elif cmd_lower == "note":
        configure_api()

    elif cmd_lower == "help":
        print("""
\033[96m╔══════════════════════════════════════════════════════════════╗
║                       OSINT LAB                              ║
║                    Command Reference                         ║
╚══════════════════════════════════════════════════════════════╝\033[0m

  \033[95mLOOKUP COMMANDS\033[0m
  ────────────────────────────────────────────────────────────

  \033[93musername <name>\033[0m       Search for public username presence
  \033[93mphone <number>\033[0m        Check publicly available phone information
  \033[93mip <address>\033[0m          Get geolocation and ISP info for an IP
  \033[93mdomain <name>\033[0m         Resolve domain to IP and host
  \033[93memail <addr>\033[0m          Check email domain and SMTP server
  \033[93mmac <addr>\033[0m            Look up MAC address vendor
  \033[93mheaders <url>\033[0m         Get HTTP headers from a website
  \033[93mportscan <ip>\033[0m         Scan common ports on an IP

  \033[95mUSAGE\033[0m
  ────────────────────────────────────────────────────────────

  \033[92musername target_user\033[0m
  \033[92mphone +919876543210\033[0m
  \033[92mip 8.8.8.8\033[0m
  \033[92mdomain target.com\033[0m
  \033[92memail test@mail.com\033[0m
  \033[92mmac 00:1B:44:11:3A:B7\033[0m
  \033[92mheaders target.com\033[0m
  \033[92mportscan 8.8.8.8\033[0m

  \033[95mOPTIONS\033[0m
  ────────────────────────────────────────────────────────────

  \033[93mclear\033[0m                  Clear the terminal
  \033[93mhelp\033[0m                   Show this help menu
  \033[93mexit\033[0m                   Exit OSINT Lab
  \033[93mnote\033[0m                   Add apis for better tracking
  
  \033[90mNOTE
  ────────────────────────────────────────────────────────────
  OSINT Lab works with publicly available information only T_T.\033[0m
""")

    elif cmd_lower == "clear":
        clear_screen()

    elif cmd_lower == "exit":
        print("\033[91m[!] Exiting OSINT Lab...\033[0m")
        break

    else:
        print("\033[91m[-] Unknown command. Type 'help' for available commands.\033[0m")