# feature_extraction.py
import re, socket, datetime, math
from urllib.parse import urlparse
import tldextract
import whois
import requests
from bs4 import BeautifulSoup
import hashlib
import statistics

# list of suspicious free TLDs
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.icu', '.work'}

# expanded shortening services (regex)
SHORTS_RE = re.compile(r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|bitly\.com|is\.gd|tiny\.cc|short\.io|shorte\.st|adf\.ly", re.I)

# suspicious keywords in domain/path
SUSP_KEYWORDS = ['free', 'claim', 'bonus', 'prize', 'win', 'login', 'verify', 'update', 'secure', 'account', 'bank', 'confirm', 'password']

def domain_entropy(s):
    # Shannon entropy of domain part
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log2(p) for p in probs)

def safe_request(url, timeout=4):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={'User-Agent':'Mozilla/5.0'})
        return r
    except Exception:
        return None

def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path or ''
        hostname = tldextract.extract(url).registered_domain or domain

        # WHOIS
        try:
            w = whois.whois(domain)
        except Exception:
            w = {}

        # 1. having_IPhaving_IP_Address
        features['having_IPhaving_IP_Address'] = -1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain) else 1

        # 2. URLURL_Length
        length = len(url)
        features['URLURL_Length'] = 1 if length < 54 else 0 if length <= 75 else -1

        # 3. Shortining_Service
        features['Shortining_Service'] = -1 if SHORTS_RE.search(url) else 1

        # 4. having_At_Symbol
        features['having_At_Symbol'] = -1 if '@' in url else 1

        # 5. double_slash_redirecting
        # suspicious if '//' appears after protocol early in URL (redirect trick)
        features['double_slash_redirecting'] = -1 if '//' in url[7:] else 1

        # 6. Prefix_Suffix (hyphen in domain)
        features['Prefix_Suffix'] = -1 if '-' in domain else 1

        # 7. having_Sub_Domain
        dots = tldextract.extract(url)
        subdomain_count = dots.subdomain.count('.') + 1 if dots.subdomain else 0
        if subdomain_count == 0:
            features['having_Sub_Domain'] = 1
        elif subdomain_count == 1:
            features['having_Sub_Domain'] = 0
        else:
            features['having_Sub_Domain'] = -1

        # 8. SSLfinal_State: check https and certificate issuer basic check
        if url.startswith('https'):
            # try check certificate issuer by performing request and reading cert via requests? requests doesn't expose cert easily.
            # Simpler: treat https as safer, but check if certificate valid via requests TTL (best-effort)
            r = safe_request(url)
            if r and r.status_code < 400:
                features['SSLfinal_State'] = 1
            else:
                features['SSLfinal_State'] = -1
        else:
            features['SSLfinal_State'] = -1

        # 9. Domain_registeration_length (short registration suspicious)
        try:
            exp = w.expiration_date
            if isinstance(exp, list): exp = exp[0]
            if exp:
                days_left = (exp - datetime.datetime.now()).days
                features['Domain_registeration_length'] = 1 if days_left > 365 else -1
            else:
                features['Domain_registeration_length'] = -1
        except Exception:
            features['Domain_registeration_length'] = -1

        # 10. Favicon: check if favicon exists and is from same domain
        try:
            r = safe_request(url)
            if r:
                soup = BeautifulSoup(r.text, 'html.parser')
                icon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
                if icon and icon.get('href'):
                    ico = icon.get('href')
                    ico_parsed = urlparse(ico)
                    if ico_parsed.netloc == '' or ico_parsed.netloc.lower().endswith(domain):
                        features['Favicon'] = 1
                    else:
                        features['Favicon'] = -1
                else:
                    features['Favicon'] = -1
            else:
                features['Favicon'] = -1
        except:
            features['Favicon'] = -1

        # 11. port: if non-standard port present
        try:
            if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
                features['port'] = -1
            else:
                features['port'] = 1
        except:
            features['port'] = 1

        # 12. HTTPS_token: presence of 'https' in domain (sneaky)
        features['HTTPS_token'] = -1 if 'https' in domain else 1

        # 13. Request_URL: fraction of page resources from external domains
        try:
            r = safe_request(url)
            if r:
                soup = BeautifulSoup(r.text, 'html.parser')
                resources = []
                # images, scripts, links
                for tag, attr in [('img','src'), ('script','src'), ('link','href')]:
                    for t in soup.find_all(tag):
                        v = t.get(attr)
                        if v:
                            resources.append(v)
                ext = 0
                total = 0
                for res in resources:
                    total += 1
                    parsed_res = urlparse(res)
                    res_domain = parsed_res.netloc
                    if res_domain and not res_domain.endswith(hostname):
                        ext += 1
                if total == 0:
                    features['Request_URL'] = 1
                else:
                    ratio = ext / total
                    features['Request_URL'] = -1 if ratio > 0.5 else 1
            else:
                features['Request_URL'] = -1
        except:
            features['Request_URL'] = -1

        # 14. URL_of_Anchor: fraction of anchors pointing to other domains
        try:
            if r:
                anchors = [a.get('href') for a in soup.find_all('a') if a.get('href')]
                total_a = len(anchors)
                external = 0
                for a in anchors:
                    parsed_a = urlparse(a)
                    if parsed_a.netloc and not parsed_a.netloc.endswith(hostname):
                        external += 1
                if total_a == 0:
                    features['URL_of_Anchor'] = 1
                else:
                    features['URL_of_Anchor'] = -1 if (external/total_a) > 0.5 else 1
            else:
                features['URL_of_Anchor'] = -1
        except:
            features['URL_of_Anchor'] = -1

        # 15. Links_in_tags: fraction of links in tags <same logic>
        try:
            links = soup.find_all(['link','a','area'])
            total_links = len(links)
            ext = sum(1 for l in links if l.get('href') and urlparse(l.get('href')).netloc and not urlparse(l.get('href')).netloc.endswith(hostname))
            features['Links_in_tags'] = -1 if total_links and (ext/total_links) > 0.5 else 1
        except:
            features['Links_in_tags'] = -1

        # 16. SFH (Server Form Handler) - check form action domain
        try:
            forms = soup.find_all('form')
            if forms:
                external_action = 0
                for f in forms:
                    a = f.get('action')
                    if a:
                        pa = urlparse(a)
                        if pa.netloc and not pa.netloc.endswith(hostname):
                            external_action += 1
                features['SFH'] = -1 if external_action > 0 else 1
            else:
                features['SFH'] = 1
        except:
            features['SFH'] = -1

        # 17. Submitting_to_email
        features['Submitting_to_email'] = -1 if any('mailto:' in a.get('href','') for a in soup.find_all('a')) else 1

        # 18. Abnormal_URL (hostname mismatch)
        features['Abnormal_URL'] = -1 if hostname not in domain else 1

        # 19. Redirect (history length)
        try:
            if r:
                features['Redirect'] = -1 if len(r.history) > 2 else 1
            else:
                features['Redirect'] = -1
        except:
            features['Redirect'] = -1

        # 20. on_mouseover (check JS events)
        try:
            js_on = bool(re.search(r'onmouseover\s*=', r.text, re.I)) if r else False
            features['on_mouseover'] = -1 if js_on else 1
        except:
            features['on_mouseover'] = -1

        # 21. RightClick
        try:
            rc_disabled = bool(re.search(r'contextmenu', r.text, re.I)) if r else False
            features['RightClick'] = -1 if rc_disabled else 1
        except:
            features['RightClick'] = -1

        # 22. popUpWidnow (check window.open in JS)
        try:
            pop = bool(re.search(r'window\.open', r.text, re.I)) if r else False
            features['popUpWidnow'] = -1 if pop else 1
        except:
            features['popUpWidnow'] = -1

        # 23. Iframe
        try:
            if r and soup.find('iframe'):
                features['Iframe'] = -1
            else:
                features['Iframe'] = 1
        except:
            features['Iframe'] = -1

        # 24. age_of_domain (use creation_date)
        try:
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            if creation:
                age_days = (datetime.datetime.now() - creation).days
                features['age_of_domain'] = 1 if age_days > 180 else -1
            else:
                features['age_of_domain'] = -1
        except:
            features['age_of_domain'] = -1

        # 25. DNSRecord
        try:
            socket.gethostbyname(domain)
            features['DNSRecord'] = 1
        except:
            features['DNSRecord'] = -1

        # 26. web_traffic (placeholder: if site responds quickly treat as likely real)
        try:
            features['web_traffic'] = 1 if r and r.status_code == 200 else -1
        except:
            features['web_traffic'] = -1

        # 27. Page_Rank (placeholder)
        features['Page_Rank'] = 1

        # 28. Google_Index (placeholder - expensive to check)
        features['Google_Index'] = 1

        # 29. Links_pointing_to_page (placeholder)
        features['Links_pointing_to_page'] = -1 if features['age_of_domain'] == -1 else 1

        # 30. Statistical_report (placeholder)
        # as a proxy, use domain entropy: high entropy suspicious
        ent = domain_entropy(hostname)
        features['Statistical_report'] = -1 if ent > 3.5 else 1

        # final sanity: ensure all feature keys present
        expected = ['having_IPhaving_IP_Address','URLURL_Length','Shortining_Service','having_At_Symbol','double_slash_redirecting','Prefix_Suffix',
                    'having_Sub_Domain','SSLfinal_State','Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL','URL_of_Anchor',
                    'Links_in_tags','SFH','Submitting_to_email','Abnormal_URL','Redirect','on_mouseover','RightClick','popUpWidnow','Iframe',
                    'age_of_domain','DNSRecord','web_traffic','Page_Rank','Google_Index','Links_pointing_to_page','Statistical_report']
        for k in expected:
            if k not in features:
                features[k] = -1

        return features

    except Exception as e:
        # if anything fatal happens, return conservative suspicious vector
        print("Feature extraction error:", e)
        return {k: -1 for k in [
            'having_IPhaving_IP_Address','URLURL_Length','Shortining_Service','having_At_Symbol','double_slash_redirecting','Prefix_Suffix',
            'having_Sub_Domain','SSLfinal_State','Domain_registeration_length','Favicon','port','HTTPS_token','Request_URL','URL_of_Anchor',
            'Links_in_tags','SFH','Submitting_to_email','Abnormal_URL','Redirect','on_mouseover','RightClick','popUpWidnow','Iframe',
            'age_of_domain','DNSRecord','web_traffic','Page_Rank','Google_Index','Links_pointing_to_page','Statistical_report'
        ]}
