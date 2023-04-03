import regex    
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
from datetime import datetime
import time
import requests
import favicon
import re
import OpenSSL
from dateutil.relativedelta import relativedelta
from googlesearch import search
url_sample = 'https://github.com/TanayBhadula/phishing-website-detection/blob/main/Phishing%20website%20detection%20using%20UI/inputScript.py'


# -1 phishing
# 0 suspicious
# 1 legitimate

# 1.1 Address Bar based Features
# 1. Using the IP Address
def url_ip_address(url):
    match=regex.search(
    '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url) #Ipv6
    if match:
        return -1
    else:
        return 1

# 2. Long URL to Hide the Suspicious Part
def url_length(url):
    if len(url) < 54:
        return 1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return -1

# 3. Using URL Shortening Services “TinyURL”
def url_shortening(url):
    match = regex.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return -1
    else:
        return 1
    
# 4. URL's having "@" Symbol
def url_at_symbol(url):
    at_symbol = regex.findall(r'@', url)
    if len(at_symbol) == 0:
        return 1
    else:
        return -1

# 5. Redirecting using "//"
def url_double_slash_redirect(url):
    for i in range(8, len(url)):
        if url[i] == '/' and url[i-1] == '/':
            return -1
    return 1

# 6. Adding Prefix or Suffix Separated by (-) to the Domain
def url_prefix_suffix(url):
    index = url.find("://")
    split_url = url[index+3:]
    index = split_url.find("/")
    split_url = split_url[:index]
    index = split_url.find("-")
    if index!=-1:
        return -1
    return 1
    
# 7. Sub Domain and Multi Sub Domains
def url_have_sub_multi_domain(sub_domain):
    if sub_domain.count('.') <= 1:
        return 1
    elif sub_domain.count('.') <= 2:
        return 0
    else:
        return -1

# 8. HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
def SSLfinal_State(url):
    list_of_trsuted_issuer = ['geotrust', 'godaddy', 'network', 'thawte', 'comodo',
                                'doster', 'verisign', 'rapidssl', 'sectigo', 'certum',
                                'google', 'amazon', 'facebook', 'globalsign','symantec']
    try:
        r = requests.get(url)
        real_url = r.url
        index = real_url.find("://")
        split_url = real_url[index+3:]
        index = split_url.find("/")
        hostname = split_url[:index]
        ctx = ssl.create_default_context()
        
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])['organizationName']
        issuer = re.sub(r'[^\w\s]', ' ', issuer)
        issuer = issuer.lower()
        issuer = issuer.split(' ')[0]
        
        if re.match('https://',real_url) is not None and issuer in list_of_trsuted_issuer:
            return 1
        elif re.match('https://',real_url):
            return 0
        else:
            return -1
    except Exception as e:
        return -1
    
# 9. Domain Registration Length
def url_registration_length(whois_response):
    if whois_response == -1:
        return -1
    else:
        try:
            expiration_date = whois_response.expiration_date if whois_response.expiration_date is not list else whois_response.expiration_date[0]
            creation_date = whois_response.creation_date if whois_response.creation_date is not list else whois_response.creation_date[0]
            print(expiration_date)
            print(creation_date)
            if expiration_date > creation_date + relativedelta(months=+12):
                return 1
            else:
                return -1
        except:
            return -1

# 10. Favicon
def check_favicon(url, url_domain):
    try:
        icons = favicon.get(url)
        icon = icons[0]
        _, domain, _ = extract(icon.url)
        fav_domain = domain
        if url_domain == fav_domain:
            return 1
        else:
            return -1
    except:
        return -1
    
# 11. Using Non-Standard Port
def check_port(url):
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        80: 'HTTP',
        443: 'HTTPS',
        445: 'SMB',
        1433: 'MSSQL',
        1521: 'ORACLE',
        3306: 'MySQL',
        3389: 'Remote Desktop'
    }

    preferred_status = {
        'FTP'           : 'Close',
        'SSH'           : 'Close',
        'Telnet'        : 'Close',
        'HTTP'          : 'Open',
        'HTTPS'         : 'Open',
        'SMB'           : 'Close',
        'MSSQL'         : 'Close',
        'ORACLE'        : 'Close',
        'MySQL'         : 'Close',
        'Remote Desktop': 'Close'
    }
    index = url.find("://")
    split_url = url[index+3:]
    index = split_url.find("/")
    hostname = split_url[:index]
    print(hostname)
    counter = 0
    for port, service in services.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect(('www.google.com', port))
            s.close()
            status = 'Open'
        except:
            status = 'Close'
        if status == preferred_status[service]:
            counter += 1
    if counter == 10:
        return 1
    else:
        return -1
    
# 12. The Existence of “HTTPS” Token in the Domain Part of the URL
def HTTPS_token(url):
    match=re.search('https://|http://',url)
    if (match.start(0)==0):
        url=url[match.end(0):]
    match=re.search('http|https',url)
    if match:
        return -1
    else:
        return 1

# Abnormal Based Features

# 13. Request URL
def check_request_url(web_domain, soup):
    try:
        linked_to_same = 0

        # For Images
        imgs = soup.findAll('img', src=True)
        total = len(imgs)

        for img in imgs:
            _, domain, _ = extract(img['src'])
            img_domain = domain
            if web_domain == img_domain or img_domain == '':
                linked_to_same += 1
        
        # For audio
        audios = soup.findAll('audio', src=True)
        total += len(audios)
        for audio in audios:
            _, domain, _ = extract(audio['src'])
            audio_domain = domain
            if web_domain == audio_domain or audio_domain == '':
                linked_to_same += 1
        
        # for embed
        embeds = soup.findAll('embed', src=True)
        total += len(audios)
        for embed in embeds:
            _, domain, _ = extract(embed['src'])
            embed_domain = domain
            if web_domain == embed_domain or embed_domain == '':
                linked_to_same += 1
        
        # for iframe
        iframes = soup.findAll('iframe', src=True)
        total += len(iframes)
        for iframe in iframes:
            _, domain, _ = extract(iframe['src'])
            iframe_domain = domain
            if web_domain == iframe_domain or iframe_domain == '':
                linked_to_same += 1

        linked_outside = total - linked_to_same
        avg = 0
        if total != 0:
            avg = linked_outside/total
        if avg < 0.22:
            return 1
        elif avg >= 0.22 and avg <= 0.61:
            return 0
        else:
            return -1
    except:
        return -1

# 14. URL of Anchor
def check_url_anchor(web_domain, soup):
    try:
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        for anchor in anchors:
            _, domain, _ = extract(anchor['href'])
            anchor_domain = domain
            if web_domain == anchor_domain or anchor_domain == '':
                linked_to_same += 1
                
        linked_outside = total - linked_to_same        
        avg = 0
        if total != 0:
            avg = linked_outside/total
        if avg < 0.31:
            return 1
        elif avg >= 0.31 and avg <= 0.67:
            return 0
        else:
            return -1
    except:
        return -1
    
# 15. Links in <Meta>, <Script> and <Link> tags
def links_in_tag(web_domain, soup):
    try:
        # link
        links = soup.findAll('link', href=True)
        total = len(links)
        linked_to_same = 0
        for link in links:
            _, domain, _ = extract(link['href'])
            link_domain = domain
            if web_domain == link_domain or link_domain == '':
                linked_to_same += 1
        
        # script
        scripts = soup.findAll('script', src=True)
        total += len(links)
        for script in scripts:
            _, domain, _ = extract(script['src'])
            script_domain = domain
            if web_domain == script_domain or script_domain == '':
                linked_to_same += 1
                
        linked_outside = total - linked_to_same        
        avg = 0
        if total != 0:
            avg = linked_outside/total
        if avg < 0.17:
            return 1
        elif avg >= 0.17 and avg <= 0.81:
            return 0
        else:
            return -1
    except:
        return -1

# 16. Server Form Handler (SFH)
def check_sfh_handle(web_domain, soup):
    try:
        forms = soup.findAll('form', action=True)
        if len(forms) == 0:
            return 1
        else:
            for form in forms:
                _, domain, _ = extract(form['action'])
                form_domain = domain
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif web_domain != form_domain and form_domain != "":
                    return 0
            return 1
    except:
        return -1
    
# 17. Submitting Information to Email
def submitting_to_mail(soup):
    try:
        
        form_component = str(soup.form)
        idx = form_component.find("mail()")
        if idx == -1:
            idx = form_component.find("mailto:")
        if idx == -1:
            return 1
        return -1
    except:
        return -1

# 18. Abnormal URL
def abnormal_url(url, whois_response):
    try:
        hostname=whois_response.domain_name[0].lower()
        match=re.search(hostname, url)
        if match:
            return 1
        else:
            return -1
    except:
        return -1

# HTML and Javascript based Features
# 19. Website Forwarding
def redirecting(response):
    try:
        if len(response.history) <= 1:
            return 1
        elif 2 <= len(response.history) <= 4:
            return 0
        else:
            return -1 
    except:
        return -1
    
# 20. Status Bar Customization
def check_statusbar(soup):
    try:
        no_of_script = 0
        for _ in soup.find_all(onmouseover=True):
            no_of_script += 1
        
        if no_of_script == 0:
            return 1
        else:
            return -1
    except:
        return -1

# 21. Disabling Right Click
def check_right_click(response, soup):
    try:
        if soup.find_all('script', mousedown=True) or re.findall(r"event.button ?== ?2", response.text):
            return -1
        else:
            return 1
    except:
        return -1

# 22. Using Pop-up Window
def check_popup_window(response):
    try:
        if regex.findall(r"alert\(", response.text):
            return 1
        else:
            return -1
    except:
        return -1

# 23. IFrame Redirection
def check_iframe(response):
    try:
        if regex.findall(r"[<iframe>|<frameBorder>]", response.text):
            return -1
        else:
            return 1
    except:
        return -1

# Domain based Features
# 24. Age of Domain
def age_of_domain(whois_response):
    try:
        creation_date = whois_response.creation_date if whois_response.creation_date is not list else whois_response.creation_date[0]
        if datetime.now() > creation_date + relativedelta(months=+6):
            return 1
        else:
            return -1
    except:
        return -1

# 25. DNS Record
def check_dns_record(whois_response):
    if whois_response == -1:
        return -1
    else:
        return 1

# 26. Web Traffic (Alexa Down)
def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
        if (rank < 100000):
            return 1
        else:
            return 0
    except :
        return -1
    
# 27. page rank (30 detik sekali)
def page_rank(domain, suffix):
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": f'{domain}.{suffix}'
    })
    page_rank = 0
    try:
        page_rank = int(re.findall(r"<b>Google PageRank:</b></font> <font color=\"#000099\"><b>([0-9]+)/10</b>", rank_checker_response.text)[0])
    except:
        return -1
    
    if page_rank <=2 :
        return -1
    else:
        return 1

# 28. google index
def google_index(url):
    try:
        subDomain, domain, suffix = extract(url)
        a=domain + '.' + suffix
        query = url
        for j in search(query, tld=suffix, num=5, stop=5):
            subDomain, domain, suffix = extract(j)
            b=domain + '.' + suffix
            if a == b:
                return 1
        return -1
    except:
        return -1

# 29. Number of Links Pointing to Page
def links_pointing_to_page(soup):
    try:
        count = 0
        for link in soup.find_all('a'):
            count += 1
        if count>=2:
            return 1
        elif 0 < count <= 2:
            return 0
        else:
            return -1
    except:
        return -1

# 30. statistical reports
def statistical_report(url):
    url_match = regex.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    _, domain, suffix = extract(url)
    domain = f'{domain}.{suffix}'
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = regex.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            return -1
        elif ip_match:
            return -1
        else:
            return 1
    except:
        return -1
        
        
def feature_extractor(url):
    if not regex.match(r"^https?", url):
        url = "http://" + url
        
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -1
    
    try:
        whois_response = whois.whois(url)
    except:
        whois_response = -1
    
    web_subdomain, web_domain, web_suffix = extract(url)
    
    features = []
    features.append(url_ip_address(url))
    features.append(url_length(url))
    features.append(url_shortening(url))
    features.append(url_at_symbol(url))
    features.append(url_double_slash_redirect(url))
    features.append(url_prefix_suffix(url))
    features.append(url_have_sub_multi_domain(web_subdomain))
    features.append(SSLfinal_State(url))
    features.append(url_registration_length(whois_response))
    features.append(check_favicon(url, web_domain))
    features.append(check_port(url))
    features.append(HTTPS_token(url))
    features.append(check_request_url(web_domain, soup))
    features.append(check_url_anchor(web_domain, soup))
    features.append(links_in_tag(web_domain, soup))
    features.append(check_sfh_handle(web_domain, soup))
    features.append(submitting_to_mail(soup))
    features.append(abnormal_url(url, whois_response))
    features.append(redirecting(response))
    features.append(check_statusbar(soup))
    features.append(check_right_click(response, soup))
    features.append(check_popup_window(response))
    features.append(check_iframe(response))
    features.append(age_of_domain(whois_response))
    features.append(check_dns_record(whois_response))
    features.append(web_traffic(url)) # GAGAL
    features.append(page_rank(web_domain, web_suffix))
    features.append(google_index(url))
    features.append(links_pointing_to_page(soup))
    features.append(statistical_report(url))
    return features

list_sites = [
    'http://widiba-it.redirectme.net/',
    'https://widiba-it.redirectme.net/',
    'https://citi.com.retrowgroup.com/',
    'https://test.unri.ac.id/wp-content/plugins/ubh/vercheck/flixnet/Login.php?sessionID=OdTZWHC6Ezo7jHXbMJrB43RnAc0kHPZjQfTtNJfiR1Lq1OC9aeTy7FkxC8PtphvwDlfw6eVlk5wAQlNkRENmV414QKDF3yAOm5MP',
    'https://spacecids.com/connect/assets/js/drainer/ms-2.js',
    'https://boursosecurite.com/deblocage/step1.php?id=71777304',
    'https://goonline-bbnppraillibass.top/',
    'https://usinedigitale.org/wp-content/upgrade/doc.html#WTJWeWRFQnVZVzFsYzJocFpXeGtMbTVsZEE9PQ==&redirect=no_url',
    'https://www.gkkai.com/skkskmskmskskmk.html',
    'https://sella-group.mysella.online/main/index.php'
    
]
# waktu = []
# for i in list_sites:
#     start_time = time.time()
#     print(feature_extractor(i))
#     end_time = time.time()
#     elapsed_time = end_time - start_time
#     waktu.append(elapsed_time)
# print("Waktu yang dibutuhkan:", sum(waktu)/10, "detik")
# print("Waktu yang dibutuhkan:", sum(waktu)/60, "detik")
# print("Waktu yang dibutuhkan:", sum(waktu), "detik")
# Waktu yang dibutuhkan: 24.07648355960846 detik
# Waktu yang dibutuhkan: 4.012747259934743 detik
# Waktu yang dibutuhkan: 240.7648355960846 detik
# print('1.  ip_address: ', url_ip_address(url_sample))
# print('2.  url_length: ', url_length(url_sample))
# print('3.  url_shortening: ', url_shortening(url_sample))
# print('4.  url_at_symbol: ', url_at_symbol(url_sample))
# print('5.  url_double_slash_redirect: ', url_double_slash_redirect(url_sample))
# print('6.  url_prefix_suffix: ', url_prefix_suffix(url_sample))
# print('7.  url_have_sub_multi_domain', url_have_sub_multi_domain(url_sample))
# print('8.  url_check_SSL: ', SSLfinal_State(url_sample))
# res = whois.whois('https://setupad.com/blog/what-is-ssl/')

# print('9.  url_registration_length: ', url_registration_length(res))
# print('10. check_favicon: ', check_favicon(url_sample))
# print('11. check_port: ', check_port(url_sample))
# print('12. HTTPS_token: ', HTTPS_token(url_sample))
# print('13. check_request_url: ', check_request_url(url_sample))
# print('14. check_url_anchor: ', check_url_anchor(url_sample))
# print('15. links_in_tag: ', links_in_tag(url_sample))
# print('16. check_sfh_handle: ', check_sfh_handle(url_sample))
# print('17. submitting_to_mail: ', submitting_to_mail(url_sample))
# print('18. abnormal_url: ', abnormal_url(url_sample))
# print('19. redirecting: ', redirecting(url_sample))
# print('20. check_statusbar: ', check_statusbar(url_sample))
# print('21. check_right_click: ', check_right_click(url_sample))
# print('22. check_popup_window: ', check_popup_window(url_sample))
# print('23. check_iframe: ', check_iframe(url_sample))
# print('24. age_of_domain: ', age_of_domain(res))
# print('25. check_dns_record: ', check_dns_record(url_sample))
# print('26. web_traffic: ', web_traffic(url_sample))
# print('27. page_rank: ', page_rank(url_sample))
# print('28. google_index: ', google_index(url_sample))
# print('29. links_pointing_to_page: ', links_pointing_to_page(url_sample))
# print('30. statistical_report: ', statistical_report(url_sample))

