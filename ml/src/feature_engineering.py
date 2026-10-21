FEATURE_SCHEMA = [
    'url_length',
    'hostname_length',
    'subdomain_count',
    'dot_count',
    'digit_count',
    'suspicious_char_count',
    'has_ip_address',
    'uses_http',
    'has_punycode',
    'suspicious_keyword_count',
    'hostname_entropy',
    'brand_domain_mismatch',
    'page_title_mismatch',
    'form_count',
    'has_password_input',
    'credential_field_count',
    'cross_domain_form_action',
    'hidden_field_count',
    'form_action_is_empty',
    'obfuscated_script_score',
    'hidden_iframe_count',
    'external_script_count',
    'meta_refresh_count',
    'brand_name_in_title',
    'brand_name_in_visible_text',
    'brand_name_in_url',
    'has_unusual_port',
    'domain_registration_age_days',
    'credential_submission_script',
]

FEATURE_EXPLANATIONS = {
    'cross_domain_form_action': 'The form sends data to a different domain than the page you are viewing.',
    'has_password_input': 'This page requests a password or login credential.',
    'uses_http': 'This page is using HTTP instead of HTTPS.',
    'has_punycode': 'This address contains a lookalike or punycode-style hostname.',
    'brand_domain_mismatch': 'The page claims to be a trusted brand, but the website address does not match the brand domain.'
}


def normalize_url(url: str) -> str:
    """Add the browser's default HTTPS scheme when a dataset omits one."""
    cleaned = url.strip()
    if '://' not in cleaned:
        return f'https://{cleaned}'
    return cleaned


def build_feature_row(url: str, title: str = '', html: str = '') -> dict:
    """Build browser-compatible features from URL and optional page metadata."""
    from html.parser import HTMLParser
    from ipaddress import ip_address
    from math import log2
    from urllib.parse import urljoin, urlsplit

    url = normalize_url(url)
    parsed = urlsplit(url)
    hostname = (parsed.hostname or '').lower()
    title_text = title.lower()
    page_text = html.lower()
    suspicious_keywords = [
        'login', 'verify', 'secure', 'account', 'update', 'wallet', 'bank',
        'signin', 'payment', 'confirm'
    ]
    brands = ['google', 'microsoft', 'apple', 'paypal', 'amazon', 'icici', 'hdfc', 'sbi', 'axis']
    keyword_count = sum(
        1 for keyword in suspicious_keywords
        if keyword in url.lower() or keyword in hostname
    )
    brand_in_title = int(any(brand in title_text for brand in brands))
    brand_in_url = int(any(brand in url.lower() for brand in brands))
    brand_domain_mismatch = int(
        any(brand in (title_text + ' ' + url.lower()) for brand in brands)
        and not any(brand in hostname for brand in brands)
    )

    hostname_without_tld = hostname.rsplit('.', 1)[0] if '.' in hostname else hostname
    subdomain_count = max(0, len(hostname.split('.')) - 2) if hostname else 0
    hostname_characters = hostname.replace('.', '')
    counts = {character: hostname_characters.count(character) for character in set(hostname_characters)}
    entropy = 0.0
    if hostname_characters:
        entropy = -sum((count / len(hostname_characters)) * log2(count / len(hostname_characters)) for count in counts.values())

    try:
        has_ip_address = int(ip_address(hostname) is not None)
    except ValueError:
        has_ip_address = 0

    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None

    class PageParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = 0
            self.password_inputs = 0
            self.credential_inputs = 0
            self.hidden_inputs = 0
            self.external_scripts = 0
            self.hidden_iframes = 0
            self.form_actions = []
            self.empty_form_actions = 0
            self.hidden_stack = []
            self.ignored_stack = []
            self.visible_text_parts = []

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            self.ignored_stack.append(tag in {'script', 'style', 'noscript', 'template'})
            self.hidden_stack.append(
                attributes.get('hidden') is not None
                or 'display:none' in (attributes.get('style') or '').lower().replace(' ', '')
                or 'visibility:hidden' in (attributes.get('style') or '').lower().replace(' ', '')
            )
            if tag == 'form':
                self.forms += 1
                action = (attributes.get('action') or '').strip()
                if action:
                    self.form_actions.append(action)
                else:
                    self.empty_form_actions += 1
            if tag == 'input':
                input_type = attributes.get('type', '').lower()
                input_name = attributes.get('name', '').lower()
                if input_type == 'password':
                    self.password_inputs += 1
                if input_type == 'hidden':
                    self.hidden_inputs += 1
                if input_type == 'password' or any(term in input_name for term in ['password', 'otp', 'card', 'cvv', 'email', 'aadhaar', 'pan', 'wallet']):
                    self.credential_inputs += 1
            if tag == 'script' and attributes.get('src'):
                self.external_scripts += 1
            if tag == 'iframe':
                style = (attributes.get('style') or '').lower().replace(' ', '')
                if (
                    attributes.get('hidden') is not None
                    or 'display:none' in style
                    or 'visibility:hidden' in style
                    or attributes.get('width') == '0'
                    or attributes.get('height') == '0'
                ):
                    self.hidden_iframes += 1

        def handle_endtag(self, tag):
            if self.ignored_stack:
                self.ignored_stack.pop()
            if self.hidden_stack:
                self.hidden_stack.pop()

        def handle_data(self, data):
            if not any(self.ignored_stack) and not any(self.hidden_stack):
                self.visible_text_parts.append(data)

    parser = PageParser()
    parser.feed(html)
    visible_text = ' '.join(parser.visible_text_parts).lower()
    brand_in_text = int(any(brand in visible_text for brand in brands))
    form_action_hosts = []
    for action in parser.form_actions:
        action_host = urlsplit(urljoin(url, action)).hostname
        if action_host:
            form_action_hosts.append(action_host.lower())

    return {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'subdomain_count': subdomain_count,
        'dot_count': hostname.count('.') + url.count('.'),
        'digit_count': sum(character.isdigit() for character in hostname + parsed.path),
        'suspicious_char_count': sum(url.count(character) for character in ['@', '%']) + int('--' in hostname) * 2,
        'has_ip_address': has_ip_address,
        'uses_http': int(parsed.scheme.lower() == 'http'),
        'has_punycode': int('xn--' in hostname),
        'suspicious_keyword_count': keyword_count,
        'hostname_entropy': round(entropy, 2),
        'brand_domain_mismatch': brand_domain_mismatch,
        'page_title_mismatch': int(bool(title_text and hostname_without_tld and hostname_without_tld not in title_text)),
        'form_count': parser.forms,
        'has_password_input': int(parser.password_inputs > 0),
        'credential_field_count': parser.credential_inputs,
        'cross_domain_form_action': int(any(host != hostname for host in form_action_hosts)),
        'hidden_field_count': parser.hidden_inputs,
        'form_action_is_empty': int(parser.empty_form_actions > 0),
        'obfuscated_script_score': float(min(
            1.0,
            sum(0.25 for marker in ['eval(', 'atob(', 'fromcharcode(', 'document.write(', 'function('] if marker in page_text),
        )),
        'hidden_iframe_count': parser.hidden_iframes,
        'external_script_count': parser.external_scripts,
        'meta_refresh_count': page_text.count('http-equiv="refresh"') + page_text.count("http-equiv='refresh'"),
        'brand_name_in_title': brand_in_title,
        'brand_name_in_visible_text': brand_in_text,
        'brand_name_in_url': brand_in_url,
        'has_unusual_port': int(bool(parsed_port and parsed_port not in {80, 443})),
        'domain_registration_age_days': 0,
        'credential_submission_script': int(
            parser.credential_inputs > 0
            and any(marker in page_text for marker in ['fetch(', 'xmlhttprequest', 'sendbeacon', 'addeventlistener'])
        ),
    }


def validate_feature_row(row: dict) -> None:
    """Raise an error when a training row does not match the browser schema."""
    missing = [name for name in FEATURE_SCHEMA if name not in row]
    extra = [name for name in row if name not in FEATURE_SCHEMA]
    if missing or extra:
        raise ValueError(f'Feature schema mismatch: missing={missing}, extra={extra}')
