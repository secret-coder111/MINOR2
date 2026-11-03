"""Versioned static HTML features; never executes scripts or reads field values.

Captured browser features are preferable for DOM training: this static fallback
cannot reproduce external CSS, rendered bounds, shadow DOM or page JavaScript.
"""
from __future__ import annotations

import ipaddress
import math
import re
import hashlib
from pathlib import Path
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from dataset_contract import normalize_url, registrable_domain

FEATURE_SCHEMA_VERSION = '0.2.0'
POLICY_VERSION = '0.5.0'
FEATURE_SCHEMA = [
    'url_length', 'hostname_length', 'subdomain_count', 'dot_count', 'digit_count',
    'suspicious_char_count', 'has_ip_address', 'uses_http', 'has_punycode',
    'suspicious_keyword_count', 'hostname_entropy', 'brand_domain_mismatch',
    'page_title_mismatch', 'form_count', 'has_password_input', 'credential_field_count',
    'cross_domain_form_action', 'hidden_field_count', 'form_action_is_empty',
    'obfuscated_script_score', 'hidden_iframe_count', 'external_script_count',
    'meta_refresh_count', 'brand_name_in_title', 'brand_name_in_visible_text',
    'brand_name_in_url', 'has_unusual_port', 'domain_registration_age_days',
    'credential_submission_script',
]
# Title/brand mismatch and registration age are not observed in raw URL feeds.
URL_FEATURE_SCHEMA = [name for name in FEATURE_SCHEMA if name in {
    'url_length', 'hostname_length', 'subdomain_count', 'dot_count', 'digit_count',
    'suspicious_char_count', 'has_ip_address', 'uses_http', 'has_punycode',
    'suspicious_keyword_count', 'hostname_entropy', 'brand_name_in_url', 'has_unusual_port'}]
FEATURE_EXPLANATIONS = {
    'cross_domain_form_action': 'A credential form targets a different site.',
    'has_password_input': 'This page requests a password.',
    'uses_http': 'This page uses unencrypted HTTP.',
    'has_punycode': 'This address contains an internationalized hostname.',
    'brand_domain_mismatch': 'An identity claim does not match the claimed brand owner.',
}
BRAND_DOMAINS = {
    # Reviewed against https://www.google.com/supported_domains on 2026-10-25.
    'google': ('''
        google.com google.ad google.ae google.com.af google.com.ag google.al google.am google.co.ao
        google.com.ar google.as google.at google.com.au google.az google.ba google.com.bd google.be
        google.bf google.bg google.com.bh google.bi google.bj google.com.bn google.com.bo google.com.br
        google.bs google.bt google.co.bw google.by google.com.bz google.ca google.cd google.cf
        google.cg google.ch google.ci google.co.ck google.cl google.cm google.cn google.com.co
        google.co.cr google.com.cu google.cv google.com.cy google.cz google.de google.dj google.dk
        google.dm google.com.do google.dz google.com.ec google.ee google.com.eg google.es google.com.et
        google.fi google.com.fj google.fm google.fr google.ga google.ge google.gg google.com.gh
        google.com.gi google.gl google.gm google.gr google.com.gt google.gy google.com.hk google.hn
        google.hr google.ht google.hu google.co.id google.ie google.co.il google.im google.co.in
        google.iq google.is google.it google.je google.com.jm google.jo google.co.jp google.co.ke
        google.com.kh google.ki google.kg google.co.kr google.com.kw google.kz google.la google.com.lb
        google.li google.lk google.co.ls google.lt google.lu google.lv google.com.ly google.co.ma
        google.md google.me google.mg google.mk google.ml google.com.mm google.mn google.com.mt
        google.mu google.mv google.mw google.com.mx google.com.my google.co.mz google.com.na google.com.ng
        google.com.ni google.ne google.nl google.no google.com.np google.nr google.nu google.co.nz
        google.com.om google.com.pa google.com.pe google.com.pg google.com.ph google.com.pk google.pl google.pn
        google.com.pr google.ps google.pt google.com.py google.com.qa google.ro google.ru google.rw
        google.com.sa google.com.sb google.sc google.se google.com.sg google.sh google.si google.sk
        google.com.sl google.sn google.so google.sm google.sr google.st google.com.sv google.td
        google.tg google.co.th google.com.tj google.tl google.tm google.tn google.to google.com.tr
        google.tt google.com.tw google.co.tz google.com.ua google.co.ug google.co.uk google.com.uy google.co.uz
        google.com.vc google.co.ve google.co.vi google.com.vn google.vu google.ws google.rs google.co.za
        google.co.zm google.co.zw google.cat
    ''').split(),
    'microsoft': ['microsoft.com','live.com','office.com','microsoftonline.com'],
    'apple': ['apple.com','icloud.com'], 'paypal': ['paypal.com'],
    'amazon': ['amazon.com','amazon.in','amazon.co.uk','amazon.ca','amazon.com.au','amazon.de','amazon.fr','amazon.it','amazon.es','amazon.co.jp','amazon.com.mx','amazon.nl','amazon.sg','amazon.ae','amazon.sa'],
    # Bank-owned migration pages/redirects reviewed on 2026-10-25; mirrored in JS.
    'icici': ['icicibank.com','icici.bank.in'], 'hdfc': ['hdfcbank.com','hdfc.bank.in'],
    'sbi': ['sbi.co.in','onlinesbi.sbi','bank.sbi','sbi.bank.in'], 'axis': ['axisbank.com','axis.bank.in'],
}
BRAND_PATTERN = re.compile(r'(?:^|[^a-z0-9])(?:' + '|'.join(BRAND_DOMAINS) + r')(?=$|[^a-z0-9])', re.I)
PROVIDER_PATTERN = re.compile(r'\b(?:sign\s*in|log\s*in|continue|connect|register|authenticate)\s+(?:with|via|using)\s+(?:(?:a|an|the|your|my)\s+)?$', re.I)
AUTH_PATTERN = re.compile(r'(?:^|[^a-z])(?:login|signin|sign[\s_-]+in|log[\s_-]+in|auth|authenticate|authentication|account)(?:$|[^a-z])', re.I)
SENSITIVE_NAMES = {'password','passwd','pwd','passcode','otp','totp','cvv','cvc','pan','aadhaar','aadhar','wallet','seed','mnemonic','card','creditcard','cardnumber','cardno','seedphrase','recoveryphrase'}
IDENTITY_NAMES = {'email','username','userid','login'}
METADATA_CODE = re.compile(r'\b(?:otp|totp|one time (?:code|password)|verification code|authentication code|authenticator code|two factor(?: authentication)? code|security code)\b')
METADATA_SENSITIVE = re.compile(r'\b(?:password|passwd|pwd|passcode|otp|totp|cvv|cvc|aadhaar|aadhar)\b|\b(?:one time (?:code|password)|verification code|authentication code|authenticator code|two factor(?: authentication)? code|(?:credit )?card number|credit card|security code|card security code|expiration(?: date)?|expiry(?: date)?|seed phrase|recovery phrase|pan number)\b')
METADATA_PASSWORD = re.compile(r'\b(?:password|passwd|pwd)\b')
METADATA_IDENTITY = re.compile(r'\b(?:email|e mail|username|user name|userid|user id)\b')
SENSITIVE_AUTOCOMPLETE = {'current-password','new-password','one-time-code','cc-number','cc-csc','cc-exp','cc-exp-month','cc-exp-year'}
VOID_TAGS = {'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
INPUT_TYPES = {'hidden','text','search','tel','url','email','password','date','month','week',
    'time','datetime-local','number','range','color','checkbox','radio','file','submit','image','reset','button'}
POLICY_CONTEXT_KEYS = {'context_index','credential_context','has_password_input','credential_field_count',
    'sensitive_credential_field_count','identity_only_form','cross_domain_form_action',
    'credential_form_cross_site','credential_form_cross_origin','credential_target_unusual_port',
    'credential_target_ip','credential_transport_downgrade','credential_insecure_transport',
    'credential_form_method_get','credential_form_explicit_get','credential_form_native_get','credential_form_get_exposes_sensitive','credential_destination_unknown','credential_script_action','brand_domain_mismatch',
    'invalid_credential_action','form_action_is_empty','credential_brand_identity_claim','credential_brand_address_match'}
POLICY_EXTRA_KEYS = POLICY_CONTEXT_KEYS | {'password_form_count','credential_script_activity',
    'is_official_brand_domain','brand_identity_claim','frontpage_is_landing_page',
    'frontpage_has_credential_form','frontpage_suspicious_signal_count','iframe_scan_truncated',
    'suspicious_hosting','redirect_count','body_brand_identity_claim','body_brand_domain_mismatch','brand_address_deception'}


@lru_cache(maxsize=1)
def reviewed_brand_aliases() -> dict[str, set[str]]:
    """Exactly one finite reviewed visual replacement; mirrors browser policy.

    This is neither edit distance nor general Unicode/IDN classification.
    """
    substitutions = {'a':['4','\u0430'], 'c':['\u0441'], 'e':['3','\u0435'],
        'i':['1','\u0456'], 'l':['1','\u04cf'], 'o':['0','\u043e'],
        'p':['\u0440'], 'x':['\u0445'], 'y':['\u0443']}
    result = {}
    for brand, domains in BRAND_DOMAINS.items():
        aliases = set()
        for label in {brand, *(domain.split('.')[0] for domain in domains)}:
            for index, letter in enumerate(label):
                for replacement in substitutions.get(letter, []):
                    aliases.add((label[:index] + replacement + label[index+1:]).encode('idna').decode('ascii'))
        result[brand] = aliases
    return result


def brand_address_info(host: str) -> set[str]:
    """Reviewed deceptive brands at the actual ICANN/PRIVATE site boundary."""
    host = host.lower().rstrip('.')
    site = registrable_domain(host)
    label = site.split('.')[0] if site else ''
    result = set()
    for brand, domains in BRAND_DOMAINS.items():
        if any(host == domain or host.endswith('.'+domain) for domain in domains):
            continue
        embedded = any(host.startswith(domain+'.') or '.'+domain+'.' in host for domain in domains)
        if label in reviewed_brand_aliases()[brand] or embedded:
            result.add(brand)
    return result


def brand_address_policy_features(url: str, primary_identity: str = '', *, sensitive_context: bool = False) -> dict:
    """Numeric policy extras for reviewed address + already-bound primary UI.

    The caller must establish a rendered, non-editor, non-article primary
    heading tied to this sensitive submission flow. A title/body mention is
    not a substitute. Browser captures do that binding in dom-features.js;
    static build_feature_row intentionally remains only the 29-field schema.
    """
    host = (urlsplit(normalize_url(url)).hostname or '').rstrip('.')
    deceptive = brand_address_info(host) if host else set()
    pattern = r'^(?:(?:welcome to|sign in to|log in to|login to)\s+)?(' + '|'.join(BRAND_DOMAINS) + r')(?:\s+(?:account|accounts|login|sign in|log in|secure login|internet banking|online banking))?\s*[.!]?$'
    text = ' '.join(primary_identity.split())
    match = re.fullmatch(pattern, text, re.I) if sensitive_context and len(text) <= 100 else None
    return {'brand_address_deception': int(bool(deceptive)),
        'credential_brand_identity_claim': int(bool(match)),
        'credential_brand_address_match': int(bool(match and match[1].lower() in deceptive))}


def policy_source_hash() -> str:
    path = Path(__file__).resolve().parents[2] / 'extension/src/shared/model-policy.js'
    return hashlib.sha256(path.read_bytes()).hexdigest()


def filter_policy_features(features: dict) -> dict:
    """Whitelist structural numbers only; omit URLs, text and all field values."""
    names = set(FEATURE_SCHEMA) | POLICY_EXTRA_KEYS
    def finite_projection(value, keys):
        if not isinstance(value,dict):
            raise ValueError('Policy features/contexts must be objects')
        result = {name:number for name,number in value.items() if name in keys}
        if any(isinstance(number,bool) or not isinstance(number,(int,float)) or not math.isfinite(number) for number in result.values()):
            raise ValueError('Policy structural features must be finite numbers')
        return result
    result = finite_projection(features,names)
    contexts = features.get('credential_contexts')
    if not isinstance(contexts,list) or len(contexts) > 10000:
        raise ValueError('Captured per-submission credential_contexts are required (at most 10000)')
    required_context = {'credential_context','has_password_input','credential_field_count','sensitive_credential_field_count',
        'cross_domain_form_action','credential_target_ip','credential_transport_downgrade',
        'credential_insecure_transport','credential_form_method_get','credential_form_explicit_get',
        'credential_script_action','invalid_credential_action'}
    result['credential_contexts'] = []
    for context in contexts:
        projected = finite_projection(context,POLICY_CONTEXT_KEYS)
        if required_context - set(projected) or any(value < 0 for value in projected.values()):
            raise ValueError('Captured credential contexts are incomplete or negative')
        result['credential_contexts'].append(projected)
    return result


@lru_cache(maxsize=1)
def extractor_source_hash() -> str:
    root = Path(__file__).resolve().parents[2] / 'extension'
    names = ['src/shared/feature-schema.js', 'src/shared/constants.js', 'src/shared/public-suffix.js',
             'src/shared/domain-utils.js', 'src/shared/document-context.js', 'src/content/url-features.js',
             'src/content/form-features.js', 'src/content/dom-features.js']
    return hashlib.sha256('\n'.join((root/name).read_text(encoding='utf-8') for name in names).encode('utf-8')).hexdigest()


def is_loopback(host: str) -> bool:
    return host == 'localhost' or host.endswith('.localhost') or host == '::1' or host.startswith('127.')


def brand_info(host: str, title: str) -> tuple[int, int]:
    claimed, host_brands = [], []
    title = title.lower()
    for brand in BRAND_DOMAINS:
        matches = list(re.finditer(r'(?:^|[^a-z0-9])' + brand + r'(?=$|[^a-z0-9])', title))
        if any(not PROVIDER_PATTERN.search(title[:match.end()-len(brand)]) for match in matches):
            claimed.append(brand)
        if re.search(r'(?:^|[-.])' + brand + r'(?=$|[-.])', host):
            host_brands.append(brand)
            if brand not in claimed:
                claimed.append(brand)
    owns = lambda brand: any(host == domain or host.endswith('.' + domain) for domain in BRAND_DOMAINS[brand])
    return int(any(not owns(brand) for brand in claimed)), int(bool(host_brands))


def hidden_style(attrs: dict, ancestors: list[dict], inert: bool = False) -> bool:
    for attributes in [*ancestors, attrs]:
        if 'hidden' in attributes or (inert and 'inert' in attributes):
            return True
        style = re.sub(r'\s+', '', attributes.get('style') or '').lower()
        if 'display:none' in style or 'content-visibility:hidden' in style or re.search(r'(?:^|;)opacity:0(?:;|$)', style):
            return True
    for attributes in [attrs, *reversed(ancestors)]:
        match = re.search(r'(?:^|;)\s*visibility\s*:\s*([^;!]+)', attributes.get('style') or '', re.I)
        if match:
            return match.group(1).strip().lower() in {'hidden','collapse'}
    return False


def metadata_tokens(value: str) -> str:
    value = re.sub(r'([a-z])([A-Z])', r'\1 \2', value)
    value = re.sub(r'([a-zA-Z])([0-9])', r'\1 \2', value)
    value = re.sub(r'([0-9])([a-zA-Z])', r'\1 \2', value)
    return re.sub(r'[^a-z0-9]+', ' ', value.lower()).strip()


def control_type(node: dict) -> str:
    """Apply the browser's invalid/missing enumerated input/button defaults."""
    if node['tag'] == 'textarea':
        return 'textarea'
    if node['tag'] not in {'input', 'button'}:
        return 'text'
    declared = (node['attrs'].get('type') or '').lower()
    if node['tag'] == 'button':
        return declared if declared in {'submit','reset','button'} else 'submit'
    return declared if declared in INPUT_TYPES else 'text'


def executable_script(attrs: dict) -> bool:
    kind = (attrs.get('type') or '').strip().lower()
    return not kind or kind == 'module' or bool(re.fullmatch(
        r'(?:text|application)/(?:x-)?(?:java|ecma)script(?:1\.[0-5])?(?:\s*;.*)?', kind))


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.forms, self.inputs, self.submitters, self.scripts, self.frames = [], [], [], [], [], []
        self.script_srcs, self.meta_refresh, self.visible_text, self.base = [], 0, [], None
        self.nodes = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        ancestors = [node['attrs'] for node in self.stack]
        form = next((node for node in reversed(self.stack) if node['tag'] == 'form'), None)
        parent = self.stack[-1] if self.stack else None
        collapsed = any(ancestor['tag'] == 'dialog' and 'open' not in ancestor['attrs'] for ancestor in self.stack) or (tag == 'dialog' and 'open' not in attributes)
        for ancestor in self.stack:
            if ancestor['tag'] == 'details' and 'open' not in ancestor['attrs']:
                summary = ancestor.get('first_summary')
                in_summary = summary is not None and any(item is summary for item in self.stack)
                first_summary_itself = tag == 'summary' and parent is ancestor and summary is None
                collapsed = collapsed or not (in_summary or first_summary_itself)
        node = {'tag': tag, 'attrs': attributes, 'hidden': hidden_style(attributes, ancestors),
                'text': '', 'metadata_text': '', 'rendered_text': '', 'ancestors': self.stack.copy()}
        node['hidden'] = node['hidden'] or collapsed
        self.nodes.append(node)
        if tag == 'summary' and parent and parent['tag'] == 'details' and 'first_summary' not in parent:
            parent['first_summary'] = node
        if tag == 'legend' and parent and parent['tag'] == 'fieldset' and 'first_legend' not in parent:
            parent['first_legend'] = node
        disabled = tag in {'button','input','select','textarea','fieldset','optgroup','option'} and ('disabled' in attributes or any(
            ancestor['tag'] == 'fieldset' and 'disabled' in ancestor['attrs']
            and not any(item is ancestor.get('first_legend') for item in self.stack)
            for ancestor in self.stack))
        node['disabled'] = disabled
        if tag == 'base' and self.base is None and 'href' in attributes:
            self.base = attributes['href'] or ''
        if tag == 'form':
            self.forms.append(node)
        custom_textbox = attributes.get('role') == 'textbox' and tag not in {'input', 'textarea'}
        if tag in {'input', 'textarea'} or custom_textbox:
            editable = next(((item.get('contenteditable') or '').lower() != 'false' for item in [attributes, *reversed(ancestors)]
                if 'contenteditable' in item and (item.get('contenteditable') or '').lower() in {'','true','plaintext-only','false'}), False)
            node.update(form=None if custom_textbox else form, active=not hidden_style(attributes, ancestors, inert=True) and not collapsed
                        and (not custom_textbox or editable)
                        and not disabled)
            self.inputs.append(node)
        if tag in {'button', 'input'}:
            node['form'] = form
            self.submitters.append(node)
        if tag == 'script' and executable_script(attributes):
            if attributes.get('src'):
                self.script_srcs.append(attributes['src'])
            elif 'src' not in attributes:
                self.scripts.append(node)
        if tag == 'iframe':
            self.frames.append(node)
        if tag == 'meta' and (attributes.get('http-equiv') or '').lower() == 'refresh':
            self.meta_refresh += 1
        if tag not in VOID_TAGS:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        # Void tags never push; find the matching tag instead of blindly popping.
        for index in range(len(self.stack)-1, -1, -1):
            if self.stack[index]['tag'] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if self.stack and self.stack[-1]['tag'] == 'script':
            self.stack[-1]['text'] += data
        if not (self.stack and self.stack[-1]['hidden']) and not any(
                node['tag'] in {'input','textarea','select','option','script','style','noscript','template','head','title'}
                or 'contenteditable' in node['attrs'] for node in self.stack):
            self.visible_text.append(data)
        # Accessible labels may surround controls; their contents must never
        # contribute textarea values or editable text to metadata recognition.
        blocked = any('contenteditable' in node['attrs'] for node in self.stack)
        rendered = not (self.stack and self.stack[-1]['hidden'])
        for node in reversed(self.stack):
            blocked = blocked or node['tag'] in {'input','textarea','select','option','script','style','template'} or 'contenteditable' in node['attrs']
            if not blocked:
                # The browser joins distinct text nodes with spaces. Preserve
                # their boundaries so span chunks cannot invent/merge words.
                node['metadata_text'] += data + ' '
                if rendered:
                    node['rendered_text'] += data + ' '


def build_feature_row(url: str, title: str = '', html: str = '') -> dict:
    url = normalize_url(url)
    if not url:
        raise ValueError('A valid HTTP(S) document URL is required')
    parsed = urlsplit(url)
    host = parsed.hostname or ''
    normalized_host = host.rstrip('.')
    browser_host = '[' + host + ']' if ':' in host else host
    try:
        ipaddress.ip_address(normalized_host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    site = registrable_domain(url)
    chars = browser_host.replace('.', '')
    entropy = -sum(chars.count(ch)/len(chars) * math.log2(chars.count(ch)/len(chars)) for ch in set(chars)) if chars else 0
    title_mismatch, brand_in_url = brand_info(normalized_host, title)
    parser = PageParser()
    parser.feed(html)
    parser.close()
    forms_by_id = {node['attrs']['id']: node for node in parser.forms if node['attrs'].get('id')}
    nodes_by_id = {}
    for node in parser.nodes:
        if node['attrs'].get('id'):
            nodes_by_id.setdefault(node['attrs']['id'], node)
    labels = [node for node in parser.nodes if node['tag'] == 'label']
    def accessible_metadata(node):
        attrs = node['attrs']
        chunks = [attrs.get('aria-label') or '', attrs.get('placeholder') or '']
        for identifier in (attrs.get('aria-labelledby') or '').split():
            if identifier in nodes_by_id:
                chunks.append(nodes_by_id[identifier]['metadata_text'])
        for label in labels:
            if 'for' in label['attrs']:
                associated = bool(attrs.get('id')) and label['attrs']['for'] == attrs['id'] and nodes_by_id.get(attrs['id']) is node
            else:
                first_control = next((candidate for candidate in parser.nodes
                    if candidate['tag'] in {'button','input','meter','output','progress','select','textarea'}
                    and not (candidate['tag'] == 'input' and control_type(candidate) == 'hidden')
                    and any(ancestor is label for ancestor in candidate['ancestors'])), None)
                associated = first_control is node
            if associated:
                chunks.append(label['metadata_text'])
        return metadata_tokens(' '.join(chunks))
    for node in parser.inputs + parser.submitters:
        if node['tag'] in {'input','textarea','button'} and 'form' in node['attrs']:
            node['form'] = forms_by_id.get(node['attrs']['form'])
    fields = []
    for node in parser.inputs:
        attrs = node['attrs']
        kind = control_type(node)
        if not node['active'] or kind in {'hidden','button','submit','reset','image','checkbox','radio','file'}:
            continue
        tokens = set(metadata_tokens((attrs.get('name') or '')+' '+(attrs.get('id') or '')).split())
        compact = {re.sub(r'[^a-z0-9]', '', (attrs.get(key) or '').lower()) for key in ['name','id']}
        autocomplete = set((attrs.get('autocomplete') or '').lower().split())
        metadata = accessible_metadata(node) if kind in {'text','password','email','tel','number','textarea'} else ''
        explicit_identity = kind == 'email' or bool(tokens & IDENTITY_NAMES or compact & IDENTITY_NAMES or autocomplete & {'username','email'})
        identity_control = kind == 'email' or bool(autocomplete & {'username','email'})
        metadata_requests_identity = explicit_identity or bool(METADATA_IDENTITY.search(metadata))
        password_metadata = not metadata_requests_identity and bool(METADATA_PASSWORD.search(metadata))
        sensitive_metadata = (not metadata_requests_identity or (not identity_control and bool(METADATA_CODE.search(metadata)))) and bool(METADATA_SENSITIVE.search(metadata))
        sensitive = kind == 'password' or bool((not identity_control and (tokens & SENSITIVE_NAMES or compact & (SENSITIVE_NAMES | {'creditcardnumber'}))) or autocomplete & SENSITIVE_AUTOCOMPLETE or sensitive_metadata)
        identity = kind == 'email' or bool(tokens & IDENTITY_NAMES or compact & IDENTITY_NAMES or autocomplete & {'username','email'} or METADATA_IDENTITY.search(metadata))
        if sensitive or identity:
            fields.append({'node': node, 'form': node.get('form'), 'sensitive': sensitive,
                'username': 'username' in autocomplete,
                'password': kind == 'password' or bool((not identity_control and tokens & {'password','passwd','pwd'}) or autocomplete & {'current-password','new-password'} or password_metadata)})
    any_sensitive = any(field['sensitive'] for field in fields)
    def auth_context(form, form_fields):
        return any(field['sensitive'] or field['username'] for field in form_fields) or bool(
            form and AUTH_PATTERN.search(' '.join(form['attrs'].get(key) or '' for key in ['action','id','name']))) or bool(
            not any_sensitive and AUTH_PATTERN.search(title + ' ' + parsed.path))
    credential_forms = [form for form in parser.forms if (form_fields := [field for field in fields if field['form'] is form]) and auth_context(form, form_fields)]
    cross_site, empty = 0, 0
    base_url = urljoin(url, parser.base) if parser.base is not None else url
    for form in credential_forms:
        targets = [form['attrs']]
        for node in parser.submitters:
            attrs = node['attrs']
            kind = control_type(node)
            if node.get('form') is form and kind in {'submit','image'} and not node['disabled'] and not node['hidden'] and not hidden_style(attrs,[item['attrs'] for item in node['ancestors']],inert=True) and ('formaction' in attrs or 'formmethod' in attrs):
                targets.append({'action': attrs.get('formaction', form['attrs'].get('action')),
                                'method': attrs.get('formmethod', form['attrs'].get('method'))})
        for target in targets:
            if (target.get('method') or 'get').lower() == 'dialog':
                continue
            action = (target.get('action') or '').strip()
            empty = max(empty, int(not action))
            target_url = urljoin(base_url, action) if action else url
            target_parts = urlsplit(target_url)
            if target_parts.scheme in {'http','https'} and target_parts.hostname:
                cross_site = max(cross_site, int(host != target_parts.hostname and not (site and site == registrable_domain(target_url))))
    script_text = ' '.join(node['text'] for node in parser.scripts)
    obfuscation = sum(bool(re.search(pattern, script_text, re.I)) for pattern in [r'eval\s*\(',r'atob\s*\(',r'fromCharCode\s*\(',r'document\.write\s*\(',r'Function\s*\(']) * .25
    obfuscation += min(.8, .1 * len(re.findall(r'[A-Za-z0-9+/=]{200,}', script_text)))
    zero_size = lambda value: bool(re.fullmatch(r'\s*0+(?:\.0+)?(?:px|%)?\s*', str(value), re.I))
    def hidden_frame(node):
        attrs = node['attrs']
        styles = dict(re.findall(r'(?:^|;)\s*([\w-]+)\s*:\s*([^;]+)', attrs.get('style') or ''))
        return node['hidden'] or any(key in attrs and zero_size(attrs[key]) for key in ['width','height']) or any(zero_size(styles.get(key, '')) for key in ['width','height'])
    heading_pattern = re.compile(r'^(?:(?:welcome to|sign in to|log in to|login to)\s+)?(?:google|microsoft|apple|paypal|amazon|icici|hdfc|sbi|axis)(?:\s+(?:account|accounts|login|sign in|log in|secure login|internet banking|online banking))?\s*[.!]?$',re.I)
    heading_nodes = [node for node in parser.nodes if node['tag'] == 'h1' or (node['attrs'].get('role') == 'heading' and node['attrs'].get('aria-level') == '1')][:20]
    contextual = lambda node: any(item['tag'] in {'article','nav','footer','aside'} or item['attrs'].get('role') in {'article','comment'} for item in [node,*node['ancestors']])
    def contains_sensitive(scope, exclude_contextual=False):
        return any(field['sensitive'] and (not exclude_contextual or not contextual(field['node']))
            and (field['form'] is scope or field['node'] is scope or any(item is scope for item in field['node']['ancestors'])) for field in fields)
    def nearby_sensitive(heading):
        if contextual(heading):
            return False
        form = next((item for item in reversed(heading['ancestors']) if item['tag'] == 'form'),None)
        if form:
            return contains_sensitive(form)
        parent = heading['ancestors'][-1] if heading['ancestors'] else None
        siblings = [node for node in parser.nodes if (node['ancestors'][-1] if node['ancestors'] else None) is parent]
        heading_index = next(index for index,node in enumerate(siblings) if node is heading)
        following = siblings[heading_index+1:][:3]
        for sibling in following:
            if contextual(sibling) or sibling['tag'] in {'h1','h2'} or sibling['attrs'].get('role') == 'heading':
                break
            if contains_sensitive(sibling,True):
                return True
        return False
    headings = [text for node in heading_nodes if not node['hidden'] and not hidden_style(node['attrs'],[item['attrs'] for item in node['ancestors']],inert=True)
        and not any('contenteditable' in item['attrs'] for item in [node,*node['ancestors']])
        and nearby_sensitive(node)
        and (text := ' '.join(node['rendered_text'].split())) and len(text) <= 100 and heading_pattern.fullmatch(text)] if any_sensitive else []
    body_mismatch = brand_info(normalized_host,' - '.join(headings))[0] if headings else 0
    return {
        'url_length': len(url), 'hostname_length': len(browser_host),
        'subdomain_count': max(0, len(normalized_host.split('.'))-len(site.split('.'))) if site and not is_ip else 0,
        'dot_count': url.count('.'), 'digit_count': len(re.findall(r'[0-9]', url)),
        'suspicious_char_count': len(re.findall(r'[@%]', url)) + len(re.findall(r'-{2,}', url)),
        'has_ip_address': is_ip, 'uses_http': int(parsed.scheme == 'http' and not is_loopback(normalized_host)),
        'has_punycode': int('xn--' in host),
        'suspicious_keyword_count': sum(term in url.lower() for term in ['login','verify','secure','account','update','wallet','bank','signin','payment','confirm']),
        'hostname_entropy': round(entropy, 2), 'brand_domain_mismatch': max(title_mismatch,body_mismatch), 'page_title_mismatch': title_mismatch,
        'form_count': len(parser.forms), 'has_password_input': int(any(field['password'] for field in fields)),
        'credential_field_count': len(fields), 'cross_domain_form_action': cross_site,
        'hidden_field_count': sum(node['tag'] == 'input' and (node['attrs'].get('type') or '').lower() == 'hidden' and 'disabled' not in node['attrs'] for node in parser.inputs),
        'form_action_is_empty': empty, 'obfuscated_script_score': round(min(1, obfuscation), 2),
        'hidden_iframe_count': sum(hidden_frame(node) for node in parser.frames[:200]),
        'external_script_count': sum(urlsplit(urljoin(base_url, src)).hostname != host for src in parser.script_srcs),
        'meta_refresh_count': parser.meta_refresh, 'brand_name_in_title': int(bool(BRAND_PATTERN.search(title))),
        'brand_name_in_visible_text': int(bool(BRAND_PATTERN.search(' '.join(parser.visible_text)))),
        'brand_name_in_url': brand_in_url, 'has_unusual_port': int(parsed.port not in {None,80,443} and not is_loopback(normalized_host)),
        'domain_registration_age_days': 0, 'credential_submission_script': 0,
    }


def validate_feature_row(row: dict) -> None:
    if not isinstance(row, dict):
        raise ValueError('Feature row must be an object')
    missing = [name for name in FEATURE_SCHEMA if name not in row]
    extra = [name for name in row if name not in FEATURE_SCHEMA]
    if missing or extra:
        raise ValueError(f'Feature schema mismatch: missing={missing}, extra={extra}')
    if any(isinstance(value, bool) or not isinstance(value, (int,float)) or not math.isfinite(value) for value in row.values()):
        raise ValueError('Every feature must be a finite number')
