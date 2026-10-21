# Privacy policy

PhishGuard is designed to prioritize local processing.

## Data collected

By default, the extension only analyzes:

- URL structure
- hostname
- DOM structure
- form attributes
- script and redirect metadata
- limited generic brand indicators in page title and visible text

It does not read:

- typed passwords
- page text content beyond limited generic brand indicators
- form values entered by the user
- cookies or browser history

## Optional enrichment

If the user enables domain-age enrichment, the extension may send only the hostname to a trusted RDAP/WHOIS service. It will not send the full URL, form content, or page text.

If the user enables reputation enrichment, the extension sends only the hostname to the endpoint configured by the user. The extension does not include API keys in its code and does not send page contents, form values, cookies, or credentials.

## Local storage

The extension stores only minimal local metadata such as:

- tab result
- score
- reasons
- user feedback
- option preferences

Feedback reports are kept locally, capped at the most recent 100 entries, and are not uploaded automatically.

This data is kept in browser storage and can be cleared via the options page.
