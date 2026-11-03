The offline public suffix data in `extension/src/shared/public-suffix-rules.json`
and `public-suffix.js` is generated from the Public Suffix List embedded in
**tldts 7.4.16**, using `scripts/vendor-public-suffix.cjs`. ICANN and PRIVATE rules
are included. Its rule hash is stored in both generated artifacts.

Source: https://github.com/remusao/tldts and https://publicsuffix.org/.
The tldts MIT license is reproduced in
`extension/src/shared/tldts-LICENSE.txt`. The upstream Public Suffix List is made
available under the Mozilla Public License 2.0:
https://publicsuffix.org/list/public_suffix_list.dat and
https://mozilla.org/MPL/2.0/.

No list is downloaded by the extension. To update it, update the pinned tldts
dependency, regenerate the two assets, review the changes, and run the JS and
Python domain/feature parity suites.
