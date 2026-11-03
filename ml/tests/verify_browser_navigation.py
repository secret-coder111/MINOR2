"""Feed a real Edge CDP trace to the collector's document-response binder.

The Node browser smoke test owns the live transport; no Playwright installation
is needed for this parser/loader integration check. This is not the full capture
CLI or its network sandbox.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from capture_dom_snapshots import DocumentResponses


class TraceSession:
    def on(self, *_args):
        pass

    def send(self, *_args):
        pass

    def detach(self):
        pass


class TraceContext:
    def new_cdp_session(self, _page):
        return TraceSession()


trace = json.load(sys.stdin)
binder = DocumentResponses(TraceContext(), None)
for event in trace['events']:
    if event['method'] == 'Network.requestWillBeSent':
        binder._request(event['params'])
    elif event['method'] == 'Network.responseReceived':
        binder._response(event['params'])
response = binder.for_snapshot({'document_identity': trace['document_identity']})
assert response['status'] == 404, response
assert response['url'].endswith('/capture-final'), response
assert any(event['method'] == 'Network.responseReceived' and event['params'].get('response', {}).get('status') == 200 for event in trace['events'])
print(json.dumps({'passed': True, 'original_status': 200, 'captured_document_status': response['status'],
                 'binding': 'real Edge Network events and loader identity through actual DocumentResponses'}))
