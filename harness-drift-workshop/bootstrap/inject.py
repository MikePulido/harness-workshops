#!/usr/bin/env python3
"""Create drift on purpose, through the Harness API, the way a hand edit in the
UI would. Embedded by bootstrap/main.tf into the <prefix>_inject pipeline;
also runs from a workstation:

  python3 bootstrap/inject.py --target environment --identifier drift_workshop_dev --tag tier --value dev-manual-change
  python3 bootstrap/inject.py --target variable    --identifier drift_workshop_replicas --value 3

Environment: HARNESS_API_URL (default https://app.harness.io), HARNESS_API_KEY,
HARNESS_ACCOUNT_ID, HARNESS_ORG_ID, HARNESS_PROJECT_ID.

environment: reads the environment, sets one tag, writes it back with the same
name, type and description, so the only change is the tag.
variable: reads the project variable and writes it back with the new fixed
value.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def http(method, url, key, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={'x-api-key': key, 'Content-Type': 'application/json', 'User-Agent': 'drift-workshop-inject'})
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            status, text = res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors='replace')
        e.close()
    try:
        return status, json.loads(text) if text else None
    except ValueError:
        return status, text


class Harness:
    def __init__(self, env):
        self.api = env.get('HARNESS_API_URL', 'https://app.harness.io').rstrip('/')
        self.key = env['HARNESS_API_KEY']
        self.scope = {'accountIdentifier': env['HARNESS_ACCOUNT_ID'], 'orgIdentifier': env['HARNESS_ORG_ID'], 'projectIdentifier': env['HARNESS_PROJECT_ID']}

    def url(self, path):
        return '%s%s?%s' % (self.api, path, urllib.parse.urlencode(self.scope))

    def get(self, path):
        return http('GET', self.url(path), self.key)

    def put(self, path, body):
        return http('PUT', self.url(path), self.key, body)


def environment_payload(env_obj, tag, value):
    """The PUT body for environmentsV2 from a GET response, with one tag set."""
    tags = dict(env_obj.get('tags') or {})
    before = tags.get(tag)
    tags[tag] = value
    body = {
        'identifier': env_obj['identifier'],
        'orgIdentifier': env_obj.get('orgIdentifier'),
        'projectIdentifier': env_obj.get('projectIdentifier'),
        'name': env_obj['name'],
        'type': env_obj['type'],
        'tags': tags,
    }
    if env_obj.get('description'):
        body['description'] = env_obj['description']
    return body, before


def variable_payload(var_obj, value):
    spec = dict(var_obj.get('spec') or {})
    before = spec.get('fixedValue')
    spec['valueType'] = 'FIXED'
    spec['fixedValue'] = value
    body = {'variable': {
        'identifier': var_obj['identifier'],
        'name': var_obj.get('name') or var_obj['identifier'],
        'orgIdentifier': var_obj.get('orgIdentifier'),
        'projectIdentifier': var_obj.get('projectIdentifier'),
        'type': var_obj.get('type', 'String'),
        'spec': spec,
    }}
    if var_obj.get('description'):
        body['variable']['description'] = var_obj['description']
    return body, before


def inject(h, target, identifier, tag, value, out=print):
    if target == 'environment':
        status, res = h.get('/ng/api/environmentsV2/%s' % identifier)
        env_obj = (res or {}).get('data', {}).get('environment') if isinstance(res, dict) else None
        if status != 200 or not env_obj:
            raise SystemExit('environment %s: GET %s %s' % (identifier, status, json.dumps(res)[:300]))
        body, before = environment_payload(env_obj, tag, value)
        status, res = h.put('/ng/api/environmentsV2', body)
        if status != 200:
            raise SystemExit('environment %s: PUT %s %s' % (identifier, status, json.dumps(res)[:300]))
        out('environment %s: tag %s %r -> %r' % (identifier, tag, before, value))
        return {'target': target, 'identifier': identifier, 'attribute': 'tags.%s' % tag, 'before': before, 'after': value}
    if target == 'variable':
        status, res = h.get('/ng/api/variables/%s' % identifier)
        var_obj = (res or {}).get('data', {}).get('variable') if isinstance(res, dict) else None
        if status != 200 or not var_obj:
            raise SystemExit('variable %s: GET %s %s' % (identifier, status, json.dumps(res)[:300]))
        body, before = variable_payload(var_obj, value)
        status, res = h.put('/ng/api/variables', body)
        if status != 200:
            raise SystemExit('variable %s: PUT %s %s' % (identifier, status, json.dumps(res)[:300]))
        out('variable %s: value %r -> %r' % (identifier, before, value))
        return {'target': target, 'identifier': identifier, 'attribute': 'spec.fixedValue', 'before': before, 'after': value}
    raise SystemExit('target must be environment or variable')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--target', required=True, choices=['environment', 'variable'])
    ap.add_argument('--identifier', required=True)
    ap.add_argument('--tag', default='tier', help='environment only')
    ap.add_argument('--value', required=True)
    a = ap.parse_args(argv)
    missing = [k for k in ('HARNESS_API_KEY', 'HARNESS_ACCOUNT_ID', 'HARNESS_ORG_ID', 'HARNESS_PROJECT_ID') if not os.environ.get(k)]
    if missing:
        raise SystemExit('missing %s' % ', '.join(missing))
    inject(Harness(os.environ), a.target, a.identifier, a.tag, a.value)
    print('Drift injected. Run the workspace\'s Detect Drift to see it remediated.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
