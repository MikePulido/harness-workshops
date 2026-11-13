#!/usr/bin/env python3
"""Set up one Harness project with everything the workshops need, the same
way every time.

  python3 harness-workshops/install.py --project <project id> --token <api key of that project's user>

The rest comes from the env file (default: .env at the repository root):
  WORKSHOP_ACCOUNT_ID, WORKSHOP_ORG_ID   where the projects live
  WORKSHOP_PROJECT_ID, WORKSHOP_API_KEY  defaults for --project and --token
  WORKSHOP_GIT_USERNAME                  default for --git-username
                                         (else <project>@harnessevents.com)
  anthropic_api_key                      model key for the Worker Agents
  aws-access-key, aws-secret-key         any cloud credential; IaCM wants a
                                         provider connector on a workspace
Environment variables WORKSHOP_*, ANTHROPIC_API_KEY, AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_REGION and HARNESS_API_URL override the file;
flags override both.

Three steps, each idempotent (re-running updates in place):
  1. secrets anthropic_api_key and aws_secret_key; connectors anthropic_api
     (Anthropic, claude-sonnet-4-6) and aws_creds (AWS, manual keys)
  2. drift remediation workshop: harness-drift-workshop/bootstrap/install.sh
  3. DevSecOps labs 1-5 (service frontend, pipeline workshop) and the
     fix-one-vulnerability loop: harness-devsecops-workshop/install.py
--no-drift and --no-devsecops skip a kit; --dry-run prints the plan only.
Needs python3, git, tofu (or terraform with TF=terraform) and the harness CLI.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DRIFT = os.path.join(ROOT, 'harness-drift-workshop', 'bootstrap', 'install.sh')
DEVSECOPS = os.path.join(ROOT, 'harness-devsecops-workshop', 'install.py')
MODEL_CONNECTOR, CLOUD_CONNECTOR = 'anthropic_api', 'aws_creds'
MODEL_SECRET, CLOUD_SECRET = 'anthropic_api_key', 'aws_secret_key'
NEEDED = {'account': 'WORKSHOP_ACCOUNT_ID', 'org': 'WORKSHOP_ORG_ID', 'project': '--project', 'token': '--token',
          'anthropic_key': 'anthropic_api_key', 'aws_access_key': 'aws-access-key', 'aws_secret_key': 'aws-secret-key'}


def read_env_file(path):
    """KEY=VALUE lines; anything else (comments, PEM blocks) is skipped."""
    out = {}
    try:
        with open(path, encoding='utf-8') as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for line in lines:
        m = re.match(r'^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*?)\s*$', line)
        if not m or line.lstrip().startswith('#'):
            continue
        v = m.group(2)
        if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
        out[m.group(1)] = v
    return out


def settings(args, env, file_vars):
    def pick(*names, default=''):
        for source in (env, file_vars):
            for n in names:
                if source.get(n):
                    return source[n]
        return default
    s = {'account': args.account or pick('WORKSHOP_ACCOUNT_ID'),
         'org': args.org or pick('WORKSHOP_ORG_ID'),
         'project': args.project or pick('WORKSHOP_PROJECT_ID'),
         'token': args.token or pick('WORKSHOP_API_KEY'),
         'anthropic_key': pick('ANTHROPIC_API_KEY', 'anthropic_api_key'),
         'aws_access_key': pick('AWS_ACCESS_KEY_ID', 'aws-access-key'),
         'aws_secret_key': pick('AWS_SECRET_ACCESS_KEY', 'aws-secret-key'),
         'aws_region': pick('AWS_REGION', default='us-east-2'),
         'api_url': pick('HARNESS_API_URL', default='https://app.harness.io').rstrip('/'),
         'model': args.model or 'claude-sonnet-4-6'}
    s['git_username'] = args.git_username or pick('WORKSHOP_GIT_USERNAME') or ('%s@harnessevents.com' % s['project'] if s['project'] else '')
    return s


# ---- Harness API --------------------------------------------------------------

def call(s, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(s['api_url'] + path, data=data, method=method, headers={'x-api-key': s['token'], 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode() or 'null')
    except urllib.error.HTTPError as e:
        t = e.read().decode(errors='replace')
        try:
            return e.code, json.loads(t)
        except ValueError:
            return e.code, t[:500]


def scope(s):
    return 'accountIdentifier=%s&orgIdentifier=%s&projectIdentifier=%s' % (s['account'], s['org'], s['project'])


def fail(what, status, body):
    msg = body.get('message') if isinstance(body, dict) else str(body)
    raise SystemExit('%s failed: %s %s' % (what, status, (msg or '')[:600]))


def secret_body(s, identifier, value):
    return {'secret': {'type': 'SecretText', 'name': identifier, 'identifier': identifier, 'orgIdentifier': s['org'], 'projectIdentifier': s['project'],
                       'spec': {'secretManagerIdentifier': 'harnessSecretManager', 'valueType': 'Inline', 'value': value}}}


def anthropic_connector(s):
    return {'connector': {'name': MODEL_CONNECTOR, 'identifier': MODEL_CONNECTOR, 'orgIdentifier': s['org'], 'projectIdentifier': s['project'], 'type': 'Anthropic',
                          'spec': {'url': 'https://api.anthropic.com', 'authentication': {'type': 'Token', 'spec': {'tokenRef': MODEL_SECRET}},
                                   'model': s['model'], 'executeOnDelegate': False}}}


def aws_connector(s):
    return {'connector': {'name': CLOUD_CONNECTOR, 'identifier': CLOUD_CONNECTOR, 'orgIdentifier': s['org'], 'projectIdentifier': s['project'], 'type': 'Aws',
                          'spec': {'credential': {'type': 'ManualConfig', 'region': s['aws_region'],
                                                  'spec': {'accessKey': s['aws_access_key'], 'secretKeyRef': CLOUD_SECRET, 'secretInputMethod': 'INDIVIDUAL'}},
                                   'executeOnDelegate': False}}}


def install_secret(s, identifier, value):
    status, r = call(s, 'GET', '/ng/api/v2/secrets/%s?%s' % (identifier, scope(s)))
    if status == 200 and (r.get('data') or {}).get('secret'):
        status, r = call(s, 'PUT', '/ng/api/v2/secrets/%s?%s' % (identifier, scope(s)), secret_body(s, identifier, value))
        verb = 'updated'
    else:
        status, r = call(s, 'POST', '/ng/api/v2/secrets?%s' % scope(s), secret_body(s, identifier, value))
        verb = 'created'
    if status != 200:
        fail('secret %s' % identifier, status, r)
    print('   secret %s %s' % (identifier, verb))


def install_connector(s, body):
    ident = body['connector']['identifier']
    status, r = call(s, 'GET', '/ng/api/connectors/%s?%s' % (ident, scope(s)))
    if status == 200 and ((r.get('data') or {}).get('connector') or {}).get('identifier'):
        status, r = call(s, 'PUT', '/ng/api/connectors?accountIdentifier=%s' % s['account'], body)
        verb = 'updated'
    else:
        status, r = call(s, 'POST', '/ng/api/connectors?accountIdentifier=%s' % s['account'], body)
        verb = 'created'
    if status != 200:
        fail('connector %s' % ident, status, r)
    print('   connector %s %s' % (ident, verb))


# ---- the two kits ---------------------------------------------------------------

def kit_commands(s, drift=True, devsecops=True):
    base = {'HARNESS_ACCOUNT_ID': s['account'], 'HARNESS_API_KEY': s['token'], 'HARNESS_ORG_ID': s['org'], 'HARNESS_PROJECT_ID': s['project'],
            'HARNESS_GIT_USERNAME': s['git_username'], 'HARNESS_API_URL': s['api_url'], 'MODEL_CONNECTOR': MODEL_CONNECTOR}
    out = []
    if drift:
        out.append(('drift remediation workshop', [DRIFT], dict(base, PROVIDER_CONNECTOR=CLOUD_CONNECTOR)))
    if devsecops:
        out.append(('DevSecOps labs 1-5 and the fix-one-vulnerability loop', [sys.executable, DEVSECOPS], base))
    return out


def main(argv):
    ap = argparse.ArgumentParser(description='Set up one Harness project with the workshops.')
    ap.add_argument('--project')
    ap.add_argument('--token')
    ap.add_argument('--account')
    ap.add_argument('--org')
    ap.add_argument('--git-username')
    ap.add_argument('--model')
    ap.add_argument('--env-file', default=os.path.join(ROOT, '.env'))
    ap.add_argument('--no-drift', action='store_true')
    ap.add_argument('--no-devsecops', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)
    s = settings(args, os.environ, read_env_file(args.env_file))
    missing = [NEEDED[k] for k in NEEDED if not s[k]]
    if missing:
        raise SystemExit('missing: %s (flags, environment, or %s)' % (', '.join(missing), args.env_file))
    for tool in ('git', os.environ.get('TF', 'tofu'), 'harness'):
        if not args.no_drift and not shutil.which(tool):
            raise SystemExit('%s not found on PATH (needed by the drift workshop; --no-drift skips it)' % tool)
    if not args.no_devsecops and not shutil.which('harness'):
        raise SystemExit('harness CLI not found on PATH: brew install --cask harness/tap/harness-cli')
    kits = kit_commands(s, drift=not args.no_drift, devsecops=not args.no_devsecops)
    total = 1 + len(kits)
    print('Project %s, org %s, account %s; git user %s; model %s; token %s...' % (s['project'], s['org'], s['account'], s['git_username'], s['model'], s['token'][:8]))
    if args.dry_run:
        print('Plan: secrets %s, %s; connectors %s, %s; then %s' % (MODEL_SECRET, CLOUD_SECRET, MODEL_CONNECTOR, CLOUD_CONNECTOR, ', '.join(k[0] for k in kits) or 'nothing else'))
        return 0
    print('== 1/%d secrets and connectors' % total)
    install_secret(s, MODEL_SECRET, s['anthropic_key'])
    install_secret(s, CLOUD_SECRET, s['aws_secret_key'])
    install_connector(s, anthropic_connector(s))
    install_connector(s, aws_connector(s))
    for n, (label, cmd, env) in enumerate(kits, 2):
        print('== %d/%d %s' % (n, total, label))
        sys.stdout.flush()
        r = subprocess.run(cmd, env=dict(os.environ, **env))
        if r.returncode != 0:
            raise SystemExit('%s failed (exit %d)' % (label, r.returncode))
    print('\nDone: project %s has the workshop setup.' % s['project'])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
