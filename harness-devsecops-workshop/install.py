#!/usr/bin/env python3
"""Install the critical-fix loop into a Harness project.

  HARNESS_ACCOUNT_ID=... HARNESS_API_KEY=... HARNESS_ORG_ID=... HARNESS_PROJECT_ID=... \
  HARNESS_GIT_USERNAME=<email the key belongs to> \
  [MODEL_CONNECTOR=anthropic_api] [NAME_PREFIX=devsecops] [REPO=harness-devsecops] \
  [PIPELINE_ID=workshop] [HARNESS_API_URL=https://app.harness.io] \
  python3 install.py [--render] [--no-lab] [--reset-lab] [--no-pipeline]

Six steps, each idempotent:
  1. service frontend from lab/service-frontend.yaml (labs 1-5)
  2. pipeline PIPELINE_ID from lab/pipeline.yaml, created when missing and
     otherwise left alone (--reset-lab rewrites it; --no-lab skips 1 and 2)
  3. Worker Agent <prefix>_critical_fix through the harness CLI
     (brew install --cask harness/tap/harness-cli)
  4. secret <prefix>_api_key holding HARNESS_API_KEY, for the findings and
     publish steps
  5. StepGroup template <prefix>_critical_fix_loop v0.1, scripts embedded
  6. the step group appended to the Build (CI) stage of PIPELINE_ID, unless
     it is already there or --no-pipeline

The lab pipeline uses what a workshop project comes with: templates
Compile_Application, fortify and owasp, connector dockerhub_devsecops,
service backend, environment prod with infrastructure k8s, project variable
username, and the Code repository REPO. Nothing here creates those.
--render prints the rendered template and exits (no network).
Needs python3 only; the CLI is used for the agent because agents have no
Terraform resource.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ['HARNESS_ACCOUNT_ID', 'HARNESS_API_KEY', 'HARNESS_ORG_ID', 'HARNESS_PROJECT_ID', 'HARNESS_GIT_USERNAME']


def settings(env):
    s = {k: env.get(k, '') for k in REQUIRED}
    s['api_url'] = env.get('HARNESS_API_URL', 'https://app.harness.io').rstrip('/')
    s['model_connector'] = env.get('MODEL_CONNECTOR', 'anthropic_api')
    s['prefix'] = env.get('NAME_PREFIX', 'devsecops')
    s['repo'] = env.get('REPO', 'harness-devsecops')
    s['pipeline'] = env.get('PIPELINE_ID', 'workshop')
    s['agent'] = '%s_critical_fix' % s['prefix']
    s['secret'] = '%s_api_key' % s['prefix']
    # Not <prefix>_critical_fix: the agent itself is stored as a Step template under that identifier.
    s['template'] = '%s_critical_fix_loop' % s['prefix']
    s['git_url'] = 'https://git.harness.io/%s/%s/%s/%s.git' % (s['HARNESS_ACCOUNT_ID'], s['HARNESS_ORG_ID'], s['HARNESS_PROJECT_ID'], s['repo'])
    return s


def render(s):
    with open(os.path.join(HERE, 'templates', 'critical_fix.yaml.tmpl'), encoding='utf-8') as fh:
        text = fh.read()
    scripts = {'findings_py': 'findings.py', 'publish_py': 'publish.py'}
    lines = []
    for line in text.splitlines():
        m = re.match(r'^(\s*)\{\{(findings_py|publish_py)\}\}\s*$', line)
        if m:
            indent = m.group(1)
            with open(os.path.join(HERE, 'scripts', scripts[m.group(2)]), encoding='utf-8') as fh:
                lines += [(indent + l) if l else '' for l in fh.read().rstrip('\n').splitlines()]
        else:
            lines.append(line)
    out = '\n'.join(lines) + '\n'
    for k, v in {'prefix': s['prefix'], 'org': s['HARNESS_ORG_ID'], 'project': s['HARNESS_PROJECT_ID'], 'agent': s['agent'], 'api_url': s['api_url'],
                 'api_key_secret': s['secret'], 'repo': s['repo'], 'git_url': s['git_url'], 'git_username': s['HARNESS_GIT_USERNAME']}.items():
        out = out.replace('{{%s}}' % k, v)
    left = re.findall(r'\{\{[a-z_]+\}\}', out)
    if left:
        raise SystemExit('unrendered tokens: %s' % ', '.join(sorted(set(left))))
    return out


def lab_yaml(s, name):
    with open(os.path.join(HERE, 'lab', name), encoding='utf-8') as fh:
        text = fh.read()
    for k, v in {'org': s['HARNESS_ORG_ID'], 'project': s['HARNESS_PROJECT_ID'], 'repo': s['repo'], 'pipeline': s['pipeline']}.items():
        text = text.replace('{{%s}}' % k, v)
    left = re.findall(r'\{\{[a-z_]+\}\}', text)
    if left:
        raise SystemExit('unrendered tokens in lab/%s: %s' % (name, ', '.join(sorted(set(left)))))
    return text


def call(s, method, path, body=None, ctype='application/json'):
    data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(s['api_url'] + path, data=data, method=method, headers={'x-api-key': s['HARNESS_API_KEY'], 'Content-Type': ctype})
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
    return 'accountIdentifier=%s&orgIdentifier=%s&projectIdentifier=%s' % (s['HARNESS_ACCOUNT_ID'], s['HARNESS_ORG_ID'], s['HARNESS_PROJECT_ID'])


def fail(what, status, body):
    msg = body.get('message') if isinstance(body, dict) else str(body)
    raise SystemExit('%s failed: %s %s' % (what, status, (msg or '')[:600]))


def install_service(s):
    print('== 1/6 service frontend (lab)')
    body = {'identifier': 'frontend', 'name': 'frontend', 'orgIdentifier': s['HARNESS_ORG_ID'], 'projectIdentifier': s['HARNESS_PROJECT_ID'],
            'yaml': lab_yaml(s, 'service-frontend.yaml')}
    status, r = call(s, 'GET', '/ng/api/servicesV2/frontend?%s' % scope(s))
    if status == 200 and ((r.get('data') or {}).get('service') or {}).get('identifier'):
        status, r = call(s, 'PUT', '/ng/api/servicesV2?accountIdentifier=%s' % s['HARNESS_ACCOUNT_ID'], body)
        verb = 'updated'
    else:
        status, r = call(s, 'POST', '/ng/api/servicesV2?accountIdentifier=%s' % s['HARNESS_ACCOUNT_ID'], body)
        verb = 'created'
    if status != 200:
        fail('service', status, r)
    print('   ' + verb)


def install_lab_pipeline(s, reset=False):
    print('== 2/6 pipeline %s (lab)' % s['pipeline'])
    status, r = call(s, 'GET', '/pipeline/api/pipelines/%s?%s' % (s['pipeline'], scope(s)))
    exists = status == 200 and bool((r.get('data') or {}).get('yamlPipeline'))
    if exists and not reset:
        print('   already there, left as is (--reset-lab rewrites it from lab/pipeline.yaml)')
        return
    yaml = lab_yaml(s, 'pipeline.yaml')
    if exists:
        status, r = call(s, 'PUT', '/pipeline/api/pipelines/v2/%s?%s' % (s['pipeline'], scope(s)), yaml, 'application/yaml')
        verb = 'rewritten from lab/pipeline.yaml'
    else:
        status, r = call(s, 'POST', '/pipeline/api/pipelines/v2?%s' % scope(s), yaml, 'application/yaml')
        verb = 'created'
    if status != 200:
        fail('lab pipeline', status, r)
    gov = ((r.get('data') or {}).get('governanceMetadata') or {})
    print('   %s; policy on save: %s' % (verb, gov.get('status') or 'n/a'))


def install_agent(s):
    print('== 3/6 worker agent %s' % s['agent'])
    with open(os.path.join(HERE, 'agents', 'critical-fix.yaml'), encoding='utf-8') as fh:
        text = fh.read()
    text = re.sub(r'^name: .*$', 'name: %s' % s['agent'], text, count=1, flags=re.M)
    text = re.sub(r'^(      connector: ).*$', r'\g<1>%s' % s['model_connector'], text, count=1, flags=re.M)
    env = dict(os.environ, HARNESS_ACCOUNT=s['HARNESS_ACCOUNT_ID'], HARNESS_API_KEY=s['HARNESS_API_KEY'])
    common = ['--org', s['HARNESS_ORG_ID'], '--project', s['HARNESS_PROJECT_ID']]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'agent.yaml')
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(text)
        exists = subprocess.run(['harness', 'get', 'agent', s['agent']] + common, env=env, capture_output=True, text=True).returncode == 0
        verb = 'update' if exists else 'create'
        r = subprocess.run(['harness', verb, 'agent', s['agent'], '-f', path] + common, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit('harness %s agent failed: %s' % (verb, (r.stderr or r.stdout).strip()[-600:]))
    print('   %sd' % verb)


def install_secret(s):
    print('== 4/6 secret %s' % s['secret'])
    body = {'secret': {'type': 'SecretText', 'name': s['secret'], 'identifier': s['secret'], 'orgIdentifier': s['HARNESS_ORG_ID'], 'projectIdentifier': s['HARNESS_PROJECT_ID'],
                       'spec': {'secretManagerIdentifier': 'harnessSecretManager', 'valueType': 'Inline', 'value': s['HARNESS_API_KEY']}}}
    status, r = call(s, 'GET', '/ng/api/v2/secrets/%s?%s' % (s['secret'], scope(s)))
    if status == 200 and (r.get('data') or {}).get('secret'):
        status, r = call(s, 'PUT', '/ng/api/v2/secrets/%s?%s' % (s['secret'], scope(s)), body)
        verb = 'updated'
    else:
        status, r = call(s, 'POST', '/ng/api/v2/secrets?%s' % scope(s), body)
        verb = 'created'
    if status != 200:
        fail('secret', status, r)
    print('   ' + verb)


def install_template(s):
    print('== 5/6 step group template %s v0.1' % s['template'])
    yaml = render(s)
    status, r = call(s, 'GET', '/template/api/templates/%s?%s&versionLabel=v0.1' % (s['template'], scope(s)))
    if status == 200 and (r.get('data') or {}).get('yaml'):
        status, r = call(s, 'PUT', '/template/api/templates/update/%s/v0.1?%s&setDefaultTemplate=true&comments=install' % (s['template'], scope(s)), yaml, 'application/yaml')
        verb = 'updated'
    else:
        status, r = call(s, 'POST', '/template/api/templates?%s&setDefaultTemplate=true&isNewTemplate=true&comments=install' % scope(s), yaml, 'application/yaml')
        verb = 'created'
    if status != 200:
        fail('template', status, r)
    print('   ' + verb)


def add_step_group(yaml_text, template_id):
    lines = yaml_text.splitlines()
    if any(('templateRef: %s' % template_id) in l for l in lines):
        return None
    in_ci, steps_indent, start, end = False, None, None, None
    for i, l in enumerate(lines):
        st = l.strip()
        if re.match(r'^type:\s*CI\s*$', st):
            in_ci = True
        if in_ci and start is None and re.match(r'^steps:\s*$', st):
            steps_indent, start = len(l) - len(l.lstrip()), i
            continue
        if start is not None and st and (len(l) - len(l.lstrip())) <= steps_indent:
            end = i
            break
    if start is None:
        raise SystemExit('pipeline has no CI stage with execution steps')
    if end is None:
        end = len(lines)
    item = ' ' * (steps_indent + 2)
    block = [item + '- stepGroup:', item + '    name: Critical fix', item + '    identifier: critical_fix', item + '    template:',
             item + '      templateRef: %s' % template_id, item + '      versionLabel: v0.1']
    return '\n'.join(lines[:end] + block + lines[end:]) + '\n'


def install_pipeline(s):
    print('== 6/6 step group in pipeline %s' % s['pipeline'])
    status, r = call(s, 'GET', '/pipeline/api/pipelines/%s?%s' % (s['pipeline'], scope(s)))
    if status != 200:
        fail('pipeline read', status, r)
    patched = add_step_group((r.get('data') or {}).get('yamlPipeline') or '', s['template'])
    if patched is None:
        print('   already contains the step group')
        return
    status, r = call(s, 'PUT', '/pipeline/api/pipelines/v2/%s?%s' % (s['pipeline'], scope(s)), patched, 'application/yaml')
    if status != 200:
        fail('pipeline update', status, r)
    gov = ((r.get('data') or {}).get('governanceMetadata') or {})
    print('   step group added after the last Build step; policy on save: %s' % (gov.get('status') or 'n/a'))


def main(argv):
    s = settings(os.environ)
    if '--render' in argv:
        s.setdefault('HARNESS_GIT_USERNAME', '')
        sys.stdout.write(render(s))
        return 0
    missing = [k for k in REQUIRED if not s[k]]
    if missing:
        raise SystemExit('missing %s' % ', '.join(missing))
    if '--no-lab' not in argv:
        install_service(s)
        install_lab_pipeline(s, '--reset-lab' in argv)
    install_agent(s)
    install_secret(s)
    install_template(s)
    if '--no-pipeline' not in argv and s['pipeline']:
        install_pipeline(s)
    print('\nInstalled. Run pipeline %s: the Build stage ends with OSV scan, Findings, Agent, Publish. The pull request lands in Code repository %s.' % (s['pipeline'], s['repo']))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
