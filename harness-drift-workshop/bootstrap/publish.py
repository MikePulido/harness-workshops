#!/usr/bin/env python3
"""Publish the drift remediation agent's edits as a pull request.

Embedded by bootstrap/main.tf into the drift pipeline's `publish` Run step
(pipelines/drift.yaml.tftpl), so it ships with the pipeline, not with the
repository the workspace reads. Runs after the Agent step, where secrets are
real. Nothing is read from the repository except the Terraform the agent
edited, plan.json from detect-drift, and the agent's optional summary.

  1. locate the Terraform directory by plan.json; flatten resource_drift for
     the pull request body
  2. scope: only tracked *.tf / *.tfvars files under that directory may have
     changed (.terraform.lock.hcl and untracked files are ignored); a change
     anywhere else blocks publishing and fails the step
  3. no change: remediation.json action "none", exit 0
  4. branch agent/drift/<workspace>/<run sequence>, commit with a
     Pipeline-Execution trailer, push (origin first, credentialed URL fallback)
  5. the pull request, reusing an open one for the branch; the agent's
     summary.md goes in the body when present
  6. remediation.json action "opened"

The pull request is opened in Harness Code, the same repository the workspace
reads, so the whole flow stays inside Harness. Inputs: HARNESS_API_URL,
HARNESS_API_KEY, HARNESS_ACCOUNT_ID, HARNESS_ORG_ID, HARNESS_PROJECT_ID,
HARNESS_REPO (identifier), HARNESS_GIT_URL and HARNESS_GIT_USERNAME (push
fallback when the clone's own credential is refused).

Also: ROOT_DIR (default /harness), OUTPUT_DIR, WORKSPACE, PIPELINE_URL,
RUN_SEQUENCE, BASE_BRANCH (default main), DRIFT_PUBLISH_DRY_RUN=1.
Last stdout line: RESULT=<opened|none|blocked> ... Exit 1 on blocked.
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

TF_EXT = ('.tf', '.tfvars')
LOCK_FILE = '.terraform.lock.hcl'
SKIP_DIRS = {'.git', 'node_modules', '.terraform', '.artifacts', '.agent'}
COMPUTED_KEYS = {'id', 'uid', 'arn', 'resource_version', 'generation', 'creation_timestamp', 'etag', 'self_link', 'last_modified'}
AUTHOR = ['-c', 'user.name=Drift Remediation Agent', '-c', 'user.email=drift-agent@example.invalid']


class PublishError(Exception):
    pass


# ---- the plan -------------------------------------------------------------

def find_plan_files(root, max_depth=4):
    found = []

    def walk(d, depth):
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                if depth < max_depth and e.name not in SKIP_DIRS and not e.name.startswith('.iacmbin'):
                    walk(e.path, depth + 1)
            elif e.name == 'plan.json':
                found.append(e.path)

    walk(root, 0)
    return sorted(found)


def locate_plan(root):
    def has_tf(d):
        try:
            return any(n.endswith('.tf') for n in os.listdir(d))
        except OSError:
            return False
    candidates = [p for p in find_plan_files(root) if has_tf(os.path.dirname(p))]
    if len(candidates) > 1:
        raise PublishError('more than one plan.json under %s: %s' % (root, ', '.join(candidates)))
    return candidates[0] if candidates else None


ADDRESS_RE = re.compile(r'^(?:module\.[^.\[]+(?:\[[^\]]*\])?\.)*(?:data\.)?([A-Za-z0-9_]+)\.([A-Za-z0-9_-]+)(\[.*\])?$')
IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def render_path(segments):
    out = ''
    for s in segments:
        if isinstance(s, int):
            out += '[%d]' % s
        elif IDENT_RE.match(s):
            out += ('.%s' % s) if out else s
        else:
            out += '[%s]' % json.dumps(s)
    return out


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'))


def diff_values(before, after, segments=(), out=None):
    if out is None:
        out = []
    if isinstance(before, dict) and isinstance(after, dict):
        for k in sorted(set(before) | set(after)):
            diff_values(before.get(k), after.get(k), segments + (k,), out)
        return out
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        for i, (b, a) in enumerate(zip(before, after)):
            diff_values(b, a, segments + (i,), out)
        return out
    if canon(before) != canon(after):
        out.append({'segments': segments, 'before': before, 'after': after})
    return out


def flatten_drift(plan):
    entries = []
    for r in plan.get('resource_drift') or []:
        change = r.get('change') or {}
        actions = change.get('actions') or []
        if not actions or actions == ['no-op']:
            continue
        m = ADDRESS_RE.match(r.get('address', ''))
        base = {'address': r.get('address'), 'type': r.get('type') or (m.group(1) if m else None), 'name': r.get('name') or (m.group(2) if m else None)}
        if 'delete' in actions and 'create' not in actions:
            entries.append(dict(base, kind='missing_live', path=None, before=change.get('before'), after=None, computed=False))
            continue
        for d in diff_values(change.get('before') or {}, change.get('after') or {}):
            keys = [s for s in d['segments'] if isinstance(s, str)]
            entries.append(dict(base, kind='attribute', path=render_path(d['segments']), before=d['before'], after=d['after'],
                                computed=(keys[-1] if keys else '') in COMPUTED_KEYS))
    return entries


# ---- git ------------------------------------------------------------------

def git(args, cwd, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
    r = subprocess.run(['git'] + list(args), cwd=cwd, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise PublishError('git %s failed: %s' % (args[0], (r.stderr or r.stdout).strip()))
    return r.stdout


def classify_changes(root, tf_dir):
    tf_rel = os.path.relpath(tf_dir, root).replace(os.sep, '/')

    def in_dir(f):
        return f == tf_rel or f.startswith(tf_rel + '/')

    tracked = [f for f in git(['diff', '--name-only', 'HEAD', '--'], root).split('\n') if f]
    untracked = [f for f in git(['ls-files', '--others', '--exclude-standard', '--', tf_rel], root).split('\n') if f]
    in_scope, out_of_scope = [], []
    for f in tracked:
        if os.path.basename(f) == LOCK_FILE:
            continue
        (in_scope if in_dir(f) and f.endswith(TF_EXT) else out_of_scope).append(f)
    return {'tf_rel': tf_rel, 'in_scope': sorted(set(in_scope)), 'out_of_scope': sorted(set(out_of_scope)),
            'untracked_tf': sorted(f for f in untracked if f.endswith(TF_EXT))}


def slug(s):
    return re.sub(r'^-+|-+$', '', re.sub(r'[^A-Za-z0-9._-]+', '-', str(s))) or 'x'


def branch_name(workspace, seq):
    return 'agent/drift/%s/%s' % (slug(workspace), slug(seq))


def _fmt(v):
    return '(absent)' if v is None else json.dumps(v, sort_keys=True)


def commit_message(workspace, entries, pipeline_url):
    addrs = sorted(set(e['address'] for e in entries))
    lines = ['drift(%s): reconcile %d resource%s to live state' % (workspace, len(addrs), '' if len(addrs) == 1 else 's'), '']
    lines += ['- %s %s: %s -> %s' % (e['address'], e['path'], _fmt(e['before']), _fmt(e['after'])) for e in entries]
    lines += ['', 'Config edited to match what detect-drift found live; nothing applied.', '', 'Pipeline-Execution: %s' % pipeline_url]
    return '\n'.join(lines) + '\n'


def pr_title(workspace, entries):
    n = len(set(e['address'] for e in entries))
    return 'drift(%s): reconcile %d resource%s to live state' % (workspace, n, '' if n == 1 else 's')


def pr_body(workspace, entries, files, pipeline_url, drift_json, summary):
    what = ['- `%s` — `%s`: %s -> %s' % (e['address'], e['path'], _fmt(e['before']), _fmt(e['after'])) for e in entries] or ['- (see diff)']
    parts = ['<!-- agent-generated -->', 'Drift remediation for workspace `%s`' % workspace, '']
    if summary:
        parts += ['**Agent summary**', '', summary.strip(), '']
    parts += ['**Drift found**', *what, '',
              '**Why:** detect-drift found the live state differing from the config; this makes the config match what is live. Nothing was applied.', '',
              '**Decide:** merge to accept the manual change, or close and Provision the workspace again to revert it.', '',
              '**Files:** %s' % ', '.join('`%s`' % f for f in files), '',
              '**Pipeline:** %s' % pipeline_url, '',
              '<details><summary>drift.json</summary>', '', '```json', drift_json.rstrip('\n'), '```', '', '</details>', '']
    return '\n'.join(parts)


# ---- SCM backends ---------------------------------------------------------

def http(method, url, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers, **{'Content-Type': 'application/json', 'User-Agent': 'drift-remediation'}))
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            status, text = res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors='replace')
        e.close()
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return status, parsed if parsed is not None else text


def secret_diagnosis(name, value):
    if not value:
        return '%s is empty' % name
    if value.startswith('<+'):
        return '%s is an unresolved Harness expression (%d chars)' % (name, len(value))
    if set(value) <= {'*'}:
        return '%s is masked (%d asterisks)' % (name, len(value))
    family = next((p for p in ('pat.', 'sat.') if value.startswith(p)), 'unknown')
    return '%s is %d chars, prefix %s' % (name, len(value), family)


class HarnessCode:
    name = 'harness_code'

    def __init__(self, env):
        self.key = env.get('HARNESS_API_KEY', '')
        self.api = env.get('HARNESS_API_URL', 'https://app.harness.io').rstrip('/')
        self.account = env.get('HARNESS_ACCOUNT_ID', '')
        self.org = env.get('HARNESS_ORG_ID', '')
        self.project = env.get('HARNESS_PROJECT_ID', '')
        self.repo = env.get('HARNESS_REPO', '')
        self.git_url = env.get('HARNESS_GIT_URL', '')
        self.git_user = env.get('HARNESS_GIT_USERNAME', '')

    def configured(self):
        return all([self.key, self.account, self.org, self.project, self.repo])

    def missing(self):
        return 'HARNESS_API_KEY, HARNESS_ACCOUNT_ID, HARNESS_ORG_ID, HARNESS_PROJECT_ID or HARNESS_REPO missing'

    def headers(self):
        return {'x-api-key': self.key}

    def repo_url(self, suffix='', **params):
        q = urllib.parse.urlencode({'accountIdentifier': self.account, 'orgIdentifier': self.org, 'projectIdentifier': self.project})
        if params:
            q += '&' + urllib.parse.urlencode(params)
        return '%s/code/api/v1/repos/%s%s?%s' % (self.api, urllib.parse.quote(self.repo, safe=''), suffix, q)

    def check(self):
        status, body = http('GET', self.repo_url(), self.headers())
        who = body.get('identifier') if isinstance(body, dict) else None
        msg = body.get('message') if isinstance(body, dict) else str(body)[:120]
        return status, who, msg, secret_diagnosis('HARNESS_API_KEY', self.key)

    def push_url(self):
        if not self.git_url:
            return None
        return self.git_url.replace('https://', 'https://%s:%s@' % (urllib.parse.quote(self.git_user or 'git', safe=''), urllib.parse.quote(self.key, safe='')), 1)

    def pr_url(self, number):
        return '%s/ng/account/%s/module/code/orgs/%s/projects/%s/repos/%s/pulls/%d' % (self.api, self.account, self.org, self.project, self.repo, number)

    def open_pr(self, head, base, title, body):
        status, res = http('POST', self.repo_url('/pullreq'), self.headers(), {'source_branch': head, 'target_branch': base, 'title': title, 'description': body, 'is_draft': False})
        if status in (200, 201) and isinstance(res, dict) and 'number' in res:
            return {'number': res['number'], 'url': self.pr_url(res['number']), 'created': True}
        if status == 409:
            s2, lst = http('GET', self.repo_url('/pullreq', state='open', source_branch=head), self.headers())
            if s2 == 200 and isinstance(lst, list) and lst:
                return {'number': lst[0]['number'], 'url': self.pr_url(lst[0]['number']), 'created': False}
        raise PublishError('Harness Code %s opening the pull request: %s' % (status, res.get('message') if isinstance(res, dict) else str(res)[:300]))

    def after_open(self, pr):
        return []


def backend_for(env):
    return HarnessCode(env)


def push(root, branch, backend):
    r = subprocess.run(['git', 'push', '--force', '--quiet', 'origin', 'HEAD:refs/heads/%s' % branch], cwd=root,
                       capture_output=True, text=True, env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
    if r.returncode == 0:
        return 'origin'
    first = (r.stderr or r.stdout).strip()
    url = backend.push_url()
    if url:
        r2 = subprocess.run(['git', 'push', '--force', '--quiet', url, 'HEAD:refs/heads/%s' % branch], cwd=root,
                            capture_output=True, text=True, env=dict(os.environ, GIT_TERMINAL_PROMPT='0'))
        if r2.returncode == 0:
            return 'credentialed url'
        second = (r2.stderr or r2.stdout).strip()
        if backend.key:
            second = second.replace(backend.key, '***').replace(urllib.parse.quote(backend.key, safe=''), '***')
        raise PublishError('git push failed via origin (%s) and via credentialed url (%s)' % (first, second))
    raise PublishError('git push failed via origin: %s' % first)


# ---- main -----------------------------------------------------------------

def _read(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read()
    except OSError:
        return None


def run(env, root=None, out=print):
    root = root or env.get('ROOT_DIR', '/harness')
    out_dir = env.get('OUTPUT_DIR', os.path.join(root, '.artifacts', 'drift'))
    os.makedirs(out_dir, exist_ok=True)
    workspace = env.get('WORKSPACE') or 'unknown'
    pipeline_url = env.get('PIPELINE_URL', '')
    dry_run = env.get('DRIFT_PUBLISH_DRY_RUN') == '1'
    backend = backend_for(env)

    def finish(doc, code):
        with open(os.path.join(out_dir, 'remediation.json'), 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(doc, indent=2) + '\n')
        out('RESULT=%s %s' % (doc['action'], doc.get('pr_url') or '; '.join(doc.get('reasons') or []) or doc.get('summary', '')))
        return code, doc

    base = {'action': None, 'workspace': workspace, 'scm': backend.name, 'branch': None, 'pr_url': None, 'files': [], 'resources_changed': [], 'reasons': [], 'summary': ''}
    try:
        plan_file = locate_plan(root)
    except PublishError as e:
        return finish(dict(base, action='blocked', reasons=[str(e)], summary='Cannot tell which workspace drifted.'), 1)
    if not plan_file:
        return finish(dict(base, action='blocked', reasons=['no plan.json next to Terraform files under %s; detect-drift did not produce a plan' % root], summary='No plan to publish from.'), 1)
    tf_dir = os.path.dirname(plan_file)
    with open(plan_file, encoding='utf-8') as fh:
        drift = flatten_drift(json.load(fh))
    entries = [e for e in drift if e['kind'] == 'attribute' and not e['computed']]
    base['resources_changed'] = [{'address': e['address'], 'attribute': e['path'], 'from': e['before'], 'to': e['after']} for e in entries]
    summary = _read(os.path.join(out_dir, 'summary.md'))

    changes = classify_changes(root, tf_dir)
    base['files'] = changes['in_scope']
    if changes['out_of_scope']:
        return finish(dict(base, action='blocked', reasons=['edits outside %s: %s' % (changes['tf_rel'], ', '.join(changes['out_of_scope']))],
                           summary='The agent edited files outside the workspace directory; nothing published.'), 1)
    reasons = []
    if changes['untracked_tf']:
        reasons.append('new files were not committed: %s' % ', '.join(changes['untracked_tf']))
    if not summary:
        reasons.append('the agent wrote no summary.md')
    if not changes['in_scope']:
        return finish(dict(base, action='none', reasons=reasons + ['the agent changed no Terraform file'], summary='Nothing to publish.'), 0)

    branch = branch_name(workspace, env.get('RUN_SEQUENCE') or 'manual')
    git(['checkout', '-q', '-B', branch], root)
    git(['add', '--'] + changes['in_scope'], root)
    git(AUTHOR + ['commit', '-q', '-m', commit_message(workspace, entries, pipeline_url)], root)
    out('committed %s on %s' % (', '.join(changes['in_scope']), branch))
    if dry_run:
        return finish(dict(base, action='opened', branch=branch, pr_url='(dry run)', reasons=reasons, summary='Dry run: committed locally, nothing pushed.'), 0)

    if not backend.configured():
        return finish(dict(base, action='blocked', branch=branch, reasons=reasons + [backend.missing()], summary='Committed locally; cannot publish.'), 1)
    status, who, msg, diag = backend.check()
    out('credential check (%s): %s%s (%s)' % (backend.name, status, ' as %s' % who if who else '', diag))
    if status != 200:
        reasons.append('%s rejected the credential: %s %s' % (backend.name, status, msg))
    try:
        via = push(root, branch, backend)
        out('pushed %s via %s' % (branch, via))
        pr = backend.open_pr(branch, env.get('BASE_BRANCH', 'main'), pr_title(workspace, entries),
                             pr_body(workspace, entries, changes['in_scope'], pipeline_url, json.dumps(drift, indent=2, sort_keys=True), summary))
    except PublishError as e:
        return finish(dict(base, action='blocked', branch=branch, reasons=reasons + [str(e)], summary='Committed but not published.'), 1)
    reasons += backend.after_open(pr)
    out('%s pull request #%d' % ('opened' if pr['created'] else 'reused open', pr['number']))
    return finish(dict(base, action='opened', branch=branch, pr_url=pr['url'], reasons=reasons,
                       summary='Reconciled %s in %s.' % (', '.join(sorted(set(e['address'] for e in entries))), ', '.join(changes['in_scope']))), 0)


def main():
    try:
        code, _ = run(os.environ)
    except PublishError as e:
        print('RESULT=blocked %s' % e)
        return 1
    return code


if __name__ == '__main__':
    sys.exit(main())
