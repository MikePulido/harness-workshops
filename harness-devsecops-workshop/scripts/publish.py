#!/usr/bin/env python3
"""Check the agent's one-line dependency fix and open the pull request.

Embedded into the `publish` Run step of the critical-fix step group, after the
Agent step, where secrets are real. The agent chose the finding, the manifest
and the version; this step only proves the rule held and publishes:

  1. exactly one tracked file changed and no file created since the
     baseline the findings step recorded (whatever earlier steps left
     behind does not count), and it is a manifest (requirements.txt or
     package.json)
  2. exactly one line of it changed, that line pins a package, and the package
     is one of the scanner's findings, at a higher version than before
  3. OSV confirms the new version is no longer affected by the vulnerabilities
     behind the finding (the ones matching its CVE ids; all of them when the
     scanner gave none)
  4. package.json changed: regenerate package-lock.json with npm
  5. commit on agent/fix/<package>/<run>, push, open the pull request in the
     Harness Code repository (reusing an open one for the branch)

Anything else blocks: remediation.json action "blocked", exit 1, nothing
pushed. No change at all: action "none", exit 0.

Inputs: ROOT_DIR, OUTPUT_DIR, FINDINGS_FILE, PIPELINE_ID, PIPELINE_URL,
RUN_SEQUENCE, BASE_BRANCH, OSV_API_URL, HARNESS_API_URL, HARNESS_API_KEY,
HARNESS_ACCOUNT_ID, HARNESS_ORG_ID, HARNESS_PROJECT_ID, HARNESS_REPO,
HARNESS_GIT_URL, HARNESS_GIT_USERNAME, DRY_RUN=1 (commit only).
Last stdout line: RESULT=<opened|none|blocked> ...
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

PIN = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(==|~=|>=)\s*([0-9][^\s;#]*)')
NPM = re.compile(r'^\s*"([^"]+)"\s*:\s*"([\^~]?)([^"]*)"\s*,?\s*$')
IGNORED = ('.artifacts/', '.agent/', '.claude/')  # ours, and what the agent runtime writes for itself
AUTHOR = ['-c', 'user.name=Critical Fix Agent', '-c', 'user.email=critical-fix-agent@example.invalid']


class Block(Exception):
    pass


def http(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}, **{'Content-Type': 'application/json', 'User-Agent': 'critical-fix'}))
    try:
        with urllib.request.urlopen(req, timeout=60) as res:
            status, text = res.status, res.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode(errors='replace')
        e.close()
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return status, parsed if parsed is not None else text


def vkey(v):
    v = str(v or '').strip().lstrip('^~=<>!v ')
    nums, suffix = [], ''
    for part in re.split(r'[.\-+]', v):
        if part.isdigit() and not suffix:
            nums.append(int(part))
        else:
            suffix += part
    return (tuple(nums + [0] * (8 - len(nums))), 0 if not suffix else -1, suffix)


def norm(name, eco):
    return re.sub(r'[-_.]+', '-', name).lower() if eco == 'PyPI' else name


def slug(s):
    return re.sub(r'[^a-z0-9]+', '-', str(s).lower()).strip('-') or 'x'


# ---- git ---------------------------------------------------------------------

def git(args, cwd):
    r = subprocess.run(['git'] + args, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise Block('git %s failed: %s' % (args[0], (r.stderr or r.stdout).strip()[-300:]))
    return r.stdout


def blob(root, path):
    r = subprocess.run(['git', 'hash-object', '--', path], cwd=root, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def changed(root, before=None):
    """Tracked files modified and files created since the baseline the
    findings step recorded; paths already dirty then (build output, a
    lockfile rewritten by an install) do not count unless their content
    changed again."""
    before = before or {}
    was_untracked, was_modified = set(before.get('untracked') or []), before.get('modified') or {}
    modified, untracked = [], []
    for ln in git(['status', '--porcelain', '--untracked-files=all'], root).splitlines():
        if len(ln) < 4:
            continue
        code, path = ln[:2], ln[3:].strip()
        if path.startswith(IGNORED):
            continue
        if code == '??':
            if path not in was_untracked:
                untracked.append(path)
        elif path not in was_modified or blob(root, path) != was_modified[path]:
            modified.append(path)
    return modified, untracked


def one_line_diff(root, path):
    raw = git(['diff', '-U0', '--no-color', '--', path], root).splitlines()
    minus = [l[1:] for l in raw if l.startswith('-') and not l.startswith('---')]
    plus = [l[1:] for l in raw if l.startswith('+') and not l.startswith('+++')]
    if len(minus) != 1 or len(plus) != 1:
        raise Block('%s: %d line(s) removed and %d added; the rule is exactly one line changed' % (path, len(minus), len(plus)))
    return minus[0], plus[0]


def parse_pin(path, line):
    base = os.path.basename(path)
    if base == 'requirements.txt':
        m = PIN.match(line)
        return (m.group(1), m.group(3), 'PyPI') if m else None
    if base == 'package.json':
        m = NPM.match(line)
        return (m.group(1), m.group(3), 'npm') if m else None
    return None


def regen_lock(root, manifest):
    d = os.path.join(root, os.path.dirname(manifest))
    lock = os.path.join(d, 'package-lock.json')
    if not os.path.isfile(lock):
        raise Block('no package-lock.json next to %s; cannot regenerate it' % manifest)
    try:
        r = subprocess.run(['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=d, capture_output=True, text=True)
    except OSError as e:
        raise Block('npm is not available to regenerate the lockfile: %s' % e)
    if r.returncode != 0:
        raise Block('npm could not regenerate the lockfile: %s' % (r.stderr or r.stdout).strip()[-400:])
    return os.path.normpath(os.path.relpath(lock, root))


# ---- the finding behind the edit -------------------------------------------

def same_findings(findings, name, eco, old_version):
    """The scanner's findings for this package, highest CVSS first and the
    exact version first; the new version has to close one of them."""
    same = [f for f in findings if f.get('ecosystem') == eco and norm(f.get('package') or '', eco) == norm(name, eco)]
    return [f for f in same if f.get('version') == old_version] + [f for f in same if f.get('version') != old_version]


def must_close(f):
    """The OSV ids the new version has to be clear of: those matching the
    scanner's CVE ids, or every known one when the scanner gave none."""
    cves = set(f.get('cve_ids') or [])
    ids = [v['id'] for v in f.get('osv') or [] if not cves or cves & ({v.get('id')} | set(v.get('aliases') or []))]
    return ids or [v['id'] for v in f.get('osv') or []]


def osv_known(osv_url, name, eco, version):
    status, body = http('POST', osv_url.rstrip('/') + '/v1/query', body={'package': {'name': name, 'ecosystem': eco}, 'version': version})
    if status != 200:
        raise Block('OSV %s while checking %s %s: %s' % (status, name, version, str(body)[:200]))
    vulns = (body or {}).get('vulns') or []
    known = set()
    for v in vulns:
        known |= {v.get('id')} | set(v.get('aliases') or [])
    return known, len(vulns)


# ---- Harness Code ------------------------------------------------------------

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
        return status, who, msg

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
        raise Block('Harness Code %s opening the pull request: %s' % (status, res.get('message') if isinstance(res, dict) else str(res)[:300]))


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
        raise Block('git push failed via origin (%s) and via credentialed url (%s)' % (first, second))
    raise Block('git push failed via origin: %s' % first)


# ---- text --------------------------------------------------------------------

def commit_message(name, f, new_version, closed, manifest, pipeline_url):
    return ('fix(deps): %s %s -> %s\n\nCloses %s (CVSS %s) in %s. One finding, one line; nothing else changed.\n\nPipeline-Execution: %s\n'
            % (name, f['version'], new_version, ', '.join(closed) or 'the reported finding', f.get('cvss'), manifest, pipeline_url))


def pr_title(name, new_version, closed):
    return 'fix(deps): bump %s to %s%s' % (name, new_version, ' for %s' % closed[0] if closed else '')


def pr_body(pipeline, name, f, new_version, manifest, files, closed, remaining, lock_regenerated, others, summary, pipeline_url):
    parts = ['<!-- agent-generated -->', 'Dependency fix from pipeline `%s`: one finding, one line.' % pipeline, '']
    if summary:
        parts += ['**Agent summary**', '', summary.strip(), '']
    parts += ['**Finding**', '',
              '- `%s` `%s` -> `%s` in `%s`' % (name, f['version'], new_version, manifest),
              '- Severity: %s (CVSS %s); scanner ids: %s' % (f.get('severity_code'), f.get('cvss'), ', '.join('`%s`' % i for i in f.get('cve_ids') or []) or 'none'),
              '- %s' % (f.get('description') or '').strip().replace('\n', ' '), '',
              '**Verification**', '',
              '- OSV: `%s` `%s` is clear of %s; %d other known vulnerabilit%s remain for that version.' % (name, new_version, ', '.join('`%s`' % i for i in closed), remaining, 'y' if remaining == 1 else 'ies'),
              '- Lockfile regenerated: %s' % ('yes' if lock_regenerated else 'not needed'), '']
    if others:
        parts += ['**Still open:** %d other finding%s (%s). One pull request per run; merge this and run again.' % (len(others), '' if len(others) == 1 else 's', ', '.join(others)), '']
    parts += ['**Files:** %s' % ', '.join('`%s`' % x for x in files), '', '**Pipeline:** %s' % pipeline_url, '']
    return '\n'.join(parts)


# ---- main --------------------------------------------------------------------

def _read(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return fh.read()
    except OSError:
        return None


def run(env, root=None, out=print):
    root = root or env.get('ROOT_DIR', '/harness')
    out_dir = env.get('OUTPUT_DIR') or os.path.join(root, '.artifacts', 'fix')
    os.makedirs(out_dir, exist_ok=True)
    findings_file = env.get('FINDINGS_FILE') or os.path.join(out_dir, 'findings.json')
    pipeline = env.get('PIPELINE_ID', '')
    pipeline_url = env.get('PIPELINE_URL', '')
    osv_url = env.get('OSV_API_URL', 'https://api.osv.dev')
    backend = HarnessCode(env)
    base = {'action': None, 'pipeline': pipeline, 'branch': None, 'pr_url': None, 'files': [], 'finding': None, 'verification': None, 'reasons': [], 'summary': ''}

    def finish(doc, code):
        with open(os.path.join(out_dir, 'remediation.json'), 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(doc, indent=2) + '\n')
        out('RESULT=%s %s' % (doc['action'], doc.get('pr_url') or '; '.join(doc.get('reasons') or []) or doc.get('summary', '')))
        return code, doc

    try:
        raw = _read(findings_file)
        if raw is None:
            raise Block('no findings file at %s; the findings step did not run' % findings_file)
        findings = json.loads(raw).get('findings') or []
        already = json.loads(_read(os.path.join(os.path.dirname(findings_file), 'baseline.json')) or '{}')
        summary = _read(os.path.join(out_dir, 'summary.md'))
        modified, untracked = changed(root, already)
        if untracked:
            raise Block('new files were created: %s; the agent may only change one existing line' % ', '.join(untracked))
        if not modified:
            return finish(dict(base, action='none', reasons=['the agent changed nothing' if findings else 'no finding to fix'],
                               summary=(summary or '').strip() or 'Nothing to publish.'), 0)
        if len(modified) != 1:
            raise Block('%d files changed (%s); the rule is one line in one manifest' % (len(modified), ', '.join(modified)))
        path = modified[0]
        old, new = one_line_diff(root, path)
        before, after = parse_pin(path, old), parse_pin(path, new)
        if not after or not before or norm(after[0], after[2]) != norm(before[0], before[2]):
            raise Block('the changed line in %s is not a version bump of one pinned package: %r -> %r' % (path, old.strip(), new.strip()))
        name, new_version, eco = after
        if vkey(new_version) <= vkey(before[1]):
            raise Block('%s %s -> %s is not an upgrade' % (name, before[1], new_version))
        same = same_findings(findings, name, eco, before[1])
        if not same:
            raise Block('%s in %s is not one of the scanner\'s findings' % (name, path))
        known, remaining = osv_known(osv_url, name, eco, new_version)
        f, ids, still = None, [], []
        for cand in same:  # the agent fixes one finding; the first one the new version closes is it
            want = must_close(cand)
            left = [i for i in want if i in known]
            if want and not left:
                f, ids = cand, want
                break
            still = still or left
        if not f:
            if still:
                raise Block('%s %s is still affected by %s' % (name, new_version, ', '.join(still)))
            raise Block('OSV has no record for %s %s; the fix cannot be verified' % (name, before[1]))
        verification = {'package': name, 'ecosystem': eco, 'version': new_version, 'closed': ids, 'remaining_vulns': remaining}
        out('verified: %s %s closes %s; %d other known vulnerabilities remain' % (name, new_version, ', '.join(ids), remaining))
        files = [path]
        lock = regen_lock(root, path) if os.path.basename(path) == 'package.json' else None
        if lock:
            files.append(lock)
        reasons = [] if summary else ['the agent wrote no summary.md']
        branch = 'agent/fix/%s/%s' % (slug(name), slug(env.get('RUN_SEQUENCE') or 'manual'))
        git(['checkout', '-q', '-B', branch], root)
        git(['add', '--'] + files, root)
        git(AUTHOR + ['commit', '-q', '-m', commit_message(name, f, new_version, ids, path, pipeline_url)], root)
        out('committed %s on %s' % (', '.join(files), branch))
        brief = {k: f.get(k) for k in ('package', 'ecosystem', 'version', 'cvss', 'severity_code', 'cve_ids', 'sto_issue_id')}
        done = dict(base, branch=branch, files=files, finding=dict(brief, manifest=path, new_version=new_version), verification=verification, reasons=reasons)
        if env.get('DRY_RUN') == '1':
            return finish(dict(done, action='opened', pr_url='(dry run)', summary='Dry run: committed locally, nothing pushed.'), 0)
        if not backend.configured():
            raise Block(backend.missing())
        status, who, msg = backend.check()
        out('credential check (harness_code): %s%s' % (status, ' as %s' % who if who else ''))
        if status != 200:
            reasons.append('harness_code rejected the credential: %s %s' % (status, msg))
        via = push(root, branch, backend)
        out('pushed %s via %s' % (branch, via))
        fixed = (norm(f.get('package') or '', eco), f.get('version'))
        others = sorted({'%s@%s' % (x.get('package'), x.get('version')) for x in findings if (norm(x.get('package') or '', x.get('ecosystem')), x.get('version')) != fixed})
        pr = backend.open_pr(branch, env.get('BASE_BRANCH', 'main'), pr_title(name, new_version, ids),
                             pr_body(pipeline, name, f, new_version, path, files, ids, remaining, bool(lock), others, summary, pipeline_url))
        out('%s pull request #%d' % ('opened' if pr['created'] else 'reused open', pr['number']))
        return finish(dict(done, action='opened', pr_url=pr['url'], summary='Bumped %s to %s.' % (name, new_version)), 0)
    except Block as e:
        return finish(dict(base, action='blocked', reasons=[str(e)], summary='Nothing published.'), 1)


def main():
    code, _ = run(os.environ)
    return code


if __name__ == '__main__':
    sys.exit(main())
