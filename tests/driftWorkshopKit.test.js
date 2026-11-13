'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const YAML = require('yaml');

const KIT = path.join(__dirname, '..', 'harness-drift-workshop');

// What bootstrap/main.tf hands templatefile(); the scripts are embedded as
// heredocs through indent(22, ...).
const VARS = {
  prefix: 'drift_workshop', org_id: 'o', project_id: 'p', repo: 'drift_workshop_repo', git_url: 'https://git.harness.io/a/o/p/drift_workshop_repo.git',
  git_username: 'me', api_key_secret: 'drift_workshop_api_key', api_url: 'https://app.harness.io', agent_name: 'drift_workshop_remediation', repo_branch: 'main',
  publish_py: fs.readFileSync(path.join(KIT, 'bootstrap', 'publish.py'), 'utf8'),
  inject_py: fs.readFileSync(path.join(KIT, 'bootstrap', 'inject.py'), 'utf8'),
};

function render(name) {
  const text = fs.readFileSync(path.join(KIT, 'pipelines', `${name}.yaml.tftpl`), 'utf8');
  return text.replace(/\$\{indent\((\d+), (\w+)\)\}/g, (m, n, k) => VARS[k].split('\n').join('\n' + ' '.repeat(Number(n))))
    .replace(/\$\{(\w+)\}/g, (m, k) => { if (!(k in VARS)) { throw new Error(`${name}: unknown placeholder ${k}`); } return VARS[k]; });
}

describe('harness-drift-workshop kit', () => {
  it('bootstrap scripts pass their unittest suite', () => {
    const r = spawnSync('python3', ['-m', 'unittest', 'discover', '-s', path.join(KIT, 'bootstrap'), '-p', 'test_*.py'], { encoding: 'utf8' });
    if (r.error) { throw r.error; }
    expect(r.stderr + r.stdout).toMatch(/\nOK(\s|$)/);
    expect(r.status).toBe(0);
  });

  it('pipeline templates render to valid YAML with every placeholder supplied', () => {
    for (const f of ['apply', 'destroy', 'drift', 'inject']) {
      const doc = YAML.parse(render(f));
      expect(doc.pipeline.identifier).toBe(`drift_workshop_${f}`);
      expect(doc.pipeline.orgIdentifier).toBe('o');
      expect(doc.pipeline.projectIdentifier).toBe('p');
    }
  });

  it('embeds the publish and inject scripts as heredocs, so the repository needs only Terraform', () => {
    const drift = YAML.parse(render('drift')).pipeline.stages[0].stage.spec.execution.steps.map(s => s.step);
    expect(drift.map(s => s.identifier)).toEqual(['init', 'drift', 'remediate', 'publish']);
    const publish = drift[3].spec.command;
    expect(publish).toContain("python3 - <<'PUBLISH_PY'\n#!/usr/bin/env python3");
    expect(publish).toContain('\ndef run(env, root=None, out=print):');
    expect(publish.trimEnd().endsWith('\nPUBLISH_PY')).toBe(true);
    // Self-contained in Harness: the pull request goes to the Harness Code repo, never GitHub.
    expect(drift[3].spec.envVariables.HARNESS_REPO).toBeDefined();
    expect(Object.keys(drift[3].spec.envVariables).filter(k => k.startsWith('GITHUB'))).toEqual([]);
    expect(publish).not.toContain('api.github.com');
    expect(drift[3].when.condition).toContain('<+execution.steps.remediate.status> == "SUCCEEDED"');

    const inject = YAML.parse(render('inject')).pipeline.stages[0].stage.spec.execution.steps[0].step.spec.command;
    expect(inject).toContain("<<'INJECT_PY'\n#!/usr/bin/env python3");
    expect(inject.trimEnd().endsWith('\nINJECT_PY')).toBe(true);
    expect(fs.existsSync(path.join(KIT, 'scripts'))).toBe(false);
  });

  it('agent is self-contained: 40 turns, no scripts, no secrets', () => {
    const agent = YAML.parse(YAML.parse(fs.readFileSync(path.join(KIT, 'agents', 'drift-remediation.yaml'), 'utf8')).spec).agent;
    expect(agent.with.max_turns).toBe('40');
    expect(agent.with.env.MAX_TURNS).toBe('40');
    expect(agent.with.prompt).not.toMatch(/scripts\//);
    expect(agent.with.prompt).toContain('resource_drift');
    expect(agent.with.prompt).toContain('summary.md');
    expect(agent.with.env.GITHUB_TOKEN).toBeUndefined();
    expect(agent.with.env.HARNESS_API_KEY).toBeUndefined();
  });
});
