'use strict';

// The critical-fix kit (harness-devsecops-workshop/): the python unit tests,
// the rendered step group template, and the agent definition.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const YAML = require('yaml');

const KIT = path.join(__dirname, '..', 'harness-devsecops-workshop');
const ENV = {
  ...process.env,
  HARNESS_ACCOUNT_ID: 'acct', HARNESS_API_KEY: 'k', HARNESS_ORG_ID: 'o', HARNESS_PROJECT_ID: 'p', HARNESS_GIT_USERNAME: 'u@example.invalid',
};

describe('critical-fix kit', () => {
  it('python unit tests pass (kit scripts and the one-command project setup)', () => {
    // unittest reports on stderr; a non-zero exit throws, which is the assertion.
    for (const dir of [path.join(KIT, 'scripts'), path.join(__dirname, '..', 'harness-workshops')]) {
      expect(() => execFileSync('python3', ['-m', 'unittest', 'discover', '-s', dir, '-p', 'test_*.py'], { encoding: 'utf8', stdio: 'pipe' })).not.toThrow();
    }
  }, 120000);

  it('renders a CI step group template with scan, findings, agent and publish', () => {
    const text = execFileSync('python3', [path.join(KIT, 'install.py'), '--render'], { encoding: 'utf8', env: ENV });
    const t = YAML.parse(text).template;
    expect(t.type).toBe('StepGroup');
    expect(t.spec.stageType).toBe('CI');
    const steps = t.spec.steps.map(s => s.step);
    expect(steps.map(s => s.identifier)).toEqual(['osv', 'findings', 'remediate', 'publish']);
    expect(steps[0].type).toBe('OsvScanner');
    expect(steps[0].spec.mode).toBe('orchestration');
    expect(steps[1].spec.command).toContain("python3 - <<'FINDINGS_PY'\n#!/usr/bin/env python3");
    expect(steps[1].spec.command.trimEnd().endsWith('\nFINDINGS_PY')).toBe(true);
    expect(steps[1].spec.envVariables.SCANNER).toBe('osv-scanner');
    expect(steps[1].spec.envVariables.SCAN_STEP_ID).toBeUndefined();
    expect(steps[2].type).toBe('Agent');
    expect(steps[2].spec.agentName).toBe('devsecops_critical_fix');
    expect(steps[2].spec.agentSettings).toBe('');
    expect(steps[3].spec.command).toContain("python3 - <<'PUBLISH_PY'\n#!/usr/bin/env python3");
    expect(steps[3].spec.command.trimEnd().endsWith('\nPUBLISH_PY')).toBe(true);
    expect(steps[3].spec.envVariables.HARNESS_REPO).toBe('harness-devsecops');
    for (const s of steps.slice(1)) {
      expect(s.failureStrategies[0].onFailure.action.type).toBe('Ignore');
    }
    expect(text).not.toMatch(/github/i);
  });

  it('agent is self-contained: 40 turns, no scripts, no secrets', () => {
    const agent = YAML.parse(YAML.parse(fs.readFileSync(path.join(KIT, 'agents', 'critical-fix.yaml'), 'utf8')).spec).agent;
    expect(agent.with.max_turns).toBe('40');
    expect(agent.with.prompt).toContain('findings.json');
    expect(agent.with.prompt).toContain('summary.md');
    expect(agent.with.prompt).toContain('exactly one');
    expect(agent.with.prompt).not.toMatch(/scripts\//);
    expect(agent.with.env.HARNESS_API_KEY).toBeUndefined();
  });
});
