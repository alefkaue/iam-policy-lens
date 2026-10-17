"""Offline heuristic review of IAM policies; does not compute effective access."""
import argparse
import fnmatch
import json
from pathlib import Path
import sys

SENSITIVE = ('iam:PassRole', 'iam:CreateAccessKey', 'iam:AttachUserPolicy',
             'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
             'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole')


def strings(value, field):
    result = [value] if isinstance(value, str) else value
    if not isinstance(result, list) or not result or any(not isinstance(x, str) or not x for x in result):
        raise ValueError(f'{field} must be a string or nonempty list of strings')
    return result


def audit(policy):
    if not isinstance(policy, dict) or 'Statement' not in policy:
        raise ValueError('policy must contain Statement')
    statements = policy['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError('Statement must be an object or nonempty list')
    findings = []
    for index, statement in enumerate(statements):
        location = f'/Statement/{index}' if isinstance(policy['Statement'], list) else '/Statement'
        if not isinstance(statement, dict) or statement.get('Effect') not in ('Allow', 'Deny'):
            raise ValueError(f'{location}: invalid Effect or statement')
        for normal, inverse in [('Action', 'NotAction'), ('Resource', 'NotResource')]:
            if normal in statement and inverse in statement:
                raise ValueError(f'{location}: {normal} and {inverse} are mutually exclusive')
            for field in (normal, inverse):
                if field in statement:
                    strings(statement[field], field)
        if 'Action' not in statement and 'NotAction' not in statement:
            raise ValueError(f'{location}: Action or NotAction required')
        if 'Condition' in statement and not isinstance(statement['Condition'], dict):
            raise ValueError(f'{location}: Condition must be an object')
        if statement['Effect'] == 'Deny':
            continue

        def add(rule, severity, evidence, recommendation):
            findings.append(dict(rule=rule, severity=severity, location=location,
                evidence=evidence, conditional=bool(statement.get('Condition')),
                recommendation=recommendation))

        actions = strings(statement.get('Action', []), 'Action') if 'Action' in statement else []
        resources = strings(statement['Resource'], 'Resource') if 'Resource' in statement else []
        if 'NotAction' in statement:
            add('allow_not_action', 'high', statement['NotAction'], 'Revise o conjunto complementar de ações permitido.')
        if 'NotResource' in statement:
            add('allow_not_resource', 'high', statement['NotResource'], 'Prefira recursos explicitamente delimitados quando possível.')
        wildcards = [a for a in actions if '*' in a or '?' in a]
        if wildcards:
            add('wildcard_action', 'high', wildcards, 'Substitua padrões amplos pelas ações necessárias ao caso de uso.')
        if '*' in resources:
            add('all_resources', 'review', ['*'], 'Verifique se a ação permite escopo por ARN; algumas exigem Resource *.')
        sensitive = sorted({action for action in SENSITIVE for pattern in actions
                            if fnmatch.fnmatchcase(action.lower(), pattern.lower())})
        if sensitive:
            add('sensitive_identity_action', 'high', sensitive, 'Revise delegação, recursos e condições; a ação isolada não prova escalada.')
        principal = statement.get('Principal')
        public = principal == '*'
        if isinstance(principal, dict):
            public = any('*' in strings(value, 'Principal') for value in principal.values())
        if public:
            add('wildcard_principal', 'high', principal, 'Revise quem pode assumir o papel ou acessar o recurso, incluindo condições.')
        if statement.get('Condition'):
            add('condition_not_evaluated', 'review', statement['Condition'], 'Condições foram preservadas, mas não avaliadas; revise o contexto AWS.')
    return dict(statements=len(statements), findings=findings, mode='heuristic-not-effective-permissions')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('policy', type=Path)
    args = parser.parse_args()
    try:
        report = audit(json.loads(args.policy.read_text(encoding='utf-8')))
    except (OSError, ValueError) as error:
        parser.exit(2, f'Error: {error}\n')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
