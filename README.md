# IAM Policy Lens

[![Tests](https://github.com/alefkaue/iam-policy-lens/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/iam-policy-lens/actions/workflows/tests.yml)

Revisor **offline** de políticas AWS IAM em Python. Identifica padrões que merecem revisão: ações com curingas, permissões sensíveis de identidade, recursos amplos, principal `*` e uso de `NotAction`/`NotResource` em statements Allow.

## Demonstração

Python 3.11+; somente biblioteca padrão. Não exige conta AWS, credenciais ou dependências externas.

```console
git clone https://github.com/alefkaue/iam-policy-lens.git
cd iam-policy-lens
python iam_policy_lens.py examples/risky.json
python iam_policy_lens.py examples/scoped.json
python -m unittest discover -s tests -v
```

O exemplo `risky.json` gera `wildcard_action`, `all_resources` e `sensitive_identity_action`; o exemplo `scoped.json` não aciona as regras implementadas. Código de saída: **0** sem achados, **1** com achados, **2** erro. Não aplica políticas nem faz chamadas à AWS.

## Como revisar um achado

Cada item contém `rule`, `severity`, `location` (JSON Pointer), `evidence`, `conditional` e uma recomendação. Ações sensíveis são comparadas com os padrões da política sem diferenciar maiúsculas/minúsculas. Condições são preservadas como evidência e explicitamente marcadas como não avaliadas.

1. Localize o statement pelo campo `location`.
2. Relacione as ações ao caso de uso real.
3. Verifique se o serviço permite restringir `Resource` por ARN.
4. Revise condições e políticas relacionadas na AWS antes de concluir sobre acesso efetivo.

## Arquitetura e limites

`JSON → validação estrutural básica → revisão de Allow → achados JSON`. A validação não implementa o schema completo da AWS. Statements Deny não geram achados e não anulam achados de Allow: a ferramenta não calcula permissões efetivas, SCPs, boundaries, sessões ou políticas de recursos. Não comprova acesso público nem escalada de privilégio. Algumas ações precisam de `Resource: "*"`; esse achado é classificado como `review`.

O catálogo de ações sensíveis é pequeno e explícito no código. Ausência de achados significa apenas ausência dos padrões implementados. Próxima evolução: fixtures por serviço e exportação SARIF.

## Referências

- [AWS: NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html)
- [AWS: Resource](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html)
- [AWS: Condition](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html)

Projeto educacional independente, desenvolvido com assistência de IA, com exemplos sintéticos e testes reproduzíveis. Licença MIT.
