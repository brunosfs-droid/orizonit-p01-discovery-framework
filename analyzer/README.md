# P01 Discovery Analyzer v0.2

O Analyzer v0.2 mantém as 10 regras da versão anterior e adiciona controles de inatividade AD, secure channel Windows, compartilhamentos, FTP e política local de senha Linux.

## Compatibilidade
- Collector Windows/AD v0.2.1 e v0.3.0
- Collector Linux v0.2.0 e v0.3.0
- Ruleset v0.2.0

Novos handlers ignoram campos ausentes, portanto JSONs antigos continuam analisáveis.

## Uso
```bash
python3 P01_Discovery_Analyzer_v0.2.py \
  --input-dir ./inputs \
  --output-dir ./output \
  --rules-file ./P01_Rules_v0.2.json \
  --run-label LAB-P01-v0.3
```

## Regras
O ruleset possui 19 regras habilitadas. Thresholds atuais incluem 90 dias para inatividade AD e 14 caracteres como baseline configurável para comprimento mínimo de senha.

## Princípios
- análise determinística;
- evidência rastreável;
- nenhuma remediação automática;
- suporte a `confidence` para distinguir achados confirmados de condições que exigem validação;
- read-only.
