# VAIXLNS

VAIXLNS هو إطار معماري يفرق بوضوح بين:

- NEXENT: محرك توليد القدرات والمعرفة والنسخ البديلة والتعافي الذكي
- VX: محرك التنفيذ السيادي والقرار والتحقق والالتزام بالحقيقة

المبدأ الأساسي:

NEXENT may generate the future. VX decides which future is allowed to become real.

## الفكرة المركزية

نحو نظام لا يركز على "وكيل ذكي" فحسب، بل على:

Knowledge → Capability → Proof → Authority → Reality → Evidence → Evolution

## طبقات النظام

### 1. NEXENT
- اكتشاف المعرفة
- فهم السياق
- تركيب القدرات
- بناء الـ Capability IR
- توليد Proof Package
- تحليل Counterfactual
- التنبؤ والاختبار والتعلم من الواقع

### 2. VX
- التحقق من النظم
- التحقق من البراهين
- الصلاحية / Authorization
- التنف��ذ المحدود
- الالتزام بالمعايير
- التسجيل والتتبع
- إعادة التشغيل والتجربة

## هيكل المستودع

```text
vaixlns-nexent-vx/
├── README.md
├── pyproject.toml
├── src/
│   └── vaixlns/
│       ├── __init__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── capability.py
│       │   ├── epistemic.py
│       │   └── proof.py
│       └── vx/
│           ├── __init__.py
│           ├── execution_gate.py
│           ├── runtime.py
│           └── state_machine.py
├── examples/
│   └── demo.py
├── tests/
│   └── test_capability.py
└── docs/
    └── architecture.md
```

## التشغيل السريع

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python examples/demo.py
pytest -q
```

## المثال الأساسي

```python
from vaixlns.core.capability import Capability, ResourceContract
from vaixlns.core.proof import ProofPackage
from vaixlns.vx.execution_gate import SovereignExecutionGate

cap = Capability(
    identity="CAP-001",
    name="semantic_repair",
    intent="repair broken dependency graph",
    allowed_actions=["analyze", "suggest_patch", "replay"],
    forbidden_actions=["mutate_canon_without_governance"],
    resource_contract=ResourceContract(
        max_cpu_ms=250,
        max_memory_mb=256,
        network_allowed=False,
        determinism_required=True,
    ),
)

proof = ProofPackage(
    capability_id=cap.identity,
    dependency_proof={"status": "pass"},
    invariant_proof={"status": "pass"},
    determinism_test={"status": "pass"},
    negative_tests=[{"status": "pass"}],
    evidence_manifest={"digest": "abc123"},
)

gate = SovereignExecutionGate()
result = gate.authorize(cap, proof)
print(result)
```

## ملاحظات التصميم

هذا المستودع لا يركز فقط على الـ Agent/Tool/Result التقليدي، بل على:

- Capability synthesis
- Proof-carrying execution
- Epistemic state separation
- Capability closure
- Temporal truth
- Evidence ledger
- Deterministic runtime boundary

## الخلاصة

الهدف ليس أن يكون NEXENT "أذكى" فقط، بل أن يكون:

- مولدًا للقدرات
- ومُنظّمًا للمعرفة
- ومُكوّنًا للبرهان

بينما VX هو:

- نظام القرار السيادي
- محرك التحقق والاعتماد
- نقطة تنفيذ الواقع المؤكد

