# Traceability matrix

| Requirement | CIA / CRA property | Counters | DFD element | Test |
|---|---|---|---|---|
| SR-1 | Confidentiality | MC-1 | P3, D1 | test_sr1 |
| SR-2 | Confidentiality | MC-3 | P1, D2 | test_sr2 |
| SR-3 | Confidentiality | traffic interception | F2 (TB1) | test_sr3 |
| SR-4 | Confidentiality | MC-2 | P4 | test_sr4 |
| SR-5 | Integrity | injection | P2, P4 | test_sr5 |
| SR-6 | Integrity | tampering in DB | P1, D2 | test_sr6 |
| SR-7 | Availability | MC-1, DoS | P2, P3 | test_sr7 |
| SR-8 | Availability | data loss | P5, D4 | restore drill |
| SR-9 | Integrity / accountability | repudiation | D3 | test_sr9 |
| SR-10 | CRA: vulnerability handling, secure by default, SBOM | supply chain | whole app | CI |
| CR-1, CR-2 | Confidentiality | MC-1 | P3 | test_cr1 |
| CR-3, CR-4 | Confidentiality | MC-2 | P4 | test_cr3, test_sr4 |
| CR-5, CR-6 | Confidentiality | MC-3 | P5, D4 | review |
| PR-1, PR-2 | Privacy | excessive collection | P3, D1, D2 | test_pr2 |
