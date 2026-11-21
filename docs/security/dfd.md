# Data flow diagram (level 1)
![DFD](dfd.png)
```mermaid
flowchart LR
  subgraph TB1["Internet / browser"]
    E1[/"E1 User"/]
    E2[/"E2 Admin"/]
    P1(("P1 Web client\n(AES-GCM in browser)"))
  end
  subgraph TB2["Perimeter"]
    P2(("P2 Reverse proxy\nTLS, body limit"))
  end
  subgraph APP["Application network"]
    P3(("P3 Auth"))
    P4(("P4 Notes"))
    P5(("P5 Backup job"))
  end
  subgraph DATA["Data layer"]
    D1[("D1 Users")]
    D2[("D2 Notes (ciphertext)")]
    D3[("D3 Audit log")]
  end
  subgraph TB4["Third party"]
    E3[/"E3 SMTP (planned)"/]
  end
  subgraph TB5["External storage"]
    D4[("D4 Encrypted backups")]
  end
  E1 -->|F1 password, text| P1
  P1 -->|F2 HTTPS| P2
  E2 -->|F10 admin requests| P2
  P2 -->|F3| P3
  P2 -->|F5| P4
  P3 <-->|F4| D1
  P4 <-->|F6| D2
  P3 -->|F7| D3
  P4 -->|F7| D3
  P3 -.->|F8 reset mail| E3
  D1 --> P5
  D2 --> P5
  P5 -->|F9| D4
```

Trust boundaries: TB1 internet/browser | perimeter, TB2 perimeter | application network, TB3 application | data layer,
TB4 system | third-party SMTP, TB5 data layer | external backup storage.
Secure-by-design annotations: see `assets-and-gaps.md`.

