# 🛡️ Falco·Tetragon으로 구현하는 Cloud-Native 런타임 보안 파이프라인
> **eBPF · Falco · Tetragon** 기반 런타임 보안 + **Kafka · NiFi · OpenSearch · Grafana** 분석 파이프라인  
> K-Shield Junior 16기 | 2조 | 2026.05.04 ~ 2026.05.21

---

## 프로젝트 개요

Cloud-Native 환경에서 **GitOps 자동 배포 흐름을 악용한 공급망 공격(Supply Chain Attack)** 이후 발생하는 런타임 위협을 실시간으로 탐지·차단하고, 자동 분석·시각화까지 연결하는 End-to-End SecOps 자동화 환경을 구축·검증한 프로젝트입니다.

npm 타이포스쿼팅, GitLab 계정 탈취 등으로 오염된 코드가 GitOps 배포 흐름을 타고 운영 Pod까지 도달하는 공격 경로를 재현하고, **eBPF 커널 수준**에서 이를 탐지·차단합니다.

---

## 👥 팀원

| 역할 | 이름 |
|------|------|
| PM | 최정환 |
| 팀원 | 고성운 |
| 팀원 | 박현수 |
| 팀원 | 윤지환 |
| 팀원 | 이준혁 |

---

## 🏗️ 시스템 아키텍처

### 인프라 구성 (GCP GCE VM 4대)

 <img width="745" height="390" alt="image" src="https://github.com/user-attachments/assets/ba5ec763-ab07-448d-9780-360245541f14" />


### 데이터 흐름

<img width="840" height="436" alt="image" src="https://github.com/user-attachments/assets/70465f43-ecb0-412b-87d1-651e0de329ad" />

---

## 🔧 핵심 기술 스택

| 카테고리 | 기술 |
|----------|------|
| **컨테이너 플랫폼** | Kubernetes (kubeadm, Cilium CNI) |
| **GitOps** | GitLab CE (Self-hosted) · Argo CD |
| **Runtime 탐지** | Falco (modern eBPF) · Falcosidekick |
| **Runtime 차단** | Tetragon (TracingPolicy + Sigkill) |
| **이벤트 수집** | Kafka (KRaft) · Filebeat |
| **데이터 가공** | Apache NiFi |
| **저장·검색** | OpenSearch |
| **시각화** | OpenSearch Dashboards · Grafana |
| **클라우드** | GCP GCE |
| **애플리케이션** | Node.js / Express |

---

## ⚔️ 공격 시나리오

### 시나리오 1 — 공급망 오염 기반 Initial Access

| 단계 | 공격 기법 | 내용 |
|------|-----------|------|
| 1 | npm Typosquatting | `axios`와 유사한 악성 패키지 게시, `postinstall` 스크립트로 자격증명 수집 |
| 2 | GitLab 계정 탈취 | CI/CD 배포 자격증명 탈취로 저장소 권한 확보 |
| 3 | 이미지 변조 | 오염된 이미지 태그(v1.0.8) + 백도어 엔드포인트 삽입 |
| 4 | GitOps 자동 배포 | Argo CD가 정상 변경으로 인식 → 운영 Pod에 자동 반영 |

### 시나리오 2 — Runtime 공격 탐지 및 차단

백도어 엔드포인트(`/api/internal/metrics?check=`)를 통해 수행되는 런타임 공격:

| 공격 단계 | 공격 내용 | MITRE ATT&CK | 탐지 | 차단 |
|-----------|-----------|--------------|------|------|
| 명령 실행 (RCE) | 컨테이너 내 임의 명령 실행 | TA0002 / T1059.004 | ✅ Falco | — |
| 민감 파일 접근 | `/etc/passwd` 등 접근 | TA0006 / T1552.001 | ✅ Falco | — |
| SA 토큰 접근 | ServiceAccount 토큰 탈취 시도 | TA0006 / T1552.001 | ✅ Falco | — |
| IMDS 접근 | 클라우드 자격증명 탈취 시도 | TA0006 / T1552.005 | ✅ Falco | ✅ Tetragon Sigkill |

---

## 🔍 탐지 정책

### Falco Custom Rules (4종)

```yaml
# 예시: RCE 탐지
- rule: Scenario RCE in Container
  desc: Detects command execution via backdoor endpoint
  condition: spawned_process and container and ...
  output: "RCE detected in container (cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [supply_chain, TA0002, T1059.004]
```

| 룰 이름 | 탐지 대상 | MITRE |
|---------|-----------|-------|
| Scenario RCE in Container | 컨테이너 내 명령 실행 | T1059.004 |
| Scenario Sensitive File Read | 민감 파일 접근 | T1552.001 |
| ServiceAccount Token Read | SA 토큰 접근 | T1552.001 |
| IMDS Access Attempt | 메타데이터 서버 접근 | T1552.005 |

### Tetragon TracingPolicy — IMDS Sigkill 차단

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: imds-block
spec:
  kprobes:
    - call: "tcp_connect"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values: ["169.254.169.254"]
      actions:
        - action: Sigkill
```

IMDS(`169.254.169.254`) 접근 시 커널 수준에서 즉시 프로세스 강제 종료.

---

## 📊 분석 파이프라인

```
Falco 이벤트
     │
Falcosidekick ──► Slack (Fast Path: 즉시 알람)
     │
     └──► Kafka (falco-events 토픽)
               │
             NiFi (JSON 파싱 · 필드 추출 · 정규화)
               │
          OpenSearch (인덱싱 · 장기 저장)
               │
    ┌──────────┴──────────┐
OpenSearch Dashboards   Grafana Dashboard
(개별 이벤트 탐색)      (보안 관제 시각화)

Tetragon 이벤트
     │
  Filebeat ──► Kafka (tetragon-events 토픽) ──► (동일 파이프라인)
```

---

## 🎯 주요 의의

| 의의 | 내용 |
|------|------|
| **End-to-End 검증** | 공급망 공격 유입 → 런타임 탐지·차단 → 분석·시각화까지 단일 프로젝트에서 완성 |
| **Invisible Monitoring** | 애플리케이션 코드 수정 없이 커널 수준(eBPF)에서 런타임 행위 관측·차단 |
| **이중 방어 구조** | Falco(탐지) + Tetragon(차단) 역할 분리로 운영 안전성과 보안 효과 균형 |
| **오픈소스 스택** | Apache 2.0 기반 OpenSearch 등 라이선스 부담 없는 상용 이전 가능 구성 |
| **Zone 기반 격리** | Red Zone(공격 대상) / Green Zone(분석·관제) 분리로 공격 영향 최소화 |

---

## 📁 프로젝트 구조

```
.
├── manifests/                  # Kubernetes YAML 파일
│   ├── kshield-shop/           # K-Shield Shop 애플리케이션
│   ├── falco/                  # Falco DaemonSet 설정
│   ├── tetragon/               # Tetragon TracingPolicy
│   ├── kafka/                  # Kafka KRaft 구성
│   ├── nifi/                   # NiFi Flow 구성
│   └── opensearch/             # OpenSearch 설정
├── rules/                      # 보안 룰 파일
│   ├── falco-custom-rules.yaml # Falco Custom Rules 4종
│   └── tetragon-imds-block.yaml# Tetragon IMDS 차단 정책
├── app/                        # K-Shield Shop (Node.js)
│   ├── src/
│   └── package.json
├── argocd/                     # Argo CD Application 설정
└── docs/                       # 문서
    └── final-report.pdf        # 최종 보고서
```

---

## 🚀 환경 구성 요약

### 사전 요구사항

- GCP GCE VM 4대 (추천 사양: e2-standard-4, Ubuntu 22.04 LTS)
- Kubernetes 1.28+ (kubeadm)
- Cilium CNI
- Self-hosted GitLab CE

### 핵심 컴포넌트 설치 순서

```bash
# 1. Kubernetes 클러스터 초기화
kubeadm init --pod-network-cidr=10.244.0.0/16

# 2. Cilium CNI 설치
helm install cilium cilium/cilium --namespace kube-system

# 3. Argo CD 설치
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 4. Falco 설치 (modern eBPF)
helm install falco falcosecurity/falco \
  --set driver.kind=modern_ebpf \
  --set falcosidekick.enabled=true

# 5. Tetragon 설치
helm install tetragon cilium/tetragon --namespace kube-system

# 6. 분석 파이프라인 (Kafka → NiFi → OpenSearch → Grafana)
kubectl apply -f manifests/kafka/
kubectl apply -f manifests/nifi/
kubectl apply -f manifests/opensearch/
```

---

## 📋 탐지 결과 요약

| 공격 단계 | 탐지 룰 | 탐지 | 차단 |
|-----------|---------|------|------|
| 명령 실행 (RCE) | Scenario RCE in Container | ✅ | — |
| 민감 파일 접근 | Scenario Sensitive File Read | ✅ | — |
| SA 토큰 접근 | ServiceAccount Token Read | ✅ | — |
| IMDS 접근 | IMDS Access Attempt + Tetragon | ✅ | ✅ (Sigkill) |

---

## 📚 참고 기술

- [Falco](https://falco.org/) — Cloud-Native Runtime Security
- [Tetragon](https://tetragon.io/) — eBPF-based Security Observability & Runtime Enforcement
- [Argo CD](https://argo-cd.readthedocs.io/) — GitOps Continuous Delivery
- [Apache Kafka](https://kafka.apache.org/) — Distributed Event Streaming
- [Apache NiFi](https://nifi.apache.org/) — Data Flow Automation
- [OpenSearch](https://opensearch.org/) — Search & Analytics (Apache 2.0)
- [Grafana](https://grafana.com/) — Observability & Visualization
- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial Tactics & Techniques

---

## 📄 라이선스

본 프로젝트는 K-Shield Junior 16기 교육 목적으로 제작되었습니다.

---

> **K-Shield Junior 16기 2조** | 정보보호 운영 Project
