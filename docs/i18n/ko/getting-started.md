<!-- docs/getting-started.md(원본 커밋: a7b9cee)의 커뮤니티가 관리하는 번역본입니다 — 영어 버전이 공식 버전입니다. -->

# 시작하기

<!-- See the authoritative English page for the latest installation status. -->

## 설치

Lightwork는 소스 코드에서 설치합니다. Python 3.11–3.12와 Git이 필요합니다. macOS, Linux, Windows용 명령은 [소스 설치 절차](../../source-install.md)에 나와 있습니다. 미리 빌드된 바이너리, PyPI 패키지, 컨테이너 이미지는 아직 게시되지 않았습니다. 현재 게시된 릴리스가 없으므로 `main`에서 설치하세요.

그런 다음 `lightwork dashboard`를 실행하고 <http://127.0.0.1:8765>를 열어 소유자와 모델 제공자 설정을 마치세요.

## 첫 실행

```bash
maverick init
```

마법사는 2분 정도 걸리며 `~/.maverick/config.toml`과 `~/.maverick/.env`를 기록합니다.

그다음:

```bash
maverick start "Build a CLI that emails me a digest of today's top Hacker News stories — research the API, write it, and verify it runs"
```

## 스웜이 목표를 분해하는 과정 지켜보기

두 번째 터미널에서 `maverick monitor`를 실행하세요. 오케스트레이터가 목표를 계획한 다음, 병렬로 일하는 전문 하위 에이전트들을 생성합니다. 여기서는 리서처가 API를 파악하고, 코더가 도구를 작성하며, 베리파이어가 그것을 실행해 봅니다.

```
Goal #1 active  2m elapsed
Build a CLI that emails me a digest of today's top Hacker News stories

Plan tree
  ├─        done  #2 Research the Hacker News Firebase API
  ├─      active  #3 Write the digest CLI (fetch + format + send)
  ├─      active  #4 Verify it runs and emails a sample digest
  ├─     pending  #5 Write a short usage README

Latest episode #7 (running)  $0.0431  in=18,204 out=2,910 tools=11

Recent activity
  4s ago [researcher] decision: top stories live at /v0/topstories.json, then /v0/item/<id>.json
  3s ago [coder] tool_call: write_file hn_digest.py (118 lines)
  1s ago [verifier] tool_call: run "python hn_digest.py --dry-run" -> printed 10 stories

Cumulative spend on this DB: $0.21
```

작업이 끝나면:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## 일시 중지 / 재개

스웜에 사용자만 답할 수 있는 질문이 생기면, 스웜은 일시 중지하고 질문을 대기열에 넣습니다.

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

목표는 재시작 후에도 유지됩니다. 노트북을 덮고 내일 다시 돌아와도 됩니다.

## 실행이 만든 파일 편집 되돌리기

워크스페이스 저널을 활성화하면(`[workspace] journal = true`, 또는 마법사의
*Workspace journal* 단계에서 예 선택), 에이전트가 파일 도구로 덮어쓰거나
생성하는 모든 파일이 변경 전에 기록됩니다:

```bash
maverick journal list --goal 12     # 무엇이 변경되었는지
maverick journal diff --goal 12     # 실행 전 상태와 현재 디스크의 차이
maverick journal revert --goal 12   # 최신 항목부터 모든 파일 복원
```

되돌리기는 서명된 `workspace_revert` 감사 행을 기록하고 저널을 보관
처리합니다. 셸을 통한 변경(`rm`, `mv`, 리디렉션)은 저널에 기록되지 않으며 —
감사 추적이 해당 명령을 기록합니다.

## 지켜본 작업으로 나만의 전문 에이전트 만들기

작업을 말로 설명할 필요는 없습니다. 직접 보여주면 됩니다. 누군가가 그 일을 수행하는
순서대로 된 기록(그들이 취한 동작과 그 이유에 대한 설명)을 JSONL 또는 간단한 접두사가
붙은 텍스트로 캡처한 다음, 그 파일을 Lightwork에 건네주세요.

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

이 명령은 시연을 파싱해 초안 전문 에이전트를 유도하고, 도출된 워크플로를 보여준 뒤,
저장하기 전에 사용자의 승인을 기다립니다. 비밀 정보는 입구에서 마스킹되며, 초안은
설명으로 만든 팩과 동일한 역량 제한(capability clamp)과 페르소나 스캔을 그대로
상속받습니다. 사용자가 승인하지 않으면 아무것도 활성화되지 않습니다. 유용한 플래그:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm`은 관찰된 단계를 결정론적으로 그대로 반영합니다(도구 = 사람이 실제로 사용한
것). 이 플래그를 빼면 모델이 기록을 바탕으로 제안하도록 할 수 있습니다.

대화형으로 팩을 구성할 때도 동일한 에이전트 팩토리 흐름이 실행됩니다.

```bash
maverick onboard
```

승인하면 이제 `onboard`가 팩을 프로비저닝합니다. 워크플로에 필요한 카탈로그 스킬을
설치하고, 기본 제공되지 않는 선언된 도구를 합성하므로, 갓 승인된 전문 에이전트는 첫
실행부터 자기 일을 할 수 있도록 갖춰집니다. (이 단계는 `[self_learning]` /
`provision_packs` 설정을 따르며, 팩의 제한된 범위를 결코 넓히지 않습니다.)

## 음성 입력(내장, 오프라인)

대시보드의 마이크 버튼과 `transcribe_audio` 도구는 공급자 키 없이
동작합니다. 로컬 Whisper 엔진은 대시보드 패키지에 포함되어 있으며,
앱을 열어도 기본적으로 모델 파일을 다운로드하지 않습니다.
**Settings → Models**의 음성 받아쓰기 섹션에서 전역 관리자는 설정된 모델의 출처와 크기(기본 모델은
약 148 MB)를 확인한 뒤 모델을 검사하거나 다운로드할 수 있습니다.
페이지를 새로고침해도 진행 상황은 유지되고, 취소하면 완료되지 않은 다운로드가
삭제되며, 실패한 경우 같은 화면에서 다시 시도할 수 있습니다. 기존 파일은
정확한 크기와 체크섬 검사를 통과해야 검증된 것으로 표시됩니다. 모델 검증은
음성 엔진이 로드되었거나 마이크가 작동한다는 보장은 아닙니다.

설치 프로그램은 시작 시 다운로드를 허용할지 명시적으로 묻습니다. 저장된
`[voice] auto_fetch_model = true` 또는 `MAVERICK_VOICE_AUTO_FETCH=1`은
계속 시작 시 다운로드를 활성화합니다. 리디렉션을 포함해 네트워크 정책은
항상 적용됩니다. 관리형 사용자 지정 모델 경로와 선택한 클라우드 음성 백엔드의
설정은 유지되며, 이 화면에서 자동으로 바꾸지 않습니다. CLI도 사용할 수 있습니다:

```bash
maverick voice setup    # 체크섬 검증된 모델 다운로드(약 148 MB)
maverick voice status   # 사용 가능한 음성 인식 백엔드 확인
maverick voice transcribe clip.wav   # 파이프라인 동작 테스트
```

시스템 엔진을 선호한다면 PATH의 `whisper.cpp` 바이너리
(`brew install whisper-cpp`)나 faster-whisper도 같은 체인에 연결됩니다.
`[voice] stt_backend = "local"`을 설정하면 OpenAI/Groq 키가 있어도
오디오가 머신 밖으로 나가지 않습니다.

## 모델 또는 공급자 변경

설치 후 **Settings → Provider keys** 또는 **Settings → Models**에서 선택을 변경하세요.
배포에서 관리하는 값은 화면에 표시됩니다. 그런 값을 변경하려면 설치 관리자가
원본 설정을 바꿔야 새 값이 적용됩니다. 기본 설정에 관한 내용은
[`configuration.md`](../../configuration.md)를 참고하세요.

## 데이터가 저장되는 위치

| 파일 | 내용 |
|---|---|
| `~/.maverick/config.toml` | 사용자 설정(배포, 모델, 안전, 예산) |
| `~/.maverick/.env` | API 키(chmod 600) |
| `~/.maverick/world.db` | 영속적인 월드 모델: 목표, 사실, 에피소드 |
| `~/.maverick/skills/` | 성공한 실행에서 자동으로 증류된 SKILL.md 파일 |
| `~/maverick-workspace/` | 샌드박스 기본 작업 디렉터리 |
| `~/.maverick/learned-skills/` | 학습 루프가 증류한 스킬 |
| `~/.maverick/dreams/` | 통합된 통찰, 리허설 큐, 학습 스냅샷 |

Lightwork는 위 파일을 사용 중인 배포 환경에 저장합니다. 클라우드 AI 공급자나
연결된 서비스를 활성화하면 이를 통해 전송되는 작업 내용이 배포 환경 밖으로
나갈 수 있습니다. 사용하기 전에 각 공급자, 커넥터 및 외부 전송 정책을 확인하세요.

실행을 몇 번 쌓고 나면, 학습 영역은 네 가지 명령으로 요약됩니다. `maverick dream`(경험
통합), `maverick hindsight`(학습이 도움이 되었는가, 아니면 퇴보했는가?),
`maverick proof`(산출물, 절감한 비용, ROI), 그리고 `maverick domains-lint`(에이전트
전문 카탈로그 감사)이며, 여기에 `maverick domains-audit`(거버넌스 태세: 각
에이전트가 무엇에 접근하고, 무엇을 거부하며, 무엇을 거절하는지)와
`maverick domains-eval --check`(행동 골든 케이스)가 더해집니다.
