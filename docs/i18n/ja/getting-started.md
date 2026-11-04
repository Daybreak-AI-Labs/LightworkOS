<!-- これは docs/getting-started.md（翻訳元コミット: a7b9cee）のコミュニティによって維持されている翻訳です。英語版が正式版です。 -->

# はじめに

<!-- See the authoritative English page for the latest installation status. -->

## インストール

Lightwork はソースコードからインストールします。Python 3.11〜3.12 と Git が必要です。macOS、Linux、Windows 向けのコマンドは[ソースからのインストール手順](../../source-install.md)に記載しています。ビルド済みバイナリ、PyPI パッケージ、コンテナイメージはまだ公開していません。現在公開されているリリースはありません。`main` からインストールしてください。

その後 `lightwork dashboard` を実行し、<http://127.0.0.1:8765> を開いて所有者とモデルプロバイダーの設定を完了してください。

## 初回実行

```bash
maverick init
```

ウィザードの所要時間は 2 分ほどです。`~/.maverick/config.toml` と `~/.maverick/.env` を書き出します。

次に、以下を実行します。

```bash
maverick start "Build a CLI that emails me a digest of today's top Hacker News stories — research the API, write it, and verify it runs"
```

## スウォームが目標を分解する様子を見る

2 つ目のターミナルで `maverick monitor` を実行します。オーケストレーターが目標の計画を立て、並列で動作する専門のサブエージェントを起動します。この例では、リサーチャーが API を特定し、コーダーがツールを書き、ベリファイアがそれを実行して確認します。

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

完了したら:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## 一時停止と再開

あなたにしか答えられないことが必要になると、スウォームは一時停止し、質問をキューに入れます。

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

目標は再起動後も保持されます。ノート PC を閉じて、明日また戻ってきても問題ありません。

## 実行によるファイル編集を元に戻す

ワークスペースジャーナルを有効にすると（`[workspace] journal = true`、または
ウィザードの *Workspace journal* ステップで「はい」を選択）、エージェントが
ファイルツールで上書き・作成するすべてのファイルが、変更の前に記録されます:

```bash
maverick journal list --goal 12     # 何が変更されたか
maverick journal diff --goal 12     # 実行前の状態と現在のディスクの差分
maverick journal revert --goal 12   # 新しい順にすべてのファイルを復元
```

リバートは署名付きの `workspace_revert` 監査行を書き込み、ジャーナルを
アーカイブします。シェル経由の変更（`rm`、`mv`、リダイレクト）はジャーナルに
記録されません — それらのコマンドは監査証跡に記録されます。

## 観察したタスクから自分専用のスペシャリストを作る

仕事を言葉で説明する必要はありません。実際にやって見せることもできます。誰かが作業をしている様子（取った行動と、その理由についての説明）を順序付きの記録として JSONL かシンプルな接頭辞付きテキストで取得し、そのファイルを Lightwork に渡してください。

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

これはデモンストレーションを解析し、ドラフトのスペシャリストを生成し、導出されたワークフローを表示して、保存する前にあなたの承認を待ちます。シークレットは入り口で秘匿化され、ドラフトは説明から作成したパックと同じ機能の制限とペルソナスキャンを引き継ぎます。あなたが「はい」と言わない限り、何も有効化されません。便利なフラグ:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` は観察されたステップを決定論的にそのまま再現します（ツール = その人が使ったもの）。これを外すと、モデルがトランスクリプトから提案できるようになります。

同じエージェントファクトリーのフローは、対話形式でパックを構築するときにも実行されます。

```bash
maverick onboard
```

承認すると、`onboard` はパックをプロビジョニングするようになりました。ワークフローに必要なカタログスキルをインストールし、ビルトインではない宣言済みツールを合成するので、承認されたばかりのスペシャリストは最初の実行からその仕事をこなす準備が整っています。（このステップは `[self_learning]` / `provision_packs` の設定を尊重し、パックの制限された範囲を広げることは決してありません。）

## 音声入力(内蔵・オフライン)

ダッシュボードのマイクボタンと `transcribe_audio` ツールは、プロバイダーの
API キーなしで動作します。ローカル Whisper エンジンはダッシュボード
パッケージに同梱されていますが、アプリを開いても既定ではモデルファイルは
ダウンロードされません。**Settings → Models** の音声入力セクションでは、
グローバル管理者が設定済みモデルの取得元とサイズ（既定のモデルは約 148 MB）を
確認し、モデルをチェックまたはダウンロードできます。ページを再読み込みしても
進捗は保持され、キャンセルすると未完了のダウンロードが削除されます。失敗した
場合は同じ画面から再試行できます。既存のファイルは、サイズとチェックサムが
完全に一致するまで検証済みと表示されません。モデルの検証は、音声エンジンの
読み込みやマイクの動作を保証するものではありません。

インストーラーは起動時のダウンロードを許可するか明示的に尋ねます。保存済みの
`[voice] auto_fetch_model = true` または `MAVERICK_VOICE_AUTO_FETCH=1` は
引き続き起動時のダウンロードを有効にします。リダイレクトを含め、ネットワーク
ポリシーは常に適用されます。管理者が設定したカスタムモデルのパスと選択済みの
クラウド音声バックエンドは維持され、この設定画面で無断で置き換えられることは
ありません。CLI も利用できます:

```bash
maverick voice setup    # チェックサム検証済みモデルを取得(約148 MB)
maverick voice status   # 利用可能な音声認識バックエンドを確認
maverick voice transcribe clip.wav   # パイプラインの動作確認
```

システムのエンジンを使いたい場合は、PATH 上の `whisper.cpp` バイナリ
(`brew install whisper-cpp`)や faster-whisper も同じチェーンに組み込めます。
`[voice] stt_backend = "local"` を設定すると、OpenAI/Groq のキーがあっても
音声はマシンの外に出ません。

## モデルやプロバイダーの変更

インストール後は、**Settings → Provider keys** または **Settings → Models** を開いて
選択を変更できます。デプロイ側で管理されている値は画面に示されます。その値を
有効に変更するには、インストール管理者が元の設定を変更する必要があります。
基になる設定については [`configuration.md`](../../configuration.md) を参照してください。

## データの保存場所

| ファイル | 内容 |
|---|---|
| `~/.maverick/config.toml` | 設定（デプロイ、モデル、安全性、予算） |
| `~/.maverick/.env` | API キー（chmod 600） |
| `~/.maverick/world.db` | 永続的なワールドモデル: 目標、事実、エピソード |
| `~/.maverick/skills/` | 成功した実行から自動的に蒸留された SKILL.md ファイル |
| `~/maverick-workspace/` | サンドボックスのデフォルト作業ディレクトリ |
| `~/.maverick/learned-skills/` | 学習ループによって蒸留されたスキル |
| `~/.maverick/dreams/` | 統合された知見、リハーサルキュー、学習スナップショット |

Lightwork は上記のファイルを利用中のデプロイ環境に保存します。クラウド AI
プロバイダーや接続サービスを有効にすると、それらを通じて送信される作業内容が
その環境の外に出ることがあります。利用前に、各プロバイダー、コネクター、
外部通信ポリシーを確認してください。

ある程度の実行を重ねたら、学習面は 4 つのコマンドに集約されます。`maverick dream`（経験を統合する）、`maverick hindsight`（学習は役立ったか、それとも後退したか？）、`maverick proof`（成果物、回避できたコスト、ROI）、そして `maverick domains-lint`（スペシャリストカタログを監査する）に加えて、`maverick domains-audit`（ガバナンス態勢: 各エージェントが何にアクセスでき、何を拒否し、何を却下するか）と `maverick domains-eval --check`（振る舞いのゴールデンケース）です。
