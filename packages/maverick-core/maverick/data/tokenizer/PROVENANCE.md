The unmodified cl100k_base vocabulary is distributed with Lightwork so the
default local token estimate works without a network connection or an existing
tokenizer cache. Customer text is counted as ordinary text, including literal
special-token markers. This is a BPE estimate, not a provider billing count.

Vocabulary source:
https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken

SHA-256:
223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7

Encoding metadata and the expected vocabulary fingerprint are from the
cl100k_base constructor in OpenAI tiktoken 0.14.0:
https://github.com/openai/tiktoken/blob/0.14.0/tiktoken_ext/openai_public.py

The upstream MIT license notice is retained in TIKTOKEN_LICENSE.txt. Runtime
loading checks the bundled vocabulary against the upstream fingerprint and
constructs tiktoken.Encoding directly; it never fetches a replacement or changes
the user's cache settings.
