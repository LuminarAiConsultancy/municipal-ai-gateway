"""End-to-end integration smoke test.

Exercises the full proxy flow: auth → scrub → forward → scrub response → log.
Uses respx to mock the upstream provider — no real API calls are made.
"""

import respx
from httpx import Response
from sqlalchemy.orm import Session

from main import RequestLog


OPENAI_URL = "https://api.openai.com/v1/chat/completions"


class TestEndToEnd:
    @respx.mock
    def test_clean_request_round_trip(self, test_client, valid_api_key, db_engine):
        """Valid key + clean body + mocked upstream → 200, logged, chain intact.

        Verifies:
          - Proxy returns 200
          - Request is logged to the database
          - Audit chain is intact (verify endpoint passes)
          - No PII was scrubbed (body was clean)
        """
        respx.post(OPENAI_URL).mock(
            return_value=Response(
                200,
                json={
                    "id": "chatcmpl-test123",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "4"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 1},
                },
            )
        )

        r = test_client.post(
            "/v1/openai/v1/chat/completions",
            headers={
                "X-Gateway-Key": valid_api_key,
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "What is 2 plus 2?"}],
            },
        )

        # ── Proxy returned the upstream response ──
        assert r.status_code == 200
        body = r.json()
        assert body["choices"][0]["message"]["content"] == "4"

        # ── Request was logged ──
        with Session(db_engine) as session:
            logs = session.query(RequestLog).all()
            assert len(logs) == 1

            log = logs[0]
            assert log.provider == "openai"
            assert log.method == "POST"
            assert log.response_status == 200
            assert log.department == "Planning"
            assert log.staff_key_id is not None

            # Body was clean — no PII scrubbed.
            assert log.pii_detections_request == 0
            assert log.pii_detections_response == 0
            assert log.pii_types_found is None

            # Hash chain fields are populated.
            assert log.chain_hash is not None
            assert len(log.chain_hash) == 64
            assert log.previous_hash is None  # first entry

        # ── Audit chain is intact ──
        verify = test_client.get("/audit/verify")
        vdata = verify.json()
        assert vdata["status"] == "ok"
        assert vdata["entries_checked"] == 1
