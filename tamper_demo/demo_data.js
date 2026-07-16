// Generated from demo/demo-packet-unanchored.zip -- see generate_demo_packet.py.
const DEMO_PACKET = {
  "events": [
    {
      "action_id": "refund-demo-001",
      "action_type": "refund_request",
      "actor_id": "support-agent-1",
      "event_hash": "ae4149b008f27ed499c8c69ba6b89f6a58e215f22a5ca1e4c5de1d30398b2757",
      "event_id": "efba5964c572bfc805f2478f38867f2934f8f35a26bd5f5a6628371bc2c01231",
      "event_type": "ActionSubmitted",
      "payload": {
        "action_packet_hash": "a1294847ccaffafd359c3cfe88a8c3df4e651b531825327bf92b09b202455f5d"
      },
      "payload_hash": "96f96ffd7a40e7fc4947f92e3c33a004d68561965dc1839b29dda486489a3e17",
      "previous_event_hash": null,
      "schema_version": "ledger_event.v1",
      "tenant_id": "demo-tenant",
      "timestamp": "2026-07-15T09:00:00+00:00",
      "workspace_id": "demo-workspace"
    },
    {
      "action_id": "refund-demo-001",
      "action_type": "refund_request",
      "actor_id": "gateway",
      "event_hash": "bf63227bf0efc9d37cf5e96197f175442a35160dd617f5a21989df5102fd1316",
      "event_id": "fd475096e094e1c8f8e2f12b190aad493be61b2d7fe68f97a961690369610f0f",
      "event_type": "ScopeEvaluated",
      "payload": {
        "action_hash": "a1294847ccaffafd359c3cfe88a8c3df4e651b531825327bf92b09b202455f5d",
        "breach_dimensions": [],
        "executed_action": {
          "action_id": "refund-demo-001",
          "action_type": "refund_request",
          "amount": "1200.00"
        },
        "intent_scope": {
          "action_types": [
            "refund_request"
          ],
          "max_amount": "5000.00",
          "tenant_id": "demo-tenant"
        },
        "scope_hash": "d8a47bf5cdf8fd48d65ff16755aec9bbecb45ef0806d0b65be1bb8538e3928c5",
        "verdict": "IN_SCOPE"
      },
      "payload_hash": "5cd08d5243eeff927efd6ca10497b3e4b1b638dfc089f43ae0bf1224bda2e27d",
      "previous_event_hash": "ae4149b008f27ed499c8c69ba6b89f6a58e215f22a5ca1e4c5de1d30398b2757",
      "schema_version": "ledger_event.v1",
      "tenant_id": "demo-tenant",
      "timestamp": "2026-07-15T09:00:01+00:00",
      "workspace_id": "demo-workspace"
    },
    {
      "action_id": "refund-demo-001",
      "action_type": "refund_request",
      "actor_id": "gateway",
      "event_hash": "073ccf8fd5149fcae2ffd8275963b9781caf60123ef474e70232781868713c73",
      "event_id": "71afecb278d8884ad047759b1fc9e947f2d2e63086983862f46d9ce7cd052eac",
      "event_type": "Finalized",
      "payload": {
        "action_packet_hash": "a1294847ccaffafd359c3cfe88a8c3df4e651b531825327bf92b09b202455f5d",
        "decision": "ALLOW"
      },
      "payload_hash": "8836e6314bdd4351aee8c6c487ed968ea0a328dce861d8c5a8076e738274e815",
      "previous_event_hash": "bf63227bf0efc9d37cf5e96197f175442a35160dd617f5a21989df5102fd1316",
      "schema_version": "ledger_event.v1",
      "tenant_id": "demo-tenant",
      "timestamp": "2026-07-15T09:00:02+00:00",
      "workspace_id": "demo-workspace"
    }
  ],
  "manifest": {
    "action_id": "refund-demo-001",
    "chain_start_previous_event_hash": null,
    "event_count": 3,
    "receipt_public_key_hex": "bc713c7d865d07556814957f41ab9091372eff5793c3683d59431a1b69d70fd4",
    "schema_version": "dispute_packet.v1",
    "scope_conformance_headline": "in_scope",
    "settlement_anchor": {
      "status": "SETTLEMENT_UNANCHORED"
    }
  },
  "receipt": {
    "action_hash": "a1294847ccaffafd359c3cfe88a8c3df4e651b531825327bf92b09b202455f5d",
    "algorithm": "ed25519",
    "decision": "ALLOW",
    "evidence_set_hash": "1a1e50f9b78fe080e20803b146cf7f08754fafb1cc2446bb86258edfdd241fb1",
    "key_id": "demo-key-1",
    "ledger_entry_hash": "073ccf8fd5149fcae2ffd8275963b9781caf60123ef474e70232781868713c73",
    "mandate_hash": "dd955871da26c57a9aba5613ae301386356741cefc67c1c7e4453e5ac8ce62a4",
    "reason_code": "APPROVAL_GRANTED",
    "scope_conformance": {
      "action_hash": "a1294847ccaffafd359c3cfe88a8c3df4e651b531825327bf92b09b202455f5d",
      "breaches": [],
      "scope_hash": "d8a47bf5cdf8fd48d65ff16755aec9bbecb45ef0806d0b65be1bb8538e3928c5",
      "verdict": "IN_SCOPE"
    },
    "signature": "4790fd4f465b0a7d5bb0ee50c167030ee976175e995dce0014430001f67b5c437e0d89bc77cba6e2536ce9a335b71d42f6c6eb708b2431f74ee68cffb291f403",
    "signer_pubkey_hash": "6d839e7c8a29101281b89f111552235d1f7259b68acfe4c806929952d338cea9",
    "timestamp": "2026-07-15T09:00:02+00:00"
  }
};
