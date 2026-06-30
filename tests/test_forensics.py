from titan_decoder.core.device_forensics import ForensicsEngine


def make_node(preview: str):
    return {
        "content_preview": preview,
        "content_type": "Text",
    }


def test_detects_vm_and_burner_signals():
    text = "VMware Tools present on DESKTOP-ABC123 with vmmouse driver"
    report = {"nodes": [make_node(text)]}

    engine = ForensicsEngine()
    summary = engine.analyze(report)

    assert summary["vm"]["detected"]
    assert "vmware" in summary["vm"]["hits"]
    assert summary["burner"]["score"] >= 0.25


def test_extracts_mobile_identifiers():
    text = "IMEI 490154203237518 ICCID 89014103211118510720"
    report = {"nodes": [make_node(text)]}

    engine = ForensicsEngine()
    summary = engine.analyze(report)

    assert "490154203237518" in summary["mobile_ids"]["imei"]
    assert "89014103211118510720" in summary["mobile_ids"]["iccid"]


def test_handles_empty_nodes_gracefully():
    report = {"nodes": []}
    engine = ForensicsEngine()
    summary = engine.analyze(report)

    assert summary["vm"]["detected"] is False
    assert summary["mobile_ids"] == {"imei": [], "imsi": [], "iccid": []}
    assert summary["burner"]["score"] == 0


def test_ignores_intermediate_encoded_layers():
    # The root (base64-ish) layer carries noise; only the decoded leaf should be
    # scanned. Parent/child ids mark the root as a non-leaf intermediate node.
    report = {
        "nodes": [
            {"id": 0, "parent": None, "content_preview": "AMDxQUNvcmU=", "content_type": "Text"},
            {"id": 1, "parent": 0, "content_preview": "clean VMware host DESKTOP-AB12CD", "content_type": "Text"},
        ]
    }
    summary = ForensicsEngine().analyze(report)
    # VM signal from the decoded leaf is detected...
    assert summary["vm"]["detected"]
    # ...but the "AMD" substring in the encoded parent must not surface.
    assert summary["hardware_hints"] == []
