import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine


@settings(max_examples=50, deadline=None)
@given(st.binary(min_size=1, max_size=2048))
def test_root_and_lineage_commitments_hold_for_arbitrary_inputs(data):
    report = TitanEngine(Config()).run_analysis(data)
    nodes = report["nodes"]

    assert nodes
    assert [node["id"] for node in nodes] == list(range(len(nodes)))
    roots = [node for node in nodes if node["parent"] is None]
    assert len(roots) == 1
    assert roots[0]["sha256"] == hashlib.sha256(data).hexdigest()

    by_id = {node["id"]: node for node in nodes}
    for node in nodes:
        parent_id = node["parent"]
        provenance = node["provenance"]
        if parent_id is None:
            assert provenance["parent_id"] is None
            assert provenance["parent_sha256"] is None
            continue
        assert parent_id < node["id"]
        assert provenance["parent_id"] == parent_id
        assert provenance["parent_sha256"] == by_id[parent_id]["sha256"]
