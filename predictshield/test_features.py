"""Pure-python assertions for the 77-feature extraction core (no Scapy needed)."""
from features import (
    FEATURE_ORDER,
    FeatureExtractor,
    to_feature_vector,
)
from flows import FlowState


def test_feature_count_and_order():
    assert len(FEATURE_ORDER) == 77
    # first and last few must match the CICIDS2017 header exactly
    assert FEATURE_ORDER[0] == "Destination Port"
    assert FEATURE_ORDER[1] == "Flow Duration"
    assert FEATURE_ORDER[2] == "Total Fwd Packets"
    assert FEATURE_ORDER[-1] == "Idle Min"
    assert FEATURE_ORDER[-2] == "Idle Max"


def test_feature_vector_length_and_spot_checks():
    flow = FlowState(("1.2.3.4", "5.6.7.8", 1234, 22, 6), start_time=100.0)
    flow.fwd_pkt_lens = [40, 60]
    flow.bwd_pkt_lens = [30]
    flow.fwd_times = [100.0, 101.0]
    flow.bwd_times = [101.5]
    flow.all_times = [100.0, 101.0, 101.5]
    flow.fwd_seg_lens = [10, 20]
    flow.bwd_seg_lens = [5]
    flow.fwd_bytes = 100
    flow.bwd_bytes = 30
    flow.total_bytes = 130
    flow.dst_port = 22
    flow.last_time = 101.5
    flow.syn_count = 1
    flow.ack_count = 1

    features = FeatureExtractor().extract(flow)
    vector = to_feature_vector(features)

    assert len(vector) == 77
    idx = {name: i for i, name in enumerate(FEATURE_ORDER)}
    assert vector[idx["Total Fwd Packets"]] == 2
    assert vector[idx["Total Backward Packets"]] == 1
    assert vector[idx["Total Length of Fwd Packets"]] == 100
    assert vector[idx["Destination Port"]] == 22
    assert vector[idx["Flow Duration"]] == 1.5
    assert vector[idx["SYN Flag Count"]] == 1
    assert vector[idx["ACK Flag Count"]] == 1


def test_iat_and_ratios():
    flow = FlowState(("1.2.3.4", "5.6.7.8", 1234, 80, 6), start_time=0.0)
    flow.fwd_pkt_lens = [100, 100]
    flow.bwd_pkt_lens = [200]
    flow.fwd_times = [0.0, 0.5]
    flow.bwd_times = [1.0]
    flow.all_times = [0.0, 0.5, 1.0]
    flow.fwd_seg_lens = [50, 50]
    flow.bwd_seg_lens = [150]
    flow.fwd_bytes = 200
    flow.bwd_bytes = 200
    flow.total_bytes = 400
    flow.dst_port = 80
    flow.last_time = 1.0

    features = FeatureExtractor().extract(flow)
    idx = {name: i for i, name in enumerate(FEATURE_ORDER)}
    vec = to_feature_vector(features)
    assert vec[idx["Fwd IAT Total"]] == 0.5
    assert vec[idx["Down/Up Ratio"]] == 1.0  # 200/200


if __name__ == "__main__":
    test_feature_count_and_order()
    test_feature_vector_length_and_spot_checks()
    test_iat_and_ratios()
    print("All feature tests passed.")
