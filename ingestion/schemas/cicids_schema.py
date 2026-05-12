from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


# CICIDS-2017 has 78 numeric features + 1 label column.
# This schema validates a single row after normalization.
class CICIDSRecord(BaseModel):
    model_config = {"populate_by_name": True}

    destination_port: int = Field(alias="Destination Port")
    flow_duration: float = Field(alias="Flow Duration")
    total_fwd_packets: int = Field(alias="Total Fwd Packets")
    total_bwd_packets: int = Field(alias="Total Backward Packets")
    total_len_fwd_packets: float = Field(alias="Total Length of Fwd Packets")
    total_len_bwd_packets: float = Field(alias="Total Length of Bwd Packets")
    fwd_pkt_len_max: float = Field(alias="Fwd Packet Length Max")
    fwd_pkt_len_min: float = Field(alias="Fwd Packet Length Min")
    fwd_pkt_len_mean: float = Field(alias="Fwd Packet Length Mean")
    fwd_pkt_len_std: float = Field(alias="Fwd Packet Length Std")
    bwd_pkt_len_max: float = Field(alias="Bwd Packet Length Max")
    bwd_pkt_len_min: float = Field(alias="Bwd Packet Length Min")
    bwd_pkt_len_mean: float = Field(alias="Bwd Packet Length Mean")
    bwd_pkt_len_std: float = Field(alias="Bwd Packet Length Std")
    flow_bytes_per_s: Optional[float] = Field(None, alias="Flow Bytes/s")
    flow_pkts_per_s: Optional[float] = Field(None, alias="Flow Packets/s")
    flow_iat_mean: float = Field(alias="Flow IAT Mean")
    flow_iat_std: float = Field(alias="Flow IAT Std")
    flow_iat_max: float = Field(alias="Flow IAT Max")
    flow_iat_min: float = Field(alias="Flow IAT Min")
    fwd_iat_total: float = Field(alias="Fwd IAT Total")
    fwd_iat_mean: float = Field(alias="Fwd IAT Mean")
    fwd_iat_std: float = Field(alias="Fwd IAT Std")
    fwd_iat_max: float = Field(alias="Fwd IAT Max")
    fwd_iat_min: float = Field(alias="Fwd IAT Min")
    bwd_iat_total: float = Field(alias="Bwd IAT Total")
    bwd_iat_mean: float = Field(alias="Bwd IAT Mean")
    bwd_iat_std: float = Field(alias="Bwd IAT Std")
    bwd_iat_max: float = Field(alias="Bwd IAT Max")
    bwd_iat_min: float = Field(alias="Bwd IAT Min")
    fwd_psh_flags: int = Field(alias="Fwd PSH Flags")
    bwd_psh_flags: int = Field(alias="Bwd PSH Flags")
    fwd_urg_flags: int = Field(alias="Fwd URG Flags")
    bwd_urg_flags: int = Field(alias="Bwd URG Flags")
    fwd_header_len: float = Field(alias="Fwd Header Length")
    bwd_header_len: float = Field(alias="Bwd Header Length")
    fwd_pkts_per_s: float = Field(alias="Fwd Packets/s")
    bwd_pkts_per_s: float = Field(alias="Bwd Packets/s")
    min_pkt_len: float = Field(alias="Min Packet Length")
    max_pkt_len: float = Field(alias="Max Packet Length")
    pkt_len_mean: float = Field(alias="Packet Length Mean")
    pkt_len_std: float = Field(alias="Packet Length Std")
    pkt_len_variance: float = Field(alias="Packet Length Variance")
    fin_flag_cnt: int = Field(alias="FIN Flag Count")
    syn_flag_cnt: int = Field(alias="SYN Flag Count")
    rst_flag_cnt: int = Field(alias="RST Flag Count")
    psh_flag_cnt: int = Field(alias="PSH Flag Count")
    ack_flag_cnt: int = Field(alias="ACK Flag Count")
    urg_flag_cnt: int = Field(alias="URG Flag Count")
    cwe_flag_cnt: int = Field(alias="CWE Flag Count")
    ece_flag_cnt: int = Field(alias="ECE Flag Count")
    down_up_ratio: float = Field(alias="Down/Up Ratio")
    avg_pkt_size: float = Field(alias="Average Packet Size")
    avg_fwd_segment_size: float = Field(alias="Avg Fwd Segment Size")
    avg_bwd_segment_size: float = Field(alias="Avg Bwd Segment Size")
    fwd_header_len2: float = Field(alias="Fwd Header Length.1")
    subflow_fwd_pkts: int = Field(alias="Subflow Fwd Packets")
    subflow_fwd_bytes: float = Field(alias="Subflow Fwd Bytes")
    subflow_bwd_pkts: int = Field(alias="Subflow Bwd Packets")
    subflow_bwd_bytes: float = Field(alias="Subflow Bwd Bytes")
    init_win_bytes_fwd: int = Field(alias="Init_Win_bytes_forward")
    init_win_bytes_bwd: int = Field(alias="Init_Win_bytes_backward")
    act_data_pkt_fwd: int = Field(alias="act_data_pkt_fwd")
    min_seg_size_fwd: float = Field(alias="min_seg_size_forward")
    active_mean: float = Field(alias="Active Mean")
    active_std: float = Field(alias="Active Std")
    active_max: float = Field(alias="Active Max")
    active_min: float = Field(alias="Active Min")
    idle_mean: float = Field(alias="Idle Mean")
    idle_std: float = Field(alias="Idle Std")
    idle_max: float = Field(alias="Idle Max")
    idle_min: float = Field(alias="Idle Min")
    label: str = Field(alias="label")

    @field_validator("flow_bytes_per_s", "flow_pkts_per_s", mode="before")
    @classmethod
    def replace_infinity(cls, v: object) -> Optional[float]:
        if v in ("Infinity", "-Infinity", float("inf"), float("-inf")):
            return None
        return v  # type: ignore[return-value]

    @field_validator("label", mode="before")
    @classmethod
    def normalize_label(cls, v: object) -> str:
        return str(v).strip()
