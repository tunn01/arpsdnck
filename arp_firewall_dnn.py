#!/usr/bin/env python3
# arp_firewall_dnn.py
# Hybrid ARP Firewall = Rule-based (cache-mismatch spoofing + request-rate flooding)
#                    + DNN (Keras) for cold-start detection
# Mitigation = Install DROP flow for ARP frames from attacker MAC (on switch)
#
# Bám logic Algorithm 1 (ARP cache mismatch + request threshold) trong paper Telematics 2024. :contentReference[oaicite:3]{index=3}
# Thêm: L2 learning switch + install flow forwarding để đo throughput/CPU công bằng (giống baseline).

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.lib.packet import ether_types

import os
import time
import warnings
import joblib
import numpy as np
from tensorflow.keras.models import load_model

warnings.filterwarnings("ignore")

ZERO_MAC = "00:00:00:00:00:00"


def ip_oct(ip: str) -> int:
    """Return last octet of IPv4 address as int; -1 if invalid."""
    try:
        return int(str(ip).split(".")[-1])
    except Exception:
        return -1


def mac_b(mac: str) -> int:
    """Return last byte of MAC as int; -1 if invalid."""
    try:
        return int(str(mac).split(":")[-1], 16)
    except Exception:
        return -1


class HybridARPDNNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ---------- Config (giữ đúng ngưỡng 0.5) ----------
        self.ARP_THRESHOLD = int(os.getenv("ARP_THRESHOLD", "20"))       # req/s
        self.DNN_THRESHOLD = float(os.getenv("DNN_THRESHOLD", "0.5"))    # MUST be 0.5 by default
        self.WARMUP_SECONDS = float(os.getenv("WARMUP_SECONDS", "4.0"))  # tránh FP lúc mới pingall

        # Giảm false positive: cần >=2 lần DNN báo attack trong cửa sổ ngắn mới chặn
        # (vẫn giữ ngưỡng 0.5; chỉ thêm “confirmation” để ổn định)
        self.AI_CONFIRMATIONS = int(os.getenv("AI_CONFIRMATIONS", "2"))
        self.AI_WINDOW_SECONDS = float(os.getenv("AI_WINDOW_SECONDS", "1.0"))

        # DROP flow priority
        self.DROP_PRIORITY = int(os.getenv("DROP_PRIORITY", "200"))

        # Timeout của DROP (để dễ test lại). 0 = không hết hạn.
        self.DROP_IDLE_TIMEOUT = int(os.getenv("DROP_IDLE_TIMEOUT", "60"))
        self.DROP_HARD_TIMEOUT = int(os.getenv("DROP_HARD_TIMEOUT", "0"))

        # ---------- State ----------
        # L2 learning table: dpid -> {mac: port}
        self.mac_to_port = {}

        # Trusted ARP cache (learn only after SAFE)
        self.arp_cache = {}  # ip -> mac

        # Rate counter per (dpid, src_ip) for ARP REQUEST
        self.packet_counts = {}  # dpid -> {src_ip: count}
        self.start_time = {}     # dpid -> {src_ip: window_start_time}

        # MAC change counter per src_ip
        self.last_mac_for_ip = {}   # src_ip -> last mac
        self.mac_change_count = {}  # src_ip -> #changes

        # Blocked MAC set to avoid re-installing
        self.blocked_macs = set()

        # AI hit counter: (dpid, src_mac) -> [timestamps...]
        self.ai_hits = {}

        # Per-switch start time (warmup)
        self.dp_start_time = {}  # dpid -> time.time()

        # ---------- Load preprocessing + model ----------
        base_dir = os.path.dirname(os.path.abspath(__file__))
        prep_path = os.path.join(base_dir, "models", "arp_dnn_preprocess.joblib")
        model_path = os.path.join(base_dir, "models", "arp_attack_detection_model.h5")

        prep = joblib.load(prep_path)
        self.scaler = prep["scaler"]
        self.features = prep["features"]

        self.model = load_model(model_path)
        self.logger.info("DNN Model Loaded. Ready for ARP spoofing/flooding tests.")
        self.logger.info(
            f"Config: ARP_THRESHOLD={self.ARP_THRESHOLD} req/s, "
            f"DNN_THRESHOLD={self.DNN_THRESHOLD}, WARMUP={self.WARMUP_SECONDS}s, "
            f"AI_CONFIRM={self.AI_CONFIRMATIONS} within {self.AI_WINDOW_SECONDS}s"
        )

    # ------------------- Flow helpers -------------------

    def _add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        dp.send_msg(mod)

    # ------------------- Switch setup -------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        self.mac_to_port.setdefault(dp.id, {})
        self.dp_start_time[dp.id] = time.time()

        # table-miss -> controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)

        self.logger.info(
            f"Switch connected (dpid={dp.id}). Table-miss installed. Warmup={self.WARMUP_SECONDS:.1f}s"
        )

    # ------------------- Mitigation -------------------

    def _drop_arp_from_mac(self, dp, mac_block: str, reason: str):
        """Install a high-priority DROP flow for ARP frames from a given source MAC."""
        if mac_block in self.blocked_macs:
            return

        parser = dp.ofproto_parser

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_ARP,
            eth_src=mac_block
        )

        # Empty actions => DROP
        self._add_flow(
            dp,
            priority=self.DROP_PRIORITY,
            match=match,
            actions=[],
            idle_timeout=self.DROP_IDLE_TIMEOUT,
            hard_timeout=self.DROP_HARD_TIMEOUT
        )

        self.blocked_macs.add(mac_block)
        self.logger.warning(f">>> [MITIGATION] DROP(ARP) installed for MAC={mac_block} reason={reason}")

    # ------------------- Feature helpers -------------------

    def _rate_req_1s(self, dpid, src_ip) -> int:
        """Return ARP REQUEST count within a 1-second window."""
        now = time.time()
        self.packet_counts.setdefault(dpid, {})
        self.start_time.setdefault(dpid, {})

        if src_ip not in self.packet_counts[dpid]:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        if now - self.start_time[dpid][src_ip] > 1.0:
            self.packet_counts[dpid][src_ip] = 0
            self.start_time[dpid][src_ip] = now

        self.packet_counts[dpid][src_ip] += 1
        return self.packet_counts[dpid][src_ip]

    def _update_mac_change(self, src_ip, src_mac) -> int:
        """Count how many times src_ip appears with a different src_mac over time."""
        if src_ip not in self.last_mac_for_ip:
            self.last_mac_for_ip[src_ip] = src_mac
            self.mac_change_count[src_ip] = 0
        else:
            if self.last_mac_for_ip[src_ip] != src_mac:
                self.mac_change_count[src_ip] = self.mac_change_count.get(src_ip, 0) + 1
                self.last_mac_for_ip[src_ip] = src_mac
        return self.mac_change_count.get(src_ip, 0)

    def _build_row(self, opcode, src_ip, dst_ip, src_mac, arp_dst_mac, req_rate_1s, mac_chg):
        return {
            "opcode": int(opcode),
            "src_ip_oct": ip_oct(src_ip),
            "dst_ip_oct": ip_oct(dst_ip),
            "src_mac_b": mac_b(src_mac),
            "dst_mac_b": mac_b(arp_dst_mac),
            "is_request": 1 if int(opcode) == arp.ARP_REQUEST else 0,
            "is_reply": 1 if int(opcode) == arp.ARP_REPLY else 0,
            "is_gratuitous": 1 if str(src_ip) == str(dst_ip) else 0,
            "dst_mac_zero": 1 if str(arp_dst_mac).lower() == ZERO_MAC else 0,
            "req_rate_1s": int(req_rate_1s),
            "mac_change_count": int(mac_chg),
        }

    def _dnn_prob(self, rowdict) -> float:
        """Return attack probability (sigmoid output) from DNN."""
        x = np.array([[float(rowdict.get(f, 0)) for f in self.features]], dtype=float)
        x = self.scaler.transform(x)
        return float(self.model.predict(x, verbose=0)[0][0])

    def _in_warmup(self, dpid: int) -> bool:
        t0 = self.dp_start_time.get(dpid, None)
        if t0 is None:
            return True
        return (time.time() - t0) < self.WARMUP_SECONDS

    def _ai_register_hit(self, dpid: int, src_mac: str) -> int:
        """Return number of AI hits in the last AI_WINDOW_SECONDS."""
        key = (dpid, src_mac)
        now = time.time()
        hits = self.ai_hits.get(key, [])
        hits = [t for t in hits if (now - t) <= self.AI_WINDOW_SECONDS]
        hits.append(now)
        self.ai_hits[key] = hits
        return len(hits)

    # ------------------- L2 forwarding (baseline-like) -------------------

    def _l2_forward(self, dp, in_port, eth_src, eth_dst, data):
        """Learning switch behavior + install flow for known dst."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth_src] = in_port

        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
            actions = [parser.OFPActionOutput(out_port)]

            # Install flow to offload future packets (fair throughput/CPU comparison)
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            self._add_flow(dp, priority=10, match=match, actions=actions, idle_timeout=60, hard_timeout=0)
        else:
            out_port = ofp.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    # ------------------- Packet processing -------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # If already blocked, drop early (switch should drop anyway)
        if eth.src in self.blocked_macs and eth.ethertype == ether_types.ETH_TYPE_ARP:
            return

        # Non-ARP: do L2 learning + install flow
        if eth.ethertype != ether_types.ETH_TYPE_ARP:
            self._l2_forward(dp, in_port, eth.src, eth.dst, msg.data)
            return

        # ---- ARP handling ----
        a = pkt.get_protocol(arp.arp)
        if not a:
            return

        src_ip, dst_ip = a.src_ip, a.dst_ip
        src_mac = eth.src
        opcode = int(a.opcode)

        cold_start = (src_ip not in self.arp_cache)

        # Update behavior counters
        mac_chg = self._update_mac_change(src_ip, src_mac)

        # (1) RULE flooding (Algorithm 1 line 17-19): only for ARP REQUEST :contentReference[oaicite:4]{index=4}
        req_rate = 0
        if opcode == arp.ARP_REQUEST:
            req_rate = self._rate_req_1s(dpid, src_ip)
            if req_rate > self.ARP_THRESHOLD:
                self.logger.warning(
                    f"[RULE-FLOODING] Blocked src_ip={src_ip} rate={req_rate} > {self.ARP_THRESHOLD}"
                )
                self._drop_arp_from_mac(dp, src_mac, reason="rule_flooding")
                return

        # (2) RULE spoofing: cache mismatch (Algorithm 1 logic) :contentReference[oaicite:5]{index=5}
        if src_ip in self.arp_cache and self.arp_cache[src_ip] != src_mac:
            self.logger.warning(
                f"[RULE-SPOOFING] Blocked src_ip={src_ip}. cache={self.arp_cache[src_ip]} != {src_mac}"
            )
            self._drop_arp_from_mac(dp, src_mac, reason="rule_cache_mismatch")
            return

        # (3) DNN layer: run for both REQUEST and REPLY (cold-start detection) :contentReference[oaicite:6]{index=6}
        row = self._build_row(
            opcode=opcode,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_mac=src_mac,
            arp_dst_mac=a.dst_mac,
            req_rate_1s=req_rate if opcode == arp.ARP_REQUEST else 0,
            mac_chg=mac_chg,
        )
        prob = self._dnn_prob(row)

        # Warmup: log but do not block
        if self._in_warmup(dpid):
            self.logger.info(
                f"[AI-SAFE] src_ip={src_ip} prob={prob:.2f} < {self.DNN_THRESHOLD} "
                f"(req_rate={req_rate}, mac_chg={mac_chg}, cold_start={cold_start})"
            )
        else:
            if prob >= self.DNN_THRESHOLD:
                tag = "AI-ATTACK-REQ" if opcode == arp.ARP_REQUEST else "AI-ATTACK-REPLY"
                k = self._ai_register_hit(dpid, src_mac)

                if k >= self.AI_CONFIRMATIONS:
                    self.logger.warning(
                        f"[{tag}] Blocked src_ip={src_ip} prob={prob:.2f} >= {self.DNN_THRESHOLD} "
                        f"(hits={k}/{self.AI_CONFIRMATIONS}, req_rate={req_rate}, mac_chg={mac_chg}, cold_start={cold_start})"
                    )
                    self._drop_arp_from_mac(dp, src_mac, reason="dnn")
                    return
                else:
                    self.logger.warning(
                        f"[AI-SUSPECT] src_ip={src_ip} prob={prob:.2f} >= {self.DNN_THRESHOLD} "
                        f"(hits={k}/{self.AI_CONFIRMATIONS} waiting, req_rate={req_rate}, mac_chg={mac_chg}, cold_start={cold_start})"
                    )
                    # Do NOT learn mapping when suspect
            else:
                self.logger.info(
                    f"[AI-SAFE] src_ip={src_ip} prob={prob:.2f} < {self.DNN_THRESHOLD} "
                    f"(req_rate={req_rate}, mac_chg={mac_chg}, cold_start={cold_start})"
                )

        # (4) Learn mapping ONLY if not suspect
        # Learn during warmup or if prob < threshold
        if (src_ip not in self.arp_cache) and (self._in_warmup(dpid) or prob < self.DNN_THRESHOLD):
            self.arp_cache[src_ip] = src_mac
            self.logger.info(f"[LEARN] ARP_Cache += ({src_ip}, {src_mac}) size={len(self.arp_cache)}")

        # Forward ARP: flood (ARP resolution)
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        dp.send_msg(out)

