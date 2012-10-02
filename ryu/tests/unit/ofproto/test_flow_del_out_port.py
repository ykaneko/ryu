import logging

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_2

LOG = logging.getLogger(__name__)


class Test(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }

    def __init__(self, *args, **kwargs):
        super(Test, self).__init__(*args, **kwargs)

        self._verify = None

    def send_flow_stats(self, dp):
        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPFlowStatsRequest(dp, dp.ofproto.OFPTT_ALL,
                                                  dp.ofproto.OFPP_ANY,
                                                  dp.ofproto.OFPG_ANY,
                                                  0, 0, match)
        # rule = nx_match.ClsRule()
        # match = dp.ofproto_parser.OFPMatch(*rule.match_tuple())
        # m = dp.ofproto_parser.OFPFlowStatsRequest(dp, 0, match,
        #                                           0xff, dp.ofproto.OFPP_ANY)

        dp.send_msg(m)

    def mod_flow(self, dp, actions=None, command=None,
                 table_id=None, out_port=None):
        inst = []
        if actions:
            inst = [dp.ofproto_parser.OFPInstructionActions(
                    dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if not command:
            command = dp.ofproto.OFPFC_ADD

        if not table_id:
            table_id = dp.ofproto.OFPTT_ALL

        if not out_port:
            out_port = dp.ofproto.OFPP_ANY
            #out_port = dp.ofproto.OFPP_NONE

        match = dp.ofproto_parser.OFPMatch()
        m = dp.ofproto_parser.OFPFlowMod(dp, 0, 0, table_id,
                                         command,
                                         0, 0, 0xff, 0xffffffff,
                                         out_port,
                                         dp.ofproto.OFPG_ANY,
                                         0, match, inst)
        dp.send_msg(m)
        # rule = nx_match.ClsRule()
        # dp.send_flow_mod(rule, 0, (table_id << 8 | command),
        #                  0, 0, actions=actions)

    def add_flow(self, dp):
        self._verify = 'Before'

        # Add table_id=1 output=1
        actions = [dp.ofproto_parser.OFPActionOutput(1, 1500)]
        self.mod_flow(dp, actions=actions, table_id=1)

        # Add table_id=2 output=2
        actions = [dp.ofproto_parser.OFPActionOutput(2, 1500)]
        self.mod_flow(dp, actions=actions, table_id=2)

        dp.send_barrier()
        self.send_flow_stats(dp)

    def del_flow(self, dp):
        self._verify = 'After'

        command = dp.ofproto.OFPFC_DELETE
        # delete table_id=1 (output=2)
        out_port = 2
        #out_port = dp.ofproto.OFPP_ANY
        self.mod_flow(dp, command=command, out_port=out_port)
        dp.send_barrier()
        self.send_flow_stats(dp)

    @handler.set_ev_cls(ofp_event.EventOFPStatsReply,
                        handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        print '  %s flow_count:%s' % (self._verify, len(msg.body))

        for s in msg.body:
            # for a in s.actions:
            #     print "    table_id=%s, port=%s" % (s.table_id, a.port)
            for i in s.instructions:
                for a in i.actions:
                    print "    table_id=%s, port=%s" % (s.table_id, a.port)

        if self._verify == 'Before':
            self.del_flow(dp)

    @handler.set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter_leave:
            print 'TEST_START'
            self.add_flow(ev.dp)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_replay_handler(self, ev):
        pass
