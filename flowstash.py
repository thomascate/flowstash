#! /usr/bin/env python 

import sys
import flowtools
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch import helpers

#flowFile = "/var/lib/netflow/2014-10-31/ft-v05.2014-10-31.165705-0500"
flowFile = sys.argv[1]
flowData = []

esHost = "10.1.1.2"
esIndex = 'flowstash-%(date)s' % {"date": datetime.now().strftime("%Y.%m.%d") }
esIndexSettings = {
                   "settings": {
                     "number_of_shards": 5,
                     "number_of_replicas": 0,
                    }
                  }

for flow in flowtools.FlowSet( flowFile ):
  currentFlow = {
                 '_index': esIndex,
                 '_type': 'netflow',
                 '_source': {
                   'dOctets':    flow.dOctets,
                   'dPackets':   flow.dPkts,
                   'dstaddr':    flow.dstaddr,
                   'dstport':    flow.dstport,
                   'rtr_addr':   flow.exaddr,
                   'first_pkt':  datetime.fromtimestamp(flow.first),
                   'last_pkt':   datetime.fromtimestamp(flow.last),
                   'protocol':   flow.prot,
                   'src_addr':   flow.srcaddr,
                   'src_port':   flow.srcport,
                   'rtr_uptime': flow.sysUpTime,
                   'tcp_flags':  flow.tcp_flags,
                   'unix_nsecs': flow.unix_nsecs,
                   'unix_secs':  flow.unix_secs, 
                  }
                }

  flowData.append( currentFlow )

es = Elasticsearch([esHost], sniff_on_start=True)
es.indices.create(index=esIndex, body = esIndexSettings, ignore=400)

if len(flowData) > 0:
  helpers.bulk(es, flowData)
 