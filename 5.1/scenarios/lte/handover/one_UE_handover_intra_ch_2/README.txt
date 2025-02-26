# Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
#                          600 Corporate Pointe
#                          Suite 1200
#                          Culver City, CA 90230
#                          info@scalable-networks.com
#
# This source code is licensed, not sold, and is subject to a written
# license agreement.  Among other things, no portion of this source
# code may be copied, transmitted, disclosed, displayed, distributed,
# translated, used as the basis for a derivative work, or used, in
# whole or in part, for any program or purpose other than its intended
# use in compliance with the license agreement as part of the QualNet
# software.  This source code and certain of the algorithms contained
# within it are confidential trade secrets of Scalable Network
# Technologies, Inc. and may not be used as the basis for any other
# software, hardware, product or service.

PURPOSE:-
-------
To test the case of simple handover.
An UE move from an eNB to another using same channel.

SCENARIO:-
---------
One LTE subnet is present in the scenario, having two base stations (eNodeBs) 
and one user equipment (UE). Nodes 4 is the UE. Node 2 and 3 are eNodeBs.

TOPOLOGY:
---------

                        CN[6]
                         |
                        HUB
                         |
                      SGW/MME[1]
                         |
                        HUB
                       /    \
                      /      \
                     /        \
                 eNB1[2]     eNB2[3]

               UE[4]  ----------> 

CBR flows ares:

RUN:-
----
Run '<QUALNET_HOME>/bin/qualnet test.config'.


DESCRIPTION OF THE FILES:-
------------------------
1.test.config - QualNet configuration input file.
2.test.app    - QualNet configuration file for application input.
3.test.nodes  - QualNet node placement file for the simulation run.
  UE's mobility pattern is described in this file.
4.test.expected.stat - QualNet statistics collection.
6.UL_BER_MCS*.ber - Bit error rate table for various MCS(modulation, coding systems) for Uplink.
7.DL_BER_MCS*.ber - Bit error rate table for various MCS(modulation, coding systems) for Downlink.
8.README - This file

