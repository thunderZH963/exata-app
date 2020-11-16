// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.


#ifndef PROP_FLAT_BINNING_H
#define PROP_FLAT_BINNING_H

#ifdef ADDON_NGCNMS

#include "coordinates.h"
#include "fileio.h"
#include "partition.h"

void PropFlatBinningSetPropChannel(PropTxInfo* propTxInfo,
                                            PartitionData* partitionData,
                                            int channelIndex,
                                            PropChannel *propChannel,
                                            int *numNodes);

#define PROP_FLAT_BINNING_UPDATE_TIMER_DEFAULT  3*SECOND;

class PropFlatBinningNodeHash
{
private:
    std::map<NodeAddress, Node*> hash;  

public:
    PropFlatBinningNodeHash();

    NodeAddress AddHashEntry(Node* node);

    BOOL CheckHash(NodeAddress id);

    Node* RetrieveEntry(NodeAddress id);

    Node* RemoveHashEntry(NodeAddress nodeId);

    void PrintHashNodes(int boxNum);

    int CopyToNodeList(PropChannel *propChannel, int hashSize);

    int GetHashSize();
};


void PropFlatBinningInit(PartitionData* partitionData);

void
PropFlatBinningUpdateNodePosition(Node *node,
                                  int phyIndex);

PropPathProfile PropFlatBinningGetPropPathProfileFromMatrix(
    PartitionData* partitionData,
    int channelIndex,
    double wavelength,
    float txAntennaHeight,
    float rxAntennaHeight,
    float txPower_dBm,
    float txAntennaGain_dBi,
    PropPathProfile* profile,
    int index);


typedef struct struct_grid_box {
    Coordinates dimensionCoords;
    Coordinates originCoords;
    int sizeNodeList;
    int numInNodeList;
    PropFlatBinningNodeHash *nodeHash;    
} GridBox;

typedef struct struct_grid_info {
    int numXBoxes;
    int numYBoxes;
    double xSize;
    double ySize;

    double xDegrees;
    double yDegress;

    Coordinates smallerWestCoord;
    Coordinates northWestCoord;

    GridBox *gridBox;
} GridInfo;

#endif

#endif
