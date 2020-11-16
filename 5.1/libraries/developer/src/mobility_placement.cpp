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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include "api.h"

#ifdef WIRELESS_LIB
#include "mobility_group.h"
#include "mobility_waypoint.h"
#endif // WIRELESS_LIB

#ifdef MGRS_ADDON
#include "mgrs_utility.h"
#endif // MGRS_ADDON

//static
void SetNodePositionsRandomly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime);

void SetNodePositionsRandomly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime);


//static
void SetNodePositionsExternal(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime);

//static
void SetNodePositionsUniformly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime);

void SetNodePositionsUniformly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime);


//static
void SetNodePositionsInGrid(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    clocktype maxSimTime);

void SetNodePositionsInGrid(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    double gridUnit);



//static
void SetNodePositionsWithFileInputs(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    clocktype startSimTime);

//static
void SetNodePositionsWithFileInputs(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    clocktype startSimTime);

static
void SetRandomMobility(
    NodeAddress nodeId,
    MobilityData* mobilityData,
    TerrainData* terrainData,
    NodeInput* nodeInput,
    clocktype maxSimTime);

static
BOOL ReadMobilityString(
    char* inputString,
    NodeAddress* nodeId,
    clocktype* simTime,
    Coordinates* coordinates,
    Orientation* orientation
#ifdef MGRS_ADDON
    , TerrainData* terrainData
#endif // MGRS_ADDON
    );


/*
 * FUNCTION     MOBILITY_SetNodePositions
 * PURPOSE      Set positions of nodes
 *              Note: This function is called before NODE_CreateNode().
 *                    It cannot access Node structure.
 *
 * Parameters:
 *     numNodes:       number of nodes
 *     nodePositions:  array of nodePositions
 *     nodePlacementTypeCounts: array of placement type counts
 *     terrainData:    pointer to terrainData
 *     nodeInput:      configuration input
 *     seed:           random number seed
 *     maxSimTime:     maximum simulation time
 */
void MOBILITY_SetNodePositions(
    int numNodes,
    NodePositions* nodePositions,
    int* nodePlacementTypeCounts,
    TerrainData* terrainData,
    NodeInput* nodeInput,
    RandomSeed seed,
    clocktype maxSimTime,
    clocktype startSimTime)
{
    int i;
    int totalNumNodes = 0;

    // Sanity check for nodePlacementTypeCounts
    for (i = 0; i < NUM_NODE_PLACEMENT_TYPES; i++) {
        totalNumNodes += nodePlacementTypeCounts[i];
    }
    assert(totalNumNodes == numNodes);

    if (nodePlacementTypeCounts[RANDOM_PLACEMENT] != 0) {
        SetNodePositionsRandomly(
            numNodes,
            nodePlacementTypeCounts[RANDOM_PLACEMENT],
            nodePositions,
            terrainData,
            nodeInput,
            seed,
            maxSimTime);
    }

    if (nodePlacementTypeCounts[UNIFORM_PLACEMENT] != 0) {
        SetNodePositionsUniformly(
            numNodes,
            nodePlacementTypeCounts[UNIFORM_PLACEMENT],
            nodePositions,
            terrainData,
            nodeInput,
            seed,
            maxSimTime);
    }

    if (nodePlacementTypeCounts[GRID_PLACEMENT] != 0) {
        SetNodePositionsInGrid(
            numNodes,
            nodePlacementTypeCounts[GRID_PLACEMENT],
            nodePositions,
            terrainData,
            nodeInput,
            maxSimTime);
    }

    if (nodePlacementTypeCounts[FILE_BASED_PLACEMENT] != 0) {
        SetNodePositionsWithFileInputs(
            numNodes,
            nodePlacementTypeCounts[FILE_BASED_PLACEMENT],
            nodePositions,
            terrainData,
            nodeInput,
            maxSimTime,
            startSimTime);
    }

    if (nodePlacementTypeCounts[EXTERNAL_PLACEMENT] != 0) {
        SetNodePositionsExternal(
            numNodes,
            nodePlacementTypeCounts[EXTERNAL_PLACEMENT],
            nodePositions,
            terrainData,
            nodeInput,
            seed,
            maxSimTime);
    }


#ifdef WIRELESS_LIB
    if (nodePlacementTypeCounts[GROUP_PLACEMENT] != 0) {
        SetNodePositionsInGroup(
            numNodes,
            // Modified for a bug fix present in exata20_l3
            //rev 1.2.2.3.24.1.2.1
            nodePlacementTypeCounts,
            nodePositions,
            terrainData,
            nodeInput,
            seed,
            maxSimTime);
    }
#endif // WIRELESS_LIB

}


//static
//  Wrapper Function

void SetNodePositionsRandomly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions* nodePositions,
    TerrainData* terrainData,
    NodeInput* nodeInput,
    RandomSeed seed,
    clocktype maxSimTime)
{
    Coordinates origin = terrainData->getOrigin();
    Coordinates dimensions = terrainData->getDimensions();

    SetNodePositionsRandomly(
        numNodes,
        numNodesToDistribute,
        nodePositions,
        terrainData,
        &origin,
        &dimensions,
        nodeInput,
        seed,
        maxSimTime);

}

void SetNodePositionsRandomly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions* nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput* nodeInput,
    RandomSeed seed,
    clocktype maxSimTime)
{
    int i;
    int numNodesDistributed = 0;

#ifdef ADDON_BOEINGFCS
    double zValue = 0.0;
#endif

    for (i = 0; i < numNodes; i++) {
        MobilityElement* current;

        if (nodePositions[i].nodePlacementType != RANDOM_PLACEMENT) {
            continue;
        }

        current =  nodePositions[i].mobilityData->current;

        current->position.common.c1 =
            boundOrigin->common.c1 + RANDOM_erand(seed) * boundDimensions->common.c1;
        current->position.common.c2 =
            boundOrigin->common.c2 + RANDOM_erand(seed) * boundDimensions->common.c2;
        current->position.common.c3 = 0.0;
        COORD_MapCoordinateSystemToType(
            terrainData->getCoordinateSystem(), &current->position);

#ifdef ADDON_BOEINGFCS
    zValue = current->position.common.c3;
#endif

        if (nodePositions[i].mobilityData->groundNode == TRUE) {
            TERRAIN_SetToGroundLevel(
                terrainData, &(current->position));
        }

        current->sequenceNum = nodePositions[i].mobilityData->sequenceNum;
        current->time = (clocktype)0;

        current->orientation.azimuth = 0;
        current->orientation.elevation = 0;
        current->speed = 0.0;

        MOBILITY_AddANewDestination(
            nodePositions[i].mobilityData,
            (clocktype)0,
            current->position,
            current->orientation
#ifdef ADDON_BOEINGFCS
        , zValue
#endif
        );

        SetRandomMobility(
            nodePositions[i].nodeId,
            nodePositions[i].mobilityData,
            terrainData,
            nodeInput,
            maxSimTime);

        numNodesDistributed++;

        if (numNodesDistributed == numNodesToDistribute) {
            return;
        }
    }
}

// static
void SetNodePositionsExternal(
    int numNodes,
    int numNodesToDistribute,
    NodePositions* nodePositions,
    TerrainData* terrainData,
    NodeInput* nodeInput,
    RandomSeed seed,
    clocktype maxSimTime)
{
    int i;
    int numNodesDistributed = 0;
    const Coordinates origin = terrainData->getOrigin();
    const Coordinates dimensions = terrainData->getDimensions();
#ifdef ADDON_BOEINGFCS
    double zValue = 0.0;
#endif

    for (i = 0; i < numNodes; i++) {
        MobilityElement* current;

        if (nodePositions[i].nodePlacementType != EXTERNAL_PLACEMENT) {
            continue;
        }

        current =  nodePositions[i].mobilityData->current;

        current->position.common.c1 =
            origin.common.c1 + dimensions.common.c1 / 1000000;
        current->position.common.c2 =
            origin.common.c2 + dimensions.common.c2 / 1000000;
        current->position.common.c3 = 0.0;
        COORD_MapCoordinateSystemToType(
            terrainData->getCoordinateSystem(), &current->position);

#ifdef ADDON_BOEINGFCS
    zValue = current->position.common.c3;
#endif

        if (nodePositions[i].mobilityData->groundNode == TRUE) {
            TERRAIN_SetToGroundLevel(
                terrainData, &(current->position));
        }

        current->sequenceNum = nodePositions[i].mobilityData->sequenceNum;
        current->time = (clocktype)0;

        current->orientation.azimuth = 0;
        current->orientation.elevation = 0;
        current->speed = 0.0;

        MOBILITY_AddANewDestination(
            nodePositions[i].mobilityData,
            (clocktype)0,
            current->position,
            current->orientation
#ifdef ADDON_BOEINGFCS
        , zValue
#endif
        );

        SetRandomMobility(
            nodePositions[i].nodeId,
            nodePositions[i].mobilityData,
            terrainData,
            nodeInput,
            maxSimTime);

        numNodesDistributed++;

        if (numNodesDistributed == numNodesToDistribute) {
            return;
        }
    }
}

//static

// Wrapper Function
void SetNodePositionsUniformly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    RandomSeed seed,
    clocktype maxSimTime)
{
    Coordinates origin = terrainData->getOrigin();
    Coordinates dimensions = terrainData->getDimensions();

    SetNodePositionsUniformly(
        numNodes,
        numNodesToDistribute,
        nodePositions,
        terrainData,
        &(origin),
        &(dimensions),
        nodeInput,
        seed,
        maxSimTime);
}

void SetNodePositionsUniformly(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    RandomSeed groupSeed,
    clocktype maxSimTime)
{
    int i, j, k;
    int numNodesDistributed = 0;

    const double cellEdge =
        sqrt(boundDimensions->common.c1 *
             boundDimensions->common.c2 /
             numNodesToDistribute);

    // Note you will lose some of the x range and
    // the gain some y range with a partial last row.

    const int numCellsX = (int)ceil(boundDimensions->common.c1 / cellEdge);
    const int numCellsY = ((numNodesToDistribute - 1) / numCellsX) + 1;

    // Scale cell height and width to match the terrain.

    const double cellHeight = boundDimensions->common.c2 / (double)numCellsY;
    const double cellWidth = boundDimensions->common.c1 / (double)numCellsX;

    i = 0;

#ifdef ADDON_BOEINGFCS
    double zValue = 0.0;
#endif

    for (k = 0; k < numCellsY; k++) {
        for (j = 0; j < numCellsX; j++) {
            MobilityElement* current;

            while (nodePositions[i].nodePlacementType != UNIFORM_PLACEMENT) {
                i++;
                assert(i < numNodes);
            }

            current = nodePositions[i].mobilityData->current;

            current->position.common.c1 =
                boundOrigin->common.c1 +
                (cellWidth * j) +
                (RANDOM_erand(groupSeed) * cellWidth);
            current->position.common.c2 =
                boundOrigin->common.c2 +
                (cellHeight * k) +
                (RANDOM_erand(groupSeed) * cellHeight);
            current->position.common.c3 = 0.0;
            COORD_MapCoordinateSystemToType(
                terrainData->getCoordinateSystem(), &current->position);

#ifdef ADDON_BOEINGFCS
        zValue = current->position.common.c3;
#endif

            if (nodePositions[i].mobilityData->groundNode == TRUE) {
                TERRAIN_SetToGroundLevel(
                    terrainData, &(current->position));
            }

            current->sequenceNum = nodePositions[i].mobilityData->sequenceNum;
            current->time = (clocktype)0;

            current->orientation.azimuth = 0;
            current->orientation.elevation = 0;
            current->speed = 0.0;

            MOBILITY_AddANewDestination(
                nodePositions[i].mobilityData,
                (clocktype)0,
                current->position,
                current->orientation
#ifdef ADDON_BOEINGFCS
        , zValue
#endif
        );

            SetRandomMobility(
                nodePositions[i].nodeId,
                nodePositions[i].mobilityData,
                terrainData,
                nodeInput,
                maxSimTime);

            numNodesDistributed++;
            i++;

            if (numNodesDistributed == numNodesToDistribute) {
                return;
            }
        }
    }
}


//static
// Wrapper Function
void SetNodePositionsInGrid(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    clocktype maxSimTime)
{
    Coordinates origin = terrainData->getOrigin();
    Coordinates dimensions = terrainData->getDimensions();

    double gridUnit;
    BOOL wasFound;
    int squareRoot = (int)sqrt((double)numNodesToDistribute);

    IO_ReadDouble(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "GRID-UNIT",
        &wasFound,
        &gridUnit);

    if (wasFound == FALSE) {
        ERROR_ReportError("GRID-UNIT not found.");
    }

    if (gridUnit * (squareRoot - 1) > dimensions.common.c1 ||
        gridUnit * (squareRoot - 1) > dimensions.common.c2)
    {
        ERROR_ReportError(
            "GRID-UNIT is too large to fit in the specified"
            "terrain dimensions.");
    }

    SetNodePositionsInGrid(
        numNodes,
        numNodesToDistribute,
        nodePositions,
        terrainData,
        &(origin),
        &(dimensions),
        nodeInput,
        maxSimTime,
        gridUnit);

}

void SetNodePositionsInGrid(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    double gridUnit)
{
    int numNodesDistributed = 0;
    int i, j, k;
    float squareRoot = (float)sqrt((double)numNodesToDistribute);   //manish

    if (squareRoot * squareRoot != numNodesToDistribute) {
        squareRoot = ceil(squareRoot);
    }

    if (gridUnit * (squareRoot - 1) > boundDimensions->common.c1 ||
        gridUnit * (squareRoot - 1) > boundDimensions->common.c2)
    {
        ERROR_ReportError(
            "GRID-UNIT is too large to fit in the specified"
            "terrain dimensions.");
    }

    i = 0;

#ifdef ADDON_BOEINGFCS
    double zValue = 0.0;
#endif

    for (k = 0; k < squareRoot; k++) {
        for (j = 0; j < squareRoot; j++) {
            MobilityElement* current;

            while (nodePositions[i].nodePlacementType != GRID_PLACEMENT) {
                i++;
                assert(i < numNodes);
            }

            current = nodePositions[i].mobilityData->current;

            current->position.common.c1 =
                boundOrigin->common.c1 + (double)(k * gridUnit);
            current->position.common.c2 =
                boundOrigin->common.c2 + (double)(j * gridUnit);
            current->position.common.c3 = 0.0;
            COORD_MapCoordinateSystemToType(
                terrainData->getCoordinateSystem(), &current->position);

#ifdef ADDON_BOEINGFCS
        zValue = current->position.common.c3;
#endif

            if (nodePositions[i].mobilityData->groundNode == TRUE) {
                TERRAIN_SetToGroundLevel(
                    terrainData, &(current->position));
            }

            current->sequenceNum = nodePositions[i].mobilityData->sequenceNum;
            current->time = (clocktype)0;

            current->orientation.azimuth = 0;
            current->orientation.elevation = 0;
            current->speed = 0.0;

            MOBILITY_AddANewDestination(
                nodePositions[i].mobilityData,
                (clocktype)0,
                current->position,
                current->orientation
#ifdef ADDON_BOEINGFCS
        , zValue
#endif
        );

            SetRandomMobility(
                nodePositions[i].nodeId,
                nodePositions[i].mobilityData,
                terrainData,
                nodeInput,
                maxSimTime);

            numNodesDistributed++;
            i++;

            if (numNodesDistributed == numNodesToDistribute) {
                return;
            }
        }
    }
}


static
void PrintOutWarningsIfOldFilesSpecified(NodeInput* nodeInput) {
    BOOL wasFound;
    NodeInput fileInput;

    IO_ReadCachedFile(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "NODE-PLACEMENT-FILE",
        &wasFound,
        &fileInput);

    if (wasFound) {
        ERROR_ReportWarning(
            "This version of QualNet does not utilize NODE-PLACEMENT-FILE.\n"
            "Use NODE-POSITION-FILE instead.\n");
    }

    IO_ReadCachedFile(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "MOBILITY-TRACE-FILE",
        &wasFound,
        &fileInput);

    if (wasFound) {
        ERROR_ReportWarning(
            "This version of QualNet does not utilize MOBILITY-TRACE-FILE.\n"
            "Use NODE-POSITION-FILE instead.\n");
    }
}



//Wrapper function
//static
void SetNodePositionsWithFileInputs(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    clocktype startSimTime)
{
    Coordinates origin = terrainData->getOrigin();
    Coordinates dimensions = terrainData->getDimensions();

    SetNodePositionsWithFileInputs(
        numNodes,
        numNodesToDistribute,
        nodePositions,
        terrainData,
        &(origin),
        &(dimensions),
        nodeInput,
        maxSimTime,
        startSimTime);

}

//static
void SetNodePositionsWithFileInputs(
    int numNodes,
    int numNodesToDistribute,
    NodePositions *nodePositions,
    TerrainData* terrainData,
    Coordinates* boundOrigin,
    Coordinates* boundDimensions,
    NodeInput *nodeInput,
    clocktype maxSimTime,
    clocktype startSimTime)
{
    int numNodesDistributed = 0;

    clocktype upperbound;
    BOOL aLineFound;
    BOOL wasFound;
    NodeInput fileInput;
    int  i, j;
#ifdef ADDON_BOEINGFCS
    double zValue = 0.0;
#endif

    PrintOutWarningsIfOldFilesSpecified(nodeInput);

    for (i = 0; i < numNodes; i++) {
        if (nodePositions[i].nodePlacementType != FILE_BASED_PLACEMENT) {
            continue;
        }

        IO_ReadCachedFile(
            nodePositions[i].nodeId,
            ANY_ADDRESS,
            nodeInput,
            "NODE-POSITION-FILE",
            &wasFound,
            &fileInput);

        if (wasFound != TRUE) {
            char errorMessage[MAX_STRING_LENGTH];

            sprintf(errorMessage,
                    "NODE-POSITION-FILE is not found for a node (Id: %u)\n",
                    nodePositions[i].nodeId);

            ERROR_ReportError(errorMessage);
        }

        if (nodePositions[i].mobilityData->mobilityType ==
            FILE_BASED_MOBILITY)
        {
            upperbound = maxSimTime;
        }
        else {
            upperbound = 0;
        }

        aLineFound = FALSE;
        clocktype   lastSimTime = 0;
        clocktype   timeDifference;
        Coordinates lastPosition;
        BOOL        firstPosition = TRUE;
        CoordinateType distance = 0;
        float       granularity;
        double      nodeSpeed;
        double      minGranularity;

        for (j = 0; j < fileInput.numLines; j++) {
            NodeAddress nodeId = nodePositions[i].nodeId;
            clocktype   simTime;
            Coordinates position;
            Orientation orientation;
            BOOL        nodeIdMatch;

            nodeIdMatch =
                ReadMobilityString(
                    fileInput.inputStrings[j],
                    &nodeId,
                    &simTime,
                    &position,
                    &orientation
#ifdef MGRS_ADDON
                    , terrainData
#endif // MGRS_ADDON
                    );

            COORD_MapCoordinateSystemToType(
                terrainData->getCoordinateSystem(), &position);

            // substract simTime by simulation start time
            simTime -= startSimTime;

#ifdef ADDON_BOEINGFCS
        // store the original zValue
            zValue = position.common.c3;
#endif

            if (nodeIdMatch == FALSE) {
                continue;
            }

            aLineFound = TRUE;

            if (nodePositions[i].mobilityData->groundNode == TRUE) {
                TERRAIN_SetToGroundLevel(terrainData, &position);
            }
            if (simTime < 0) {
                char errorStr[MAX_STRING_LENGTH] = "";
                sprintf(errorStr, "Start Time of node position must be > then simulation Start Time\n");
                ERROR_ReportError(errorStr);
            }
            if (simTime == 0) {
                MobilityElement* current;
                current = nodePositions[i].mobilityData->current;

                current->sequenceNum =
                    nodePositions[i].mobilityData->sequenceNum;
                current->time = (clocktype)0;

                current->position = position;
                current->orientation = orientation;
                current->speed = 0.0;
            }

            if (firstPosition)
            {
                lastSimTime = simTime;
                lastPosition.common.c1 = position.common.c1;
                lastPosition.common.c2 = position.common.c2;
                lastPosition.common.c3 = position.common.c3;
                firstPosition = FALSE;
            }
            else
            {
                COORD_CalcDistance(terrainData->getCoordinateSystem(),
                                   &position,
                                   &lastPosition,
                                   &distance);

                granularity =
                        nodePositions->mobilityData->distanceGranularity;

                timeDifference = simTime - lastSimTime;

                nodeSpeed = (distance * SECOND) / timeDifference;
                minGranularity = distance / timeDifference;

                if (timeDifference < (distance / granularity))
                {
                    char errorStr[MAX_STRING_LENGTH * 4]= "/0";
                    sprintf(errorStr, "Error in \".nodes\" file. "
                           "The speed for moving the node %d from "
                           "waypoint (%lf, %lf, %lf) to waypoint "
                           "(%lf, %lf, %lf) is as fast as %lf m/s. "
                           "If this is the intended speed then please "
                           "increase the value of "
                           "MOBILITY-POSITION-GRANULARITY to at least "
                           "larger than %.2f meters.\n",
                           nodeId, lastPosition.common.c1,
                           lastPosition.common.c2, lastPosition.common.c3,
                           position.common.c1, position.common.c2,
                           position.common.c3, nodeSpeed,
                           minGranularity);

                    ERROR_ReportError(errorStr);
                }

                lastSimTime = simTime;
                lastPosition.common.c1 = position.common.c1;
                lastPosition.common.c2 = position.common.c2;
                lastPosition.common.c3 = position.common.c3;
            }

            MOBILITY_AddANewDestination(
                nodePositions[i].mobilityData,
                simTime,
                position,
                orientation
#ifdef ADDON_BOEINGFCS
        , zValue
#endif
        );

            assert(position.common.c1 >= boundOrigin->common.c1);
            assert(position.common.c1 <=
                   boundOrigin->common.c1 + boundDimensions->common.c1);
            assert(position.common.c2 >= boundOrigin->common.c2);
            assert(position.common.c2 <=
                   boundOrigin->common.c2 + boundDimensions->common.c2);

            if (simTime > upperbound) {
                break;
            }
        }

        if (aLineFound == FALSE) {
            char errorMessage[MAX_STRING_LENGTH];

            sprintf(errorMessage,
                    "NODE-POSITION-FILE does not include "
                    "the initial position of a node (Id: %u)\n",
                    nodePositions[i].nodeId);
            ERROR_ReportError(errorMessage);
        }

        if (nodePositions[i].mobilityData->mobilityType !=
            FILE_BASED_MOBILITY)
        {
            // to be replaced with MOBILITY_Reset() in future..
            nodePositions[i].mobilityData->numDests = 1;
            nodePositions[i].mobilityData->destArray[0] =
                *(nodePositions[i].mobilityData->current);

            SetRandomMobility(
                nodePositions[i].nodeId,
                nodePositions[i].mobilityData,
                terrainData,
                nodeInput,
                maxSimTime);
        }

        numNodesDistributed++;

        if (numNodesDistributed == numNodesToDistribute) {
            return;
        }
    }
}


static
void SetRandomMobility(
    NodeAddress nodeId,
    MobilityData* mobilityData,
    TerrainData* terrainData,
    NodeInput* nodeInput,
    clocktype maxSimTime)
{
    assert(mobilityData->mobilityType != FILE_BASED_MOBILITY);

    if (mobilityData->mobilityType == NO_MOBILITY) {
        if (mobilityData->numDests > 1) {
            mobilityData->numDests = 1;
        }
    }
    else if (mobilityData->mobilityType == RANDOM_WAYPOINT_MOBILITY) {
#ifdef WIRELESS_LIB
        MOBILITY_WaypointInit(
            nodeId, mobilityData, terrainData, nodeInput, maxSimTime);
#else // WIRELESS_LIB
        ERROR_ReportMissingLibrary("RANDOM-WAYPOINT", "Wireless");
#endif // WIRELESS_LIB
    }
}


static
BOOL ReadMobilityString(
    char* inputString,
    NodeAddress* nodeIdPtr,
    clocktype* simTime,
    Coordinates* coordinates,
    Orientation* orientation
#ifdef MGRS_ADDON
    , TerrainData* terrainData
#endif // MGRS_ADDON
    )
{
    char   token[MAX_STRING_LENGTH];
    char*  stringPtr;
    int    numParameters;
    double azimuth = 0.0;
    double elevation = 0.0;

    NodeAddress nodeId = *nodeIdPtr;


    //
    // Set up nodeId.
    // If this nodeId is not expected by the caller,
    // return without further parsing.
    //
    IO_GetToken(token, inputString, &stringPtr);

    *nodeIdPtr = (NodeAddress)atoi(token);

    if (*nodeIdPtr != nodeId) {
        return FALSE;
    }

    //
    // Set up simTime.
    //
    IO_GetToken(token, stringPtr, &stringPtr);

    *simTime = TIME_ConvertToClock(token);

    //
    // Set up coordinates.
    //
    stringPtr = strchr(stringPtr, '(');

    if (stringPtr == NULL) {
        char errorMessage[MAX_STRING_LENGTH];

        sprintf(errorMessage,
               "The following line includes no coordinates\n"
               "such as (x, y, z) or (lat, lon, alt).\n"
               "  '%s'\n",
               inputString);
        ERROR_ReportError(errorMessage);
    }

#ifdef MGRS_ADDON
    if (terrainData->getCoordinateSystem() == MGRS)
    {
        MgrsUtility mgrs;
        std::string sw = terrainData->getMgrsSw();
        std::string ne = terrainData->getMgrsNe();

        IO_GetDelimitedToken(token, stringPtr, "(,) ", &stringPtr);
        if (mgrs.containsInSwNeRect(token, sw, ne))
        {
            coordinates->common.c1 = mgrs.swNeRectRightEdge(sw, token);
            coordinates->common.c2 = mgrs.swNeRectTopEdge(sw, token);

            // If the third parameter is omitted, set it to zero.
            if (IO_GetDelimitedToken(token, stringPtr, "(,) ", &stringPtr))
            {
                coordinates->common.c3 = atof(token);
            }
            else
            {
                coordinates->common.c3 = 0.0;
            }
        }
        else
        {
            std::stringstream error;

            error << "Out of bound: node " << nodeId << " position ("
                << token << ") is " << "not in SW (" << sw << ") and NE ("
                << ne << ").";
            ERROR_ReportError(error.str().c_str());
        }
    }
    else
#endif // MGRS_ADDON
    {
        COORD_ConvertToCoordinates(stringPtr, coordinates);
    }

    //
    // Set up orientation.
    //
    stringPtr = strchr(stringPtr, ')');

    numParameters = sscanf(&stringPtr[1], "%lf %lf", &azimuth, &elevation);

    if (numParameters == 0 || numParameters == EOF) {
        orientation->azimuth = 0;
        orientation->elevation = 0;
    }
    else {
        assert(numParameters == 1 || numParameters == 2);

        orientation->azimuth = (OrientationType)azimuth;

        if (numParameters == 2) {
            orientation->elevation = (OrientationType)elevation;
        }
        else {
            orientation->elevation = 0;
        }
    }

    return TRUE;
}
