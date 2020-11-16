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
#include <limits.h>
#include <string.h>
#include <math.h>
#include <map>

#include "main.h"
#include "api.h"
#include "partition.h"
#include "antenna.h"
#include "node.h"
#include "network_ip.h"

#ifdef PARALLEL //Parallel
#include "parallel.h"
#endif //endParallel


#ifdef ADDON_NGCNMS
#include "prop_flat_binning.h"

#define DEBUG 0
#define DEBUG_BOX_CREATION 0
#define DEBUG_MATRIX_PROP 0
#define DEBUG_MOBILITY_UPDATE 0

#define MAX_MATRIX_SIZE 60


/*
    Determine which grid box a node is currently in
    by its current position
*/
static
int PropFlatBinningCalculateCurrentBox(PartitionData* partitionData,
                                        Coordinates currPosition,
                                        GridInfo* gridInfo,
                                        int* xBox,
                                        int* yBox)
{

    double degreesEW = 0;
    double degreesNS = 0;
    int numX = 0;
    int numY = 0;
    int boxNum = 0;

    // See how many degrees east of terrain's western border
    // node currently is
    degreesEW = currPosition.latlonalt.longitude -
        gridInfo->northWestCoord.latlonalt.longitude;

    // See how many degrees south of terrain's norther border
    // node currently is
    degreesNS = gridInfo->northWestCoord.latlonalt.latitude -
        currPosition.latlonalt.latitude;

    numX = ceil(degreesEW / gridInfo->xDegrees);

    numY = ceil(degreesNS / gridInfo->yDegress);

    boxNum = (numX-1) + (gridInfo->numXBoxes * (numY-1));

    *xBox = numX;
    *yBox = numY;

    return boxNum;
}


/*
    Determine which the middle of a box in the matrix
    grid for pathloss calculations
*/
static
Coordinates PropFlatBinningCalculateMatrixBinMiddle(int x,
                                                    int y,
                                                    GridInfo* matrixInfo)
{
    Coordinates middleBoxCoords;

    memset(&middleBoxCoords, 0, sizeof(Coordinates));

    middleBoxCoords.type = GEODETIC;

    middleBoxCoords.latlonalt.longitude =
        matrixInfo->northWestCoord.latlonalt.longitude +
        ((double)x + 0.5) * matrixInfo->xDegrees;

    middleBoxCoords.latlonalt.latitude =
        matrixInfo->northWestCoord.latlonalt.latitude -
        ((double)y + 0.5) * matrixInfo->yDegress;

    middleBoxCoords.latlonalt.altitude = 0;

    return middleBoxCoords;
}


/*
    Matrix Propagation code still needs to be re-written
    for lat-long compatibility
*/
PropPathProfile PropFlatBinningGetPropPathProfileFromMatrix(
    PartitionData* partitionData,
    int channelIndex,
    double wavelength,
    float txAntennaHeight,
    float rxAntennaHeight,
    float txPower_dBm,
    float txAntennaGain_dBi,
    PropPathProfile* profile,
    int index)
{
    double pathloss_dB;

    GridInfo* gridInfo = &(partitionData->gridInfo[channelIndex]);
    GridInfo* matrixInfo = &(partitionData->pathlossMatrixGrid[channelIndex]);

    // Box numbers of matrix and binning grids for to/from positions
    int matrixFromBoxNum = 0;
    int binFromBoxNum = 0;
    int matrixToBoxNum = 0;
    int binToBoxNum = 0;

    // x and y box nums for matrix grid for to/from positions
    int xToMatrix = 0;
    int yToMatrix = 0;
    int xFromMatrix = 0;
    int yFromMatrix = 0;

    // x and y box nums for binning grid for to/from positions
    int xToBin = 0;
    int yToBin = 0;
    int xFromBin = 0;
    int yFromBin = 0;

    // Get the box #'s of the matrix grid being sent from
    matrixFromBoxNum = PropFlatBinningCalculateCurrentBox(partitionData,
        profile->fromPosition,
        matrixInfo,
        &xFromMatrix,
        &yFromMatrix);

    // Get the box #'s of the matrix grid being sent to
    matrixToBoxNum = PropFlatBinningCalculateCurrentBox(partitionData,
        profile->toPosition,
        matrixInfo,
        &xToMatrix,
        &yToMatrix);


    PropGridMatrix* destMatrix;
    PropPathProfile newPathProfile;
    BOOL needToAdd = FALSE;

    std::map<int, PropGridMatrix>::iterator it;
    std::map<int, PropPathProfile>::iterator it2;

    it = partitionData->propChannel[channelIndex].chanGridMatrix.find(matrixFromBoxNum);

    if (it == partitionData->propChannel[channelIndex].chanGridMatrix.end())
    {
        needToAdd = TRUE;
    }
    else {
        it2 = it->second.gridMatrix.find(matrixToBoxNum);
        if (it2 != it->second.gridMatrix.end()) {
            partitionData->numUsedMatrix++;
            return it->second.gridMatrix[matrixToBoxNum];
        }
        else {
            needToAdd = TRUE;
        }
    }

    if (needToAdd) {

        if (partitionData->propChannel[channelIndex].chanGridMatrix[matrixFromBoxNum].gridMatrix.size() >
            MAX_MATRIX_SIZE)
        {
            partitionData->numMatrixErased++;
            partitionData->propChannel[channelIndex].chanGridMatrix[matrixFromBoxNum].gridMatrix.erase(
                partitionData->propChannel[channelIndex].chanGridMatrix[matrixFromBoxNum].gridMatrix.begin());
        }

        memcpy(&newPathProfile, profile, sizeof(PropPathProfile));

        if (DEBUG_MATRIX_PROP) {
            printf("Channel %d Sending from spot %f, %f (%d), to %f, %f (%d)\n",
                channelIndex,
                profile->fromPosition.latlonalt.latitude,
                profile->fromPosition.latlonalt.longitude,
                matrixFromBoxNum,
                profile->toPosition.latlonalt.latitude,
                profile->toPosition.latlonalt.longitude,
                matrixToBoxNum);
        }

        // Get the box #'s of the binning grid being sent from
        binFromBoxNum = PropFlatBinningCalculateCurrentBox(partitionData,
            profile->fromPosition,
            gridInfo,
            &xFromBin,
            &yFromBin);

        // Get the box #'s of the binning grid being sent from
        binToBoxNum = PropFlatBinningCalculateCurrentBox(partitionData,
            profile->toPosition,
            gridInfo,
            &xToBin,
            &yToBin);

        Coordinates middleFromMatrix;
        Coordinates middleToMatrix;

        middleFromMatrix = PropFlatBinningCalculateMatrixBinMiddle(
            (xFromMatrix-1),
            (yFromMatrix-1),
            matrixInfo);

        middleToMatrix = PropFlatBinningCalculateMatrixBinMiddle(
            (xToMatrix-1),
            (yToMatrix-1),
            matrixInfo);

        memcpy(&newPathProfile.fromPosition,
            &middleFromMatrix,
            sizeof(Coordinates));
        memcpy(&newPathProfile.toPosition,
            &middleToMatrix,
            sizeof(Coordinates));


        if (DEBUG_MATRIX_PROP) {
            printf("Using center of boxes, (%f, %f, %f) -> (%f, %f, %f)\n",
                newPathProfile.fromPosition.latlonalt.latitude,
                newPathProfile.fromPosition.latlonalt.longitude,
                newPathProfile.fromPosition.latlonalt.altitude,
                newPathProfile.toPosition.latlonalt.latitude,
                newPathProfile.toPosition.latlonalt.longitude,
                newPathProfile.toPosition.latlonalt.altitude);
        }

        // Calculate new path profile
        COORD_CalcDistanceAndAngle(
            PARTITION_GetTerrainPtr(node)->getCoordinateSystem(),
            &(newPathProfile.fromPosition),
            &(newPathProfile.toPosition),
            &(newPathProfile.distance),
            &(newPathProfile.txDOA),
            &(newPathProfile.rxDOA));

        PropChannel* propChannel = &(partitionData->propChannel[channelIndex]);
        newPathProfile.propDelay =
            PROP_CalculatePropagationDelay(
                newPathProfile.distance,
                propChannel->profile->wavelength * propChannel->profile->frequency,
                partitionData,
                PARTITION_GetTerrainPtr(node)->getCoordinateSystem(),
                &(newPathProfile.fromPosition),
                &(newPathProfile.toPosition),
                FALSE);

        PROP_CalculatePathloss(
            partitionData->firstNode,
            1, 2, // arbitrary txNodeId and rxNodeId
            channelIndex,
            wavelength,
            txAntennaHeight,
            rxAntennaHeight,
            &newPathProfile,
            &pathloss_dB,
            true); // for binning

        if (pathloss_dB >= 0.0) {
            newPathProfile.pathloss_dB = pathloss_dB;
        }
        else {
            newPathProfile.pathloss_dB = NEGATIVE_PATHLOSS_dB;
        }

        if (DEBUG_MATRIX_PROP) {
            printf("Pathloss = %f\n", newPathProfile.pathloss_dB);
        }

        partitionData->numMatrixAdded++;
        partitionData->propChannel[channelIndex].chanGridMatrix[matrixFromBoxNum].gridMatrix[matrixToBoxNum] =
            newPathProfile;

    }

    return partitionData->propChannel[channelIndex].chanGridMatrix[matrixFromBoxNum].gridMatrix[matrixToBoxNum];
}


/*
    Creates the grid boxes for flat binning
    or propagtion matrix.

    origin coords = south west
    end coords = north east
*/
static
void PropFlatBinningCreateBoxes(GridInfo* gridInfo,
                                BOOL autoBuild,
                                int channelIndex,
                                double chanLargestRange,
                                Coordinates endCoords,
                                Coordinates originCoords,
                                GridInfo* largerInfo,
                                BOOL matrix)
{
    double numX = 0;
    double numY = 0;

    Coordinates southEastCoords;
    Coordinates northWestCoords;

    CoordinateType distanceSWSE;
    CoordinateType distanceSWNW;
    CoordinateType distanceSENE;
    CoordinateType distanceNWNE;

    // larger east-west distance
    CoordinateType ewDistance;

    // larger north-south distance
    CoordinateType nsDistance;

    double degreesEW = 0;
    double degreesNS = 0;


    // Create coordinate point of South East point of terrain
    memcpy(&southEastCoords, &originCoords, sizeof(Coordinates));
    southEastCoords.latlonalt.longitude =
        endCoords.latlonalt.longitude;

    // Create coordinate point of North West point of terrain
    memcpy(&northWestCoords, &originCoords, sizeof(Coordinates));
    northWestCoords.latlonalt.latitude =
        endCoords.latlonalt.latitude;

    degreesEW = endCoords.latlonalt.longitude -
        northWestCoords.latlonalt.longitude;

    degreesNS = endCoords.latlonalt.latitude -
        southEastCoords.latlonalt.latitude;

    if (!matrix) {
        // Distance between SW and SE points
        COORD_CalcDistance(LATLONALT,
            &originCoords,
            &southEastCoords,
            &distanceSWSE);

        // Distance between SE and NE points
        COORD_CalcDistance(LATLONALT,        +
            &southEastCoords,
            &endCoords,
            &distanceSENE);

        // Distance between NW and NE points
        COORD_CalcDistance(LATLONALT,
            &northWestCoords,
            &endCoords,
            &distanceNWNE);

        // Distance between SW and NW points
        COORD_CalcDistance(LATLONALT,
            &originCoords,
            &northWestCoords,
            &distanceSWNW);

        // With curved earth, either the SW-SE
        // or NW-NE distance will be longer than
        // the other, depending on which hemisphere.
        // We want create a box using the longer
        // of the two.
        if (distanceSWSE > distanceNWNE) {
            // northern hemisphere
            ewDistance = distanceNWNE;
            memcpy(&gridInfo->smallerWestCoord,
                &northWestCoords,
                sizeof(Coordinates));
        }
        else {
            // southern hemisphere
            ewDistance = distanceSWSE;
            memcpy(&gridInfo->smallerWestCoord,
                &originCoords,
                sizeof(Coordinates));
        }

        // I think these two should be the same always
        if (distanceSWNW > distanceSENE) {
            nsDistance = distanceSWNW;
        }
        else {
            nsDistance = distanceSENE;
        }

        memcpy(&(gridInfo->northWestCoord),
            &northWestCoords,
            sizeof(Coordinates));
    }

    if (matrix) {
        memcpy(&gridInfo->smallerWestCoord,
            &largerInfo->smallerWestCoord,
            sizeof(Coordinates));

        memcpy(&gridInfo->northWestCoord,
            &largerInfo->northWestCoord,
            sizeof(Coordinates));
    }

    if (autoBuild) {
        numX = ewDistance / chanLargestRange;

        numY = nsDistance / chanLargestRange;

        /* Slightly resize the boxes if necessary so
           that all boxes have the same east-west and
           north-south size.  The sizes will be rounded
           up to the next highest amount to make the
           sizes even.

           Note that due to the older convention we
           can are using 'x' and 'east-west' interchangably
           along with 'y' and 'north-south'
         */
        gridInfo->numXBoxes = floor(numX);
        gridInfo->numYBoxes = floor(numY);

        if (gridInfo->numXBoxes == 0) {
            gridInfo->numXBoxes = 1;
            printf("Warning: Range for channel %d is "
                "larger than terrain in east-west direction. "
                "Making box X-size %f instead of %f\n",
                channelIndex,
                ewDistance,
                chanLargestRange);
        }

        if (gridInfo->numYBoxes == 0) {
            gridInfo->numYBoxes = 1;
            printf("Warning: Range for channel %d is "
                "larger than terrain in north-south direction. "
                "Making box Y-size %f instead of %f\n",
                channelIndex,
                nsDistance,
                chanLargestRange);
        }

        gridInfo->xDegrees = degreesEW / gridInfo->numXBoxes;
        gridInfo->yDegress = degreesNS / gridInfo->numYBoxes;

        gridInfo->xSize = ewDistance / gridInfo->numXBoxes;
        gridInfo->ySize = nsDistance / gridInfo->numYBoxes;

    }
    else {
        if (matrix) {
            ewDistance = largerInfo->xSize;
            nsDistance = largerInfo->ySize;
        }

        numX = ewDistance / gridInfo->xSize;
        numY = nsDistance / gridInfo->ySize;

        /* Slightly resize the boxes if necessary so
           that all boxes have the same east-west and
           north-south size.  The sizes will be rounded
           up to the next highest amount to make the
           sizes even.

           Note that due to the older convention we
           can are using 'x' and 'east-west' interchangably
           along with 'y' and 'north-south'
         */
        gridInfo->numXBoxes = floor(numX);
        gridInfo->numYBoxes = floor(numY);

        // Determine size and number of boxes based on
        // user input values
        if (numX != floor(numX))
        {
            double newXSize = 0;
            gridInfo->numXBoxes = floor(numX);
            newXSize = ewDistance / gridInfo->numXBoxes;

            if (!matrix) {
                printf("Warning: PropFlatBin x grid size does"
                    "not evenly fit with terrain data. "
                    "Changing from %f to %f\n",
                    gridInfo->xSize,
                    newXSize);
            }
            else {
                printf("Warning: PropMatrix x grid size does"
                    "not evenly fit with flat bin size. "
                    "Changing from %f to %f\n",
                    gridInfo->xSize,
                    newXSize);
            }

            gridInfo->xSize = newXSize;
        }

        if (numY != floor(numY))
        {
            double newYSize = 0;
            gridInfo->numYBoxes = floor(numY);
            newYSize = nsDistance / gridInfo->numYBoxes;

            if (!matrix) {
                printf("Warning: PropFlatBin y grid size does"
                    "not evenly fit with terrain data. "
                    "Changing from %f to %f\n",
                    gridInfo->ySize,
                    newYSize);
            }
            else {
                printf("Warning: PropMatrix y grid size does"
                    "not evenly fit with flat bin size. "
                    "Changing from %f to %f\n",
                    gridInfo->ySize,
                    newYSize);
            }

            gridInfo->ySize = newYSize;
        }
    }

    if (matrix) {
        gridInfo->numXBoxes *= largerInfo->numXBoxes;
        gridInfo->numYBoxes *= largerInfo->numYBoxes;
    }

    gridInfo->xDegrees = degreesEW / gridInfo->numXBoxes;
    gridInfo->yDegress = degreesNS / gridInfo->numYBoxes;

    if (DEBUG_BOX_CREATION) {
        printf("For channel %d:\n", channelIndex);
        printf("\tBox east-west size = %f meters, %f degrees\n",
            gridInfo->xSize,
            gridInfo->xDegrees);
        printf("\tBox north-south size = %f meters, %f degrees\n",
            gridInfo->ySize,
            gridInfo->yDegress);
    }


    // Propagation Matrix boxes will be allocated on the fly
    // to conserve memory.  There should be far few flat binning
    // boxes, so we will allocate them and their hashes here for
    // speed and convenience
    if (!matrix) {
        GridBox *gridBox = NULL;

        // Allocate all the boxes for Flat Binning
        int totNumBoxes = gridInfo->numXBoxes * gridInfo->numYBoxes;
        gridBox = (GridBox*)MEM_malloc(sizeof(GridBox) * totNumBoxes);
        memset(gridBox, 0, sizeof(GridBox) * totNumBoxes);

        int b=0;
        int y=0;
        int x=0;
        for (y=0; y<gridInfo->numYBoxes; y++) {
            for (x=0; x<gridInfo->numXBoxes; x++)
            {
                // Determine current box number
                b = x + y*gridInfo->numXBoxes;

                // Initialize hash of nodes contained for that box
                gridBox[b].nodeHash = new PropFlatBinningNodeHash();
                gridBox[b].sizeNodeList = 0;
                gridBox[b].numInNodeList = 0;
            }

        }
        gridInfo->gridBox = gridBox;
    }
}


/*
    Read the user input data, create the grid infos
    and call the functions to create the boxes within
    the grids
*/
static
void PropFlatBinningBuildGrids(PartitionData* partitionData)
{
    int channelIndex = 0;
    int numNodes = 0;
    int n=0;
    int i=0;
    double range = 0;
    Node* node = NULL;
    double* largestRange = NULL;
    Node** nodeLargestRange = NULL;
    int* interfaceLargestRange = NULL;

    int numChannels = partitionData->numChannels;
    largestRange = (double*)MEM_malloc(sizeof(double) * numChannels);
    nodeLargestRange = (Node**)MEM_malloc(sizeof(Node*) * numChannels);
    interfaceLargestRange = (int*)MEM_malloc(sizeof(int) * numChannels);

    // Read in user config values for flat binning and
    // matrix propagation binning
    for (channelIndex = 0;
        channelIndex < numChannels;
        channelIndex++)
    {
        if (partitionData->propChannel[channelIndex].useFlatBinning) {
            largestRange[channelIndex] = 0;
            nodeLargestRange[channelIndex] = NULL;
            interfaceLargestRange[channelIndex] = 0;
            partitionData->gridUpdateTime[channelIndex] =
                PROP_FLAT_BINNING_UPDATE_TIMER_DEFAULT;

            clocktype value;
            BOOL wasFound;
            IO_ReadTimeInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                partitionData->nodeInput,
                "PROPAGATION-FLAT-BINNING-UPDATE-TIMER",
                channelIndex,
                TRUE,
                &wasFound,
                &value);

            if (wasFound) {
                partitionData->gridUpdateTime[channelIndex] = value;
            }

            BOOL autoBuildVal = TRUE;
            partitionData->gridAutoBuild[channelIndex] = TRUE;
            IO_ReadBoolInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                partitionData->nodeInput,
                "PROPAGATION-FLAT-BINNING-AUTO-BUILD-GRID",
                channelIndex,
                TRUE,
                &wasFound,
                &autoBuildVal);

            if (wasFound) {
                partitionData->gridAutoBuild[channelIndex] = autoBuildVal;
            }

            if (!partitionData->gridAutoBuild[channelIndex])
            {
                double manualXGridSize = 0;
                double manualYGridSize = 0;

                IO_ReadDoubleInstance(
                    ANY_NODEID,
                    ANY_ADDRESS,
                    partitionData->nodeInput,
                    "PROPAGATION-FLAT-BINNING-GRID-X-SIZE",
                    channelIndex,
                    TRUE,
                    &wasFound,
                    &manualXGridSize);

                if (wasFound) {
                    partitionData->gridInfo[channelIndex].xSize = manualXGridSize;
                }
                else {
                    ERROR_Assert(FALSE,
                        "PropFlatBinning: Grid Build set to manual,"
                        " but no X size provided\n");
                }

                IO_ReadDoubleInstance(
                    ANY_NODEID,
                    ANY_ADDRESS,
                    partitionData->nodeInput,
                    "PROPAGATION-FLAT-BINNING-GRID-Y-SIZE",
                    channelIndex,
                    TRUE,
                    &wasFound,
                    &manualYGridSize);

                if (wasFound) {
                    partitionData->gridInfo[channelIndex].ySize = manualYGridSize;
                }
                else {
                    ERROR_Assert(FALSE,
                        "PropFlatBinning: Grid Build set to manual,"
                        " but no Y size provided\n");
                }
            }
        }


        if (partitionData->propChannel[channelIndex].useFlatPathlossMatrix)
        {
            double manualXPathlossGridSize = 0;
            double manualYPathlossGridSize = 0;
            BOOL wasFound;

            IO_ReadDoubleInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                partitionData->nodeInput,
                "PROPAGATION-PATHLOSS-MATRIX-GRID-X-SIZE",
                channelIndex,
                TRUE,
                &wasFound,
                &manualXPathlossGridSize);

            if (wasFound) {
                partitionData->pathlossMatrixGrid[channelIndex].xSize =
                    manualXPathlossGridSize;
            }
            else {
                ERROR_Assert(FALSE,
                    "PropFlatBinning: Pathloss Binning turned on,"
                    " but no X size provided\n");
            }

            IO_ReadDoubleInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                partitionData->nodeInput,
                "PROPAGATION-PATHLOSS-MATRIX-GRID-Y-SIZE",
                channelIndex,
                TRUE,
                &wasFound,
                &manualYPathlossGridSize);

            if (wasFound) {
                partitionData->pathlossMatrixGrid[channelIndex].ySize =
                    manualYPathlossGridSize;
            }
            else {
                ERROR_Assert(FALSE,
                    "PropFlatBinning: Pathloss Binning turned on,"
                    " but no Y size provided\n");
            }
        }
    }

    // Determine the largest range in the channel.  This will be the
    // size of the grid boxes if auto-build is turned on
    for (channelIndex = 0;
        channelIndex < numChannels;
        channelIndex++)
    {
        if (partitionData->propChannel[channelIndex].useFlatBinning &&
            partitionData->gridAutoBuild[channelIndex])
        {
            numNodes =
                partitionData->propChannel[channelIndex].numNodes;

            for (n=0; n<numNodes; n++) {
                node =
                    partitionData->propChannel[channelIndex].nodeList[n];

                range = 0;
                for (i=0; i<node->numberInterfaces; i++) {
                    if (node->phyData[i]->channelListenable[channelIndex]) {

                        // Get the interference range in free-space
                        range = PHY_PropagationRange(node,
                            i,
                            FALSE);
                    }

                    if (range > largestRange[channelIndex]) {
                        largestRange[channelIndex] = range;
                        nodeLargestRange[channelIndex] = node;
                        interfaceLargestRange[channelIndex] = i;
                    }
                }

            }
        }
    }

    // Debug prints to show the largest ranges gathered for
    // the different channels
    if (DEBUG_BOX_CREATION) {
        for (channelIndex = 0;
            channelIndex < numChannels;
            channelIndex++)
        {
            if (partitionData->propChannel[channelIndex].useFlatBinning &&
                partitionData->gridAutoBuild[channelIndex])
            {
                printf("For channel %d the largest range is %f, from "
                    "node %d, interface %d\n",
                    channelIndex,
                    largestRange[channelIndex],
                    nodeLargestRange[channelIndex]->nodeId,
                    interfaceLargestRange[channelIndex]);
            }
        }
    }


    // Get terrain info, and use it to set grid
    TerrainData *terrainData;
    terrainData = PARTITION_GetTerrainPtr(node);

    /*
        Using the origin (southwest) and dimension coords,
        determine the 'endCoords' (northeast)

        Note the binning now requires lat/long coordinates
    */
    Coordinates endCoords;
    Coordinates originCoords;
    if (terrainData->coordinateSystemType == LATLONALT)
    {
        endCoords.type = GEODETIC;
        endCoords.latlonalt.latitude =
            terrainData->origin.latlonalt.latitude +
            terrainData->dimensions.latlonalt.latitude;

        endCoords.latlonalt.longitude =
            terrainData->origin.latlonalt.longitude +
            terrainData->dimensions.latlonalt.longitude;

        endCoords.latlonalt.altitude =
            terrainData->origin.latlonalt.altitude +
            terrainData->dimensions.latlonalt.altitude;

        memcpy(&originCoords,
            &terrainData->origin,
            sizeof(Coordinates));
    }
    else {
        ERROR_Assert(FALSE,
                    "Flat Binning can only handle terrain"
                    " with LAT-LONG coordinates\n");
    }

    // Create the individual grid boxes within the grid
    // matrix pathloss turned off for moment until it is
    // rewritten for lat-long
    for (channelIndex = 0;
        channelIndex < numChannels;
        channelIndex++)
    {
        if (partitionData->propChannel[channelIndex].useFlatBinning) {

            PropFlatBinningCreateBoxes(
                &(partitionData->gridInfo[channelIndex]),
                partitionData->gridAutoBuild[channelIndex],
                channelIndex,
                largestRange[channelIndex],
                endCoords,
                originCoords,
                NULL,
                FALSE);
        }

        if (partitionData->propChannel[channelIndex].useFlatPathlossMatrix) {
            PropFlatBinningCreateBoxes(
                &(partitionData->pathlossMatrixGrid[channelIndex]),
                FALSE,
                channelIndex,
                largestRange[channelIndex],
                endCoords,
                originCoords,
                &(partitionData->gridInfo[channelIndex]),
                TRUE);
        }

    }

    MEM_free(largestRange);
    MEM_free(nodeLargestRange);
    MEM_free(interfaceLargestRange);

}


/*
    Population the hashes of grid boxes by determining
    which grid box a node is in, and placing its node
    pointer in that box's hash
*/
static
void PropFlatBinningFillGridsWithNodes(PartitionData* partitionData)
{
    int c=0;
    Node *node = NULL;
    int n=0;
    int numNodes = 0;
    GridInfo *gridInfo = NULL;

    for (c=0; c<partitionData->numChannels; c++)
    {
        if (partitionData->propChannel[c].useFlatBinning) {
            numNodes = partitionData->propChannel[c].numNodes;
            gridInfo = &(partitionData->gridInfo[c]);
            GridBox *gridBox = gridInfo->gridBox;

            for (n=0; n<numNodes; n++)
            {
                node = partitionData->propChannel[c].nodeList[n];
                if (node->partitionId == partitionData->partitionId) {
                    MobilityData* mobilityData = node->mobilityData;


                    Coordinates currPosition;
                    // Currently, mobility position saying its coords are
                    // in 'invalid type'...need to look into this later

                        memcpy(&currPosition,
                            &(mobilityData->current->position),
                            sizeof(Coordinates));

                    int boxNum = 0;
                    int x=0;
                    int y=0;
                    CoordinateType distanceEast=0;
                    boxNum = PropFlatBinningCalculateCurrentBox(
                        partitionData,
                        currPosition,
                        gridInfo,
                        &x,
                        &y);

                    // add node to box's hash
                    gridBox[boxNum].nodeHash->AddHashEntry(node);

                    // keep record within node of which box its
                    // currently in
                    node->currentGridBoxNumber[c] = boxNum;
                }

            }

            if (DEBUG_BOX_CREATION) {
                printf("For Channel %d\n", c);
                int numBoxes = gridInfo->numXBoxes * gridInfo->numYBoxes;
                int b=0;

                for (b=0; b<numBoxes; b++)
                {
                    gridInfo->gridBox[b].nodeHash->PrintHashNodes(b);
                }

            }
        }
    }

}


/*
    Create a node list of the nodes that in that will a signal will be
    delivered to.  This include the nodes in the same box as the sender
    and the nodes in the boxes surrouding the sender.  This list is
    placed in a newly created PropChannel for easy integration
    with propagation_private
*/
void
PropFlatBinningSetPropChannel(PropTxInfo* propTxInfo,
                                           PartitionData* partitionData,
                                           int channelIndex,
                                           PropChannel *propChannel,
                                           int *numNodes)
{
    Node* txNode = propTxInfo->txNode;

#ifdef USE_MPI
    BOOL nodeIsLocal;
    if (txNode == NULL) {
        nodeIsLocal = PARTITION_ReturnNodePointer(
            partitionData,
            &txNode,
            propTxInfo->txNodeId,
            TRUE);
    }
    assert(txNode != NULL);
#endif

    GridInfo *gridInfo = NULL;
    gridInfo = &(partitionData->gridInfo[channelIndex]);
        GridBox *gridBox = gridInfo->gridBox;

    int interfaceIndex = -1;
    /*for (int x=0; x<txNode->numberInterfaces; x++) {
        if (txNode->phyData[x]->channelListenable[channelIndex])
            interfaceIndex = x;
    }

    if (interfaceIndex == -1)
        ERROR_ReportWarning("Cannot find interface in Flat Binning Set Channel");*/

    interfaceIndex = propTxInfo->phyIndex;

    /*MobilityData* mobilityData = txNode->mobilityData;
    Coordinates currPosition = mobilityData->current->position;*/
    Coordinates currPosition = propTxInfo->position;

    // Determine which box the node is currently in
    int boxNum=0;
#ifdef USE_MPI
    BOOL needToUpdate = FALSE;
    if (txNode->currentGridBoxNumber == NULL) {

        int numChannels = txNode->partitionData->numChannels;
        txNode->currentGridBoxNumber =
            (int*)MEM_malloc(sizeof(int) * numChannels);
        txNode->lastGridPositionUpdate =
            (clocktype*)MEM_malloc(sizeof(clocktype) * numChannels);

        int c=0;
        for (c=0; c<numChannels; c++) {
            txNode->lastGridPositionUpdate[c] = 0;
            txNode->currentGridBoxNumber[c] = -1;
        }

        needToUpdate = TRUE;
    }
    else {
        if (txNode->currentGridBoxNumber[channelIndex] == -1) {
            needToUpdate = TRUE;
        }
    }
    if (needToUpdate) {
        int x=0;
        int y=0;
        boxNum = PropFlatBinningCalculateCurrentBox(
            partitionData,
            currPosition,
            gridInfo,
            &x,
            &y);
        txNode->currentGridBoxNumber[channelIndex] = boxNum;
    }

#endif
    boxNum= txNode->currentGridBoxNumber[channelIndex];

    GridBox *neighbor;
    int neighborBoxNum;
    BOOL neighborInBox[9];
    int numInBox = 0;

    int x=0;
    int marker = 0;
    int numInNodeList = 0;
    *numNodes = propChannel->numNodes;

    // Cycle through node's current box and all its neighbor boxes
    // to and those boxes hashes to the node list
    for (x=0; x<9; x++) {
        switch (x) {
            case 0: neighborBoxNum = boxNum - gridInfo->numXBoxes - 1; break;
            case 1: neighborBoxNum = boxNum - gridInfo->numXBoxes; break;
            case 2: neighborBoxNum = boxNum - gridInfo->numXBoxes + 1; break;
            case 3: neighborBoxNum = boxNum - 1; break;
            case 4: neighborBoxNum = boxNum; break;
            case 5: neighborBoxNum = boxNum + 1; break;
            case 6: neighborBoxNum = boxNum + gridInfo->numXBoxes - 1; break;
            case 7: neighborBoxNum = boxNum + gridInfo->numXBoxes; break;
            case 8: neighborBoxNum = boxNum + gridInfo->numXBoxes + 1; break;
        }

        int hashSize = -1;
        int numBoxes = gridInfo->numXBoxes * gridInfo->numYBoxes - 1;
        if (neighborBoxNum > numBoxes)
            neighborBoxNum = -1;

        if (neighborBoxNum >= 0) {
            hashSize = gridBox[neighborBoxNum].nodeHash->GetHashSize();
        }

        // If there are nodes in the neighbor box, add them to the
        // node list
        if (hashSize > 0) {

            if (DEBUG) {
                printf("Neighbor: ");
                gridBox[neighborBoxNum].nodeHash->PrintHashNodes(neighborBoxNum);
                printf("Self: ");
                gridBox[boxNum].nodeHash->PrintHashNodes(boxNum);
            }

            int currNumber = *numNodes;

            *numNodes+=hashSize;

            int copied = 0;

            copied = gridBox[neighborBoxNum].nodeHash->CopyToNodeList(
                propChannel,
                hashSize);

            /*
                With the math in the switch statement, we may try
                and copy the nodes of one box twice.  This is checked
                for in CopyToNodeList, and if that function returns
                a zero it means we did not recopy the box's hash to
                the list.  Therefore, we shouldn't have increased
                the size of the node list again
            */
            if (!copied) {
                *numNodes -= hashSize;
            }

        }
    }
}


/*
    Allocate structures and call functions to build the grids
    and populate them with the nodes in them
*/

void
PropFlatBinningInit(PartitionData* partitionData)
{

    int numChannels = partitionData->numChannels;
    Node *node = partitionData->firstNode;
    int c=0;
    while (node != NULL) {
        node->lastGridPositionUpdate =
            (clocktype*)MEM_malloc(sizeof(clocktype) * numChannels);

        node->currentGridBoxNumber=
            (int*)MEM_malloc(sizeof(int) * numChannels);

        for (c=0; c<numChannels; c++) {
            node->lastGridPositionUpdate[c] = 0;
            node->currentGridBoxNumber[c] = -1;
        }

        node = node->nextNodeData;
    }

    // Get terrain info, and use it to set grid
    TerrainData *terrainData;
    terrainData = PARTITION_GetTerrainPtr(node);

    if (terrainData->dataType == NO_TERRAIN_DATA)
        return;

    partitionData->gridInfo =
        (GridInfo*)MEM_malloc(sizeof(GridInfo) * numChannels);

    partitionData->pathlossMatrixGrid =
        (GridInfo*)MEM_malloc(sizeof(GridInfo) * numChannels);

    partitionData->gridUpdateTime =
        (clocktype*)MEM_malloc(sizeof(clocktype) * numChannels);

    partitionData->gridAutoBuild =
        (BOOL*)MEM_malloc(sizeof(BOOL) * numChannels);

    PropFlatBinningBuildGrids(partitionData);

    PropFlatBinningFillGridsWithNodes(partitionData);
}


/*
    With mobility a node may not stay in its same box
    throughout the entire simulation.  This function
    determines if the node is still within the same box,
    and if not, removes the pointer from the box it is in
    and puts a pointer in the hash of its new box
*/
void
PropFlatBinningUpdateNodePosition(Node *node,
                                  int phyIndex)
{
    clocktype currTime = node->getNodeTime();
    char timeString[MAX_STRING_LENGTH];
    TIME_PrintClockInSecond(currTime, timeString);
    clocktype updateInterval = 0;
    PartitionData *partitionData = node->partitionData;
    int numChannels = partitionData->numChannels;

    int c=0;

    for (c=0; c<numChannels; c++) {
        if (partitionData->propChannel[c].useFlatBinning) {
            if (node->phyData[phyIndex]->channelListenable[c]) {

                /*
                    To cut down on timers we just keep track of the
                    last time we updated, and if its more than an
                    update interval away, we update.
                */

                updateInterval = partitionData->gridUpdateTime[c];
                if ((node->lastGridPositionUpdate[c] + updateInterval) <=
                    currTime)
                {
                    if (DEBUG_MOBILITY_UPDATE) {
                        printf( "%s: time to update position of node %d\n",
                            timeString,
                            node->nodeId);
                    }

                    node->lastGridPositionUpdate[c] = currTime;


                    GridInfo *gridInfo = &(partitionData->gridInfo[c]);

                    MobilityData* mobilityData = node->mobilityData;

                    Coordinates currPosition = mobilityData->current->position;
                    int boxNum = 0;
                    int x=0;
                    int y=0;
                    boxNum = PropFlatBinningCalculateCurrentBox(
                        node->partitionData,
                        currPosition,
                        gridInfo,
                        &x,
                        &y);

                    if (boxNum != node->currentGridBoxNumber[c])
                    {
                        if (DEBUG_MOBILITY_UPDATE) {
                            printf("Removing node %d from box %d\n",
                                node->nodeId,
                                node->currentGridBoxNumber[c]);
                        }

                        // Remove from old box hash
                        gridInfo->gridBox[node->currentGridBoxNumber[c]].nodeHash->RemoveHashEntry(
                            node->nodeId);

                        if (DEBUG_MOBILITY_UPDATE) {
                            printf("Adding node %d from box %d\n",
                                node->nodeId,
                                boxNum);
                        }

                        // Add to new box hash
                        gridInfo->gridBox[boxNum].nodeHash->AddHashEntry(node)  ;

                        // Update box number in node pointer
                        node->currentGridBoxNumber[c] = boxNum;
                    }

                }
            }
        }
    }

}


/*
    Hash table constructor
*/
PropFlatBinningNodeHash::PropFlatBinningNodeHash()
{
    //count = 0;
}


/*
    Add a node to a hash
*/
NodeAddress
PropFlatBinningNodeHash::AddHashEntry(Node* node)
{
    hash[node->nodeId] = node;

    return node->nodeId;
}

/*
    Remove a node from a hash
*/
Node*
PropFlatBinningNodeHash::RemoveHashEntry(NodeAddress nodeId)
{
    std::map<NodeAddress, Node*>::iterator it;
    Node* node;

    it = hash.find(nodeId);

    if (it == hash.end())
    {
        return NULL;
    }
    else
    {
        node = it->second;
        hash.erase(it);
        return node;
    }
}


/*
    Retrieve a node pointer from a hash
*/
Node*
PropFlatBinningNodeHash::RetrieveEntry(NodeAddress id)
{
    std::map<NodeAddress, Node*>::iterator it;
    Node* node;

    it = hash.find(id);

    if (it == hash.end())
    {
        return NULL;
    }
    else
    {
        node = it->second;
        return node;
    }
}


/*
    Print the contents of a hash
*/
void
PropFlatBinningNodeHash::PrintHashNodes(int boxNum)
{
    std::map<NodeAddress, Node*>::iterator it;
    Node* node;

    it = hash.begin();

    if (!hash.empty()) {
        printf("\tBox %d has nodes: \n", boxNum);
    }

    while (it != hash.end()) {
        printf("\t\t%d\n", it->first);
        ++it;
    }
}


/*
    Copy a grid box's hash of node pointers
    to the list of nodes that is returned to
    propagation_private
*/
int
PropFlatBinningNodeHash::CopyToNodeList(PropChannel *propChannel,
                                        int hashSize)
{
    std::map<NodeAddress, Node*>::iterator it;
    Node* node;
    int marker = 0;

    // If box is an edge case, we might have already copied
    // this neighbor box to the list.  Check here if we have.
    // If so, return 0.
    int n=0;
    it = hash.begin();
    for (n=0; n < propChannel->numNodes; n++) {
        if (propChannel->nodeList[n]->nodeId == it->second->nodeId) {
            return 0;
        }
    }

    propChannel->numNodes += hashSize;

    // If this neighbor box's nodes are not already found in the list
    // then increase the list size and copy them in
    Node **oldList = propChannel->nodeList;
    propChannel->nodeList =
        (Node**)MEM_malloc(sizeof(Node*) * propChannel->numNodes);
    memset(propChannel->nodeList,
        0,
        sizeof(Node*) * propChannel->numNodes);

    marker = propChannel->numNodes - hashSize;


    if (oldList != NULL) {
        memcpy(propChannel->nodeList,
            oldList, marker * sizeof(Node*));
        MEM_free(oldList);
    }

    if (DEBUG) {
        printf("Getting ready to copy to node list\n");
    }
    for (n=marker; n<propChannel->numNodes; n++) {
        node = it->second;
        propChannel->nodeList[n] = node;


        if (DEBUG) {
            printf("Added %d to spot %d\n",
                propChannel->nodeList[n]->nodeId,
                n);
        }

        ++it;
    }

    // Code to order the node list.  I dont think this is
    // needed but leaving commented version in for the time being
    // just in case

    /*oldList = propChannel->nodeList;
    propChannel->nodeList =
        (Node**)MEM_malloc(sizeof(Node*) * propChannel->numNodes);

    int i=0;
    int j=0;
    int prevleast = -1;
    for (i=0; i<propChannel->numNodes; i++) {
        marker = 0;
        int least = oldList[0]->nodeId;
        while (prevleast >= least && marker<(propChannel->numNodes-1))  {
            marker++;
            least = oldList[marker]->nodeId;
        }

        for (j=0; j<propChannel->numNodes; j++) {
            BOOL lessThanLeast = oldList[j]->nodeId < least;
            BOOL greaterThanPrevLeast = ((int)oldList[j]->nodeId) > prevleast;
            if (lessThanLeast && greaterThanPrevLeast)
            {
                least = oldList[j]->nodeId;
                marker = j;
            }
        }

        prevleast = least;
        propChannel->nodeList[i] = oldList[marker];
    }

    MEM_free(oldList);*/

    return 1;

}

/*
    Return number of node pointers in the hash
*/
int
PropFlatBinningNodeHash::GetHashSize()
{
    return hash.size();
}
#endif
