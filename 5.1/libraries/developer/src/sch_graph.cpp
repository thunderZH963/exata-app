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

// /**
// PROTOCOL     :: Queue-Scheduler
// LAYER        ::
// REFERENCES   :: None
// COMMENTS     :: None
// **/

#include <stdio.h>

#include "api.h"
#include "sch_graph.h"


#define SERVICE_RATIO_GRAPH 0
#define THRUPUT_GRAPH 0
#define QUEUE_SIZE_IN_PKTS_GRAPH 0
#define QUEUE_SIZE_IN_BYTES_GRAPH 0


//**
// FUNCTION   :: SchedGraphStat::openFilePointer
// LAYER      ::
// PURPOSE    :: Opens a file in which the graph data for scheduler
//               performance is collected and writes headings in it.
// PARAMETERS ::
// + graphFileName[] : const char : Graph file name
// + locationInfoStr[] : const char : Location of the file
// + graphFileFd : FILE** : Pointer of pointer to graph FILE
// RETURN     :: void : Null
// **/

void SchedGraphStat::openFilePointer(
    const char graphFileName[],
    char locationInfoStr[],
    FILE** graphFileFd)
{
    char fileName[MAX_STRING_LENGTH] = {0};
    int i = 0;
    int len = (int)strlen(locationInfoStr);

    // Convert : into dot format, in case of IPv6.
    while (i < len)
    {
        if (locationInfoStr[i] == ':')
        {
            locationInfoStr[i] = '.';
        }
        i++;
    }

    sprintf(fileName, "%s.%s", graphFileName, locationInfoStr);


    *graphFileFd = fopen(fileName, "wb");

    if (*graphFileFd == NULL)
    {
        ERROR_ReportError("Graph: File open error\n");
    }

    fprintf(*graphFileFd,"%s vs time(sec)\n\n", graphFileName);
}


//**
// FUNCTION   :: SchedGraphStat::writeSeriesTags
// LAYER      ::
// PURPOSE    :: Writes series tag in file
// PARAMETERS ::
// + numQueues : int : Number of queue
// RETURN     :: void : Null
// **/

void SchedGraphStat::writeSeriesTags(int numQueues)
{
    int i = 0;
    int len = MAX_STRING_LENGTH;
    char* seriesTags = NULL;
    seriesTags = (char*)MEM_malloc(len);
    memset(seriesTags, 0, MAX_STRING_LENGTH);
    strcpy(seriesTags,"time(sec)\t");
    for (i = 0; i < numQueues; i++)
    {
        char queueTag[MAX_STRING_LENGTH] = {0};
        sprintf(queueTag, "\t\tQueue[%d]", i);
        if ((int)(strlen(seriesTags) + strlen(queueTag)) >  len)
        {
            len *= 2;
            char* temStr = (char*)MEM_malloc(len);
            strcpy(temStr, seriesTags);
            MEM_free(seriesTags);
            seriesTags = temStr;
        }
        strcat(seriesTags, queueTag);
    }
    if (THRUPUT_GRAPH)
    {
        fprintf(thruputFd, "%s\n\n", seriesTags);
    }

    if (SERVICE_RATIO_GRAPH)
    {
        fprintf(serviceRatioFd, "%s\n\n", seriesTags);
    }

    if (QUEUE_SIZE_IN_PKTS_GRAPH)
    {
        fprintf(queueSizePktsFd, "%s\n\n", seriesTags);
    }

    if (QUEUE_SIZE_IN_BYTES_GRAPH)
    {
        fprintf(queueSizeBytesFd, "%s\n\n", seriesTags);
    }
}


//**
// FUNCTION   :: SchedGraphStat::SchedGraphStat
// LAYER      ::
// PURPOSE    :: SchedGraphStat constructor
// PARAMETERS ::
// + graphDataStr : const char : Graph data string
// RETURN     :: None
// **/

SchedGraphStat::SchedGraphStat(const char graphDataStr[])
{
    char graphFileName[MAX_STRING_LENGTH] = {0};
    char intervalStr[MAX_STRING_LENGTH] = {0};
    char locationInfoStr[MAX_STRING_LENGTH] = {0};

    // graphDataStr: <sampleInterval> <interfaceAddress.out>
    sscanf(graphDataStr, "%s %s", intervalStr, locationInfoStr);

    intervalForCollectGraphStat = TIME_ConvertToClock(intervalStr);

    totalNumDequeRequestPerInterval = 0;
    lastStorageTimeForCollectGraphStat = (clocktype) 0;

    schedQueueInfo = NULL;

    if (THRUPUT_GRAPH)
    {
        strcpy(graphFileName,"scheduler-thruput-kbps");
        openFilePointer(graphFileName, locationInfoStr, &thruputFd);
    }

    if (SERVICE_RATIO_GRAPH)
    {
        strcpy(graphFileName,"scheduler-service-ratio");
        openFilePointer(graphFileName, locationInfoStr, &serviceRatioFd);
    }

    if (QUEUE_SIZE_IN_PKTS_GRAPH)
    {
        strcpy(graphFileName,"scheduler-queue-size-pkts");
        openFilePointer(graphFileName, locationInfoStr, &queueSizePktsFd);
    }

    if (QUEUE_SIZE_IN_BYTES_GRAPH)
    {
        strcpy(graphFileName,"scheduler-queue-size-bytes");
        openFilePointer(graphFileName, locationInfoStr, &queueSizeBytesFd);
    }
}


//**
// FUNCTION   :: SchedGraphStat::collectStatisticsForGraph
// LAYER      ::
// PURPOSE    :: Function collecting graph data for scheduler
// PARAMETERS ::
// + scheduler : Scheduler* : Pointer to the Scheduler class
// + numQueues : const int : Number of queue
// + priority : const int : Priority of the queue
// + pktSize : const int : Packet's size
// + currentTime : const clocktype : Current simulation time
// RETURN     :: void : Null
// **/

void SchedGraphStat::collectStatisticsForGraph(
    Scheduler* scheduler,
    const int numQueues,
    const int priority,
    const int pktSize,
    const clocktype currentTime)
{
    int i = 0;
    clocktype interval = currentTime - lastStorageTimeForCollectGraphStat;

    if (schedQueueInfo == NULL)
    {
        schedQueueInfo = (SchedQueueInfo*) MEM_malloc(
            sizeof(SchedQueueInfo) * numQueues);
        memset(schedQueueInfo, 0, sizeof(SchedQueueInfo) * numQueues);
        writeSeriesTags(numQueues);
    }

    if (THRUPUT_GRAPH)
    {
        schedQueueInfo[priority].numByteDequeuePerInterval += pktSize;
    }

    if (SERVICE_RATIO_GRAPH)
    {
        totalNumDequeRequestPerInterval++;
        schedQueueInfo[priority].numPktDequeuePerInterval++;
    }

    if (interval >= intervalForCollectGraphStat)
    {
        char time[MAX_STRING_LENGTH] = {0};

        lastStorageTimeForCollectGraphStat = currentTime;
        TIME_PrintClockInSecond(lastStorageTimeForCollectGraphStat, time);

        if (THRUPUT_GRAPH)
        {
            fprintf(thruputFd, "%s\t", time);

            for (i = 0; i < numQueues; i++)
            {
                fprintf(thruputFd, "%15f\t",
                    (schedQueueInfo[i].numByteDequeuePerInterval * 8.0)
                        / (((double)interval / SECOND) * pow(10.0,3.0)));

                schedQueueInfo[i].numByteDequeuePerInterval = 0;
            }
            fprintf(thruputFd, "\n");
        }

        if (SERVICE_RATIO_GRAPH)
        {
            fprintf(serviceRatioFd, "%s\t", time);

            for (i = 0; i < numQueues; i++)
            {
                fprintf(serviceRatioFd, "%15f\t",
                    ((double)schedQueueInfo[i].numPktDequeuePerInterval
                        / totalNumDequeRequestPerInterval));
                schedQueueInfo[i].numPktDequeuePerInterval = 0;
            }

            fprintf(serviceRatioFd, "\n");

            totalNumDequeRequestPerInterval = 0;
        }

        if (QUEUE_SIZE_IN_PKTS_GRAPH)
        {
            fprintf(queueSizePktsFd, "%s\t", time);

            for (i = 0; i < numQueues; i++)
            {
                fprintf(queueSizePktsFd, "%12u\t\t",
                    (*scheduler).numberInQueue(i));
            }

            fprintf(queueSizePktsFd, "\n");
        }

        if (QUEUE_SIZE_IN_BYTES_GRAPH)
        {
            fprintf(queueSizeBytesFd, "%s\t", time);

            for (i = 0; i < numQueues; i++)
            {
                fprintf(queueSizeBytesFd, "%12u\t",
                    (*scheduler).bytesInQueue(i));
            }
            fprintf(queueSizeBytesFd, "\n");
        }
    }
}


//**
// FUNCTION   :: SchedGraphStat::~SchedGraphStat
// LAYER      ::
// PURPOSE    :: SchedGraphStat destructor
// PARAMETERS :: None
// RETURN     :: NA :: None
// **/

SchedGraphStat::~SchedGraphStat()
{
    if (schedQueueInfo != NULL)
    {
        MEM_free(schedQueueInfo);
    }

    if (THRUPUT_GRAPH)
    {
        fclose(thruputFd);
    }

    if (SERVICE_RATIO_GRAPH)
    {
        fclose(serviceRatioFd);
    }

    if (QUEUE_SIZE_IN_PKTS_GRAPH)
    {
        fclose(queueSizePktsFd);
    }

    if (QUEUE_SIZE_IN_BYTES_GRAPH)
    {
        fclose(queueSizeBytesFd);
    }
}

