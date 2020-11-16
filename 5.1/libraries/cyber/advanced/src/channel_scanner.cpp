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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#include <stdio.h>

#include "api.h"
#include "app_util.h"
#include "partition.h"
#include "channel_scanner.h"

enum {
    CS_EVENT_START_SCAN,
    CS_EVENT_STOP_SCAN,
    CS_EVENT_RANDOM_SCAN
};

struct ChannelScanner
{
    enum ChannelScannerType {
        SCANNER_TYPE_BASIC = 0x1001,
        SCANNER_TYPE_SWEEP = 0x1002,
        SCANNER_TYPE_FILE = 0x1003
    } scannerType;

    // pertaining to basic and sweep scanners
    double startFrequency;
    double endFrequency;


    // pertaining to sweep scanners
    enum ChannelScannerSweepType {
        SCANNER_SWEEP_SEQUENTIAL = 0x2001,
        SCANNER_SWEEP_RANDOM = 0x2002
    } sweepType;
    double bandwidth;
    clocktype slotTime;
    RandomSeed randomSeed;

    // pertaining to file scanners
    NodeInput scannerFile;

    // Caller info
    Node* node;
    void* data;
    ChannelScannerCallback callback;

    // private bookkeeping data
    clocktype repeatInterval;
    int instanceId;
    bool isActive;
    struct ChannelInfo
    {
        int stacked;
        double frequency;
        bool active;

        ChannelInfo() :stacked(0), frequency(0), active(false){}
    };
    std::vector<ChannelInfo*> channels;

    ~ChannelScanner()
    {
        for (UInt32 i = 0; i < channels.size(); i++) {
            delete channels[i];
        }
        channels.clear();
    }
};

struct ChannelScannerTimerInfo
{
    int channelIndex;
    clocktype scanDuration;
};

static ChannelScanner*
ChannelScannerGetApp(Node* node, int instanceId)
{
    AppInfo *appList = node->appData.appPtr;
    ChannelScanner *scanner;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_CHANNEL_SCANNER)
        {
            scanner = (ChannelScanner *) appList->appDetail;

            if (scanner->instanceId == instanceId)
            {
                return scanner;
            }
        }
    }

    return NULL;
}

static ChannelScanner* ChannelScannerCreate(
        Node* node,
        const char* configLinePrefix,
        int scannerInstanceId)
{
    BOOL wasFound;
    ChannelScanner* scanner = new ChannelScanner;
    char param[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char errorStr[MAX_STRING_LENGTH];

    // Read SCANNER-TYPE
    sprintf(param, "%s-SCANNER-TYPE", configLinePrefix);
    IO_ReadStringInstance(
            ANY_NODEID,
            ANY_ADDRESS,
            node->partitionData->nodeInput,
            param,
            scannerInstanceId,
            scannerInstanceId == 0,
            &wasFound,
            buf);

    if (!wasFound) {
        goto report_error_not_found;
    }

    if (!strcmp(buf, "BASIC"))
    {
        scanner->scannerType = ChannelScanner::SCANNER_TYPE_BASIC;
    }
    else if (!strcmp(buf, "SWEEP"))
    {
        scanner->scannerType = ChannelScanner::SCANNER_TYPE_SWEEP;
    }
    else if (!strcmp(buf, "FILE"))
    {
        scanner->scannerType = ChannelScanner::SCANNER_TYPE_FILE;
    }
    else
    {
        sprintf(errorStr, "Scanner type [%s] is not supported in %s for instance"
                " id = %d",
                buf,
                param,
                scannerInstanceId);
        goto report_error;
    }

    if ((scanner->scannerType == ChannelScanner::SCANNER_TYPE_BASIC)
            || (scanner->scannerType == ChannelScanner::SCANNER_TYPE_SWEEP))
    {
        // Read START-FREQUENCY
        sprintf(param, "%s-START-FREQUENCY", configLinePrefix);
        IO_ReadDoubleInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                &scanner->startFrequency);

        if (!wasFound) {
            goto report_error_not_found;
        }

        if (scanner->startFrequency <= 0)
        {
            sprintf(errorStr, "Channel frequency should be positive in "
                    "%s for instance id = %d",
                    param, scannerInstanceId);
            goto report_error;
        }

        // Read END-FREQUENCY
        sprintf(param, "%s-END-FREQUENCY", configLinePrefix);
        IO_ReadDoubleInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                &scanner->endFrequency);

        if (!wasFound) {
            goto report_error_not_found;
        }

        if (scanner->endFrequency <= 0)
        {
            sprintf(errorStr, "Channel frequency should be positive in "
                    "%s for instance id = %d",
                    param, scannerInstanceId);
            goto report_error;
        }

        if (scanner->endFrequency <= scanner->startFrequency)
        {
            sprintf(errorStr, "End frequency should be greater than start frequency in "
                    "%s for instance id = %d",
                    param, scannerInstanceId);
            goto report_error;
        }
    }

    if (scanner->scannerType == ChannelScanner::SCANNER_TYPE_SWEEP)
    {
        // Read SWEEP-BANDWIDTH
        sprintf(param, "%s-SWEEP-BANDWIDTH", configLinePrefix);
        IO_ReadDoubleInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                &scanner->bandwidth);

        if (!wasFound) {
            goto report_error_not_found;
        }

        if (scanner->bandwidth <= 0)
        {
            sprintf(errorStr, "Channel bandwidth should be postive in "
                    "%s for instance id = %d",
                    param, scannerInstanceId);
            goto report_error;
        }

        // Read SWEEP-SLOT-DURATION
        sprintf(param, "%s-SWEEP-SLOT-DURATION", configLinePrefix);
        IO_ReadTimeInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                &scanner->slotTime);

        if (!wasFound) {
            goto report_error_not_found;
        }

        if (scanner->slotTime <= 0)
        {
            sprintf(errorStr, "Sweep slot duration should be positive in "
                    "%s for instance id = %d",
                    param, scannerInstanceId);
            goto report_error;
        }

        // Read SWEEP-PATTERN
        sprintf(param, "%s-SWEEP-PATTERN", configLinePrefix);
        IO_ReadStringInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                buf);

        if (!wasFound) {
            goto report_error_not_found;
        }

        if (!strcmp(buf, "SEQ")) {
            scanner->sweepType = ChannelScanner::SCANNER_SWEEP_SEQUENTIAL;
        }
        else if (!strcmp(buf, "RANDOM")) {
            scanner->sweepType = ChannelScanner::SCANNER_SWEEP_RANDOM;
        }
        else
        {
            sprintf(errorStr, "Sweep type [%s] is not supported for "
                    "%s for instance id = %d",
                    buf, param, scannerInstanceId);
            goto report_error;
        }
    }

    if (scanner->scannerType == ChannelScanner::SCANNER_TYPE_FILE)
    {
        // Read SCANNER-FILE
        sprintf(param, "%s-SCANNER-FILE", configLinePrefix);

        IO_ReadCachedFileInstance(
                ANY_NODEID,
                ANY_ADDRESS,
                node->partitionData->nodeInput,
                param,
                scannerInstanceId,
                scannerInstanceId == 0,
                &wasFound,
                &scanner->scannerFile);

        if (!wasFound) {
            goto report_error_not_found;
        }
    }


    return scanner;

report_error_not_found:
    sprintf(errorStr, "Cannot find %s for instance id = %d.",
            param,
            scannerInstanceId);

report_error:
    ERROR_ReportWarning(errorStr);
    delete scanner;
    return NULL;
}

int ChannelScannerStart(
        Node* node,
        const char* configLinePrefix,
        int scannerInstanceId,
        ChannelScannerCallback callback,
        void* data)
{
    if (callback == NULL)
    {
        ERROR_ReportWarning("Channel Scanner Error: "
                "Callback function is not defined.");
        return -1;
    }

    ChannelScanner* scanner = ChannelScannerCreate(
            node,
            configLinePrefix,
            scannerInstanceId);

    if (scanner == NULL) {
        return -1;
    }
    scanner->isActive = true;
    scanner->node = node;
    scanner->callback = callback;
    scanner->data = data;
    scanner->instanceId = node->appData.uniqueId++;

    APP_RegisterNewApp(node, APP_CHANNEL_SCANNER, scanner);

    int numChannels = node->partitionData->numChannels;

    for (int i = 0; i < numChannels; i++) {
        ChannelScanner::ChannelInfo* info = new ChannelScanner::ChannelInfo;
        info->frequency = PROP_GetChannelFrequency(node, i);
        scanner->channels.push_back(info);
    }

    switch (scanner->scannerType)
    {
    case ChannelScanner::SCANNER_TYPE_BASIC:
    {
        // No need for timers. Just find the channels that fall within the range
        // and callback for them. Also set these channels active, so that at
        // StopScan, we can make the STOP callback
        for (UInt32 i = 0; i < scanner->channels.size(); i++)
        {
            ChannelScanner::ChannelInfo* info = scanner->channels[i];
            double frequency = info->frequency;
            if ((frequency >= scanner->startFrequency)
                    && (frequency < scanner->endFrequency))
            {
                Message* msg;

                // timer for start scanning
                msg = MESSAGE_Alloc(
                        node,
                        APP_LAYER,
                        APP_CHANNEL_SCANNER,
                        CS_EVENT_START_SCAN);

                // store the scanner instance id
                msg->instanceId = scanner->instanceId;
                // store the channel index
                MESSAGE_InfoAlloc(node, msg, sizeof(ChannelScannerTimerInfo));
                ChannelScannerTimerInfo* msginfo =
                        (ChannelScannerTimerInfo *) MESSAGE_ReturnInfo(msg);
                msginfo->channelIndex = i;
                msginfo->scanDuration = 0;
                MESSAGE_Send(node, msg, 0);
            }
        }
        break;
    }
    case ChannelScanner::SCANNER_TYPE_SWEEP:
    {
        // This is little tricky:
        /* a) If sweep type is sequential
         * We optimize by sending timers only when channels exist for
         * a given frequency range.
         * for (startFrequency to endFrequency step bandwidth)
         *         if there is a good channel:
         *             send a "start scan" timer to self
         * During this process we also compute 'repeatInterval', which is
         * the time interval after which the process repeats.
         * Now, when the above timer expires, we start scan.
         * Then we send the same timer with delay = slot time to stop scan.
         * When the above expires, we send it again with delay =
         * (repeatInterval - slottime) to start scan again
         *
         * b) if sweep type is random
         * We still go through the same loop, but this time we do not send
         * any "start scan" timer, or even look for good channel.
         * The purpose of looping is to find 'repeatInterval', which is
         * relevant since (repeatInterval/slottime) is the number of
         * "buckets" from which we have to randomly pick.
         */

        clocktype delay = 0;
        double lowerFreq = scanner->startFrequency;
        double upperFreq;

        while (lowerFreq < scanner->endFrequency)
        {
            upperFreq = lowerFreq + scanner->bandwidth;
            if (upperFreq > scanner->endFrequency) {
                upperFreq = scanner->endFrequency;
            }

            // If this is random scanner, we are interested in computing
            // 'repeatInterval' only
            if (scanner->sweepType == ChannelScanner::SCANNER_SWEEP_RANDOM)
            {
                lowerFreq += scanner->bandwidth;
                delay += scanner->slotTime;
                continue;
            }

            // else (this is sequential sweep), we schedule events if there are
            // valid channels in this frequency range (our optimization)
            for (int i = 0; i < scanner->channels.size(); i++)
            {
                ChannelScanner::ChannelInfo* info = scanner->channels[i];
                double frequency = info->frequency;
                if ((frequency >= lowerFreq) && (frequency < upperFreq))
                {
                    Message* msg;

                    // timer for start scanning
                    msg = MESSAGE_Alloc(
                            node,
                            APP_LAYER,
                            APP_CHANNEL_SCANNER,
                            CS_EVENT_START_SCAN);

                    // store the scanner instance id
                    msg->instanceId = scanner->instanceId;
                    // store the channel index
                    MESSAGE_InfoAlloc(node, msg, sizeof(ChannelScannerTimerInfo));
                    ChannelScannerTimerInfo* msginfo =
                            (ChannelScannerTimerInfo *) MESSAGE_ReturnInfo(msg);
                    msginfo->channelIndex = i;
                    msginfo->scanDuration = scanner->slotTime;
                    MESSAGE_Send(node, msg, delay);
                }
            }

            lowerFreq += scanner->bandwidth;
            delay += scanner->slotTime;
        }

        scanner->repeatInterval = delay;

        // No optimization for random sweeper. Need to schedule event
        // for each slot
        if (scanner->sweepType == ChannelScanner::SCANNER_SWEEP_RANDOM)
        {
            RANDOM_SetSeed(
                    scanner->randomSeed,
                    node->globalSeed,
                    node->nodeId,
                    APP_CHANNEL_SCANNER,
                    scanner->instanceId);

            Message* msg;

            // timer for start scanning
            msg = MESSAGE_Alloc(
                    node,
                    APP_LAYER,
                    APP_CHANNEL_SCANNER,
                    CS_EVENT_RANDOM_SCAN);

            // store the scanner instance id
            msg->instanceId = scanner->instanceId;
            MESSAGE_Send(node, msg, 0);
        }
        break;
    }
    case ChannelScanner::SCANNER_TYPE_FILE:
    {
        NodeInput* nodeInput = &scanner->scannerFile;
        for (int line = 0; line < nodeInput->numLines; line++)
        {
            char token[4][MAX_STRING_LENGTH];
            double lowerFreq;
            double upperFreq;
            clocktype startTime;
            clocktype endTime;

            scanner->repeatInterval = 0;

            sscanf(nodeInput->inputStrings[line], "%s %s %s %s",
                    token[0],
                    token[1],
                    token[2],
                    token[3]);

            lowerFreq = atof(token[0]);
            upperFreq = atof(token[1]);
            startTime = TIME_ConvertToClock(token[2]);
            endTime = TIME_ConvertToClock(token[3]);

            if (endTime > scanner->repeatInterval) {
                scanner->repeatInterval = endTime;
            }

            for (UInt32 i = 0; i < scanner->channels.size(); i++)
            {
                ChannelScanner::ChannelInfo* info = scanner->channels[i];
                double frequency = info->frequency;
                if ((frequency >= lowerFreq) && (frequency < upperFreq))
                {
                    Message* msg;

                    // timer for start scanning
                    msg = MESSAGE_Alloc(
                            node,
                            APP_LAYER,
                            APP_CHANNEL_SCANNER,
                            CS_EVENT_START_SCAN);

                    // store the scanner instance id
                    msg->instanceId = scanner->instanceId;
                    // store the channel index
                    MESSAGE_InfoAlloc(node, msg, sizeof(ChannelScannerTimerInfo));
                    ChannelScannerTimerInfo* info =
                            (ChannelScannerTimerInfo *) MESSAGE_ReturnInfo(msg);
                    info->channelIndex = i;
                    info->scanDuration = endTime - startTime;
                    MESSAGE_Send(node, msg, startTime);
                }
            }

        }
        break;
    }
    default:
        ;
    }


    return scanner->instanceId;
}

void ChannelScannerStop(
        Node* node,
        int handle)
{
    ChannelScanner* scanner = ChannelScannerGetApp(node, handle);

    if (!scanner) {
        return;
    }

    scanner->isActive = false;

    for (UInt32 i = 0; i < scanner->channels.size(); i++)
    {
        ChannelScanner::ChannelInfo* info = scanner->channels[i];
        if (info->active)
        {
            // we have already validated earlier that callback is not null
            scanner->callback(
                    scanner->node,
                    i,
                    CHANNEL_SCANNING_STOPPED,
                    scanner->data);
            info->active = false;
        }
    }

    APP_UnregisterApp(node, scanner, false);
    delete scanner;
}


void ChannelScannerProcessEvent(
        Node* node,
        Message* msg)
{
    ChannelScanner* scanner = ChannelScannerGetApp(node, msg->instanceId);

    if (!scanner || !scanner->isActive) {
        MESSAGE_Free(node, msg);
        return;
    }

    switch (msg->eventType)
    {
    case CS_EVENT_START_SCAN:
    {
        // callback for this channel index
        ChannelScannerTimerInfo* msginfo =
                (ChannelScannerTimerInfo *) MESSAGE_ReturnInfo(msg);
        int channelIndex = msginfo->channelIndex;
        ChannelScanner::ChannelInfo* info = scanner->channels[channelIndex];

        if (!info->active) {
            scanner->callback(
                    scanner->node,
                    channelIndex,
                    CHANNEL_SCANNING_STARTED,
                    scanner->data);
        }
        else {
            info->stacked ++;
        }

        // this channel is not actively scanned
        info->active = true;

        // send the timer again.. this time to indicate the scan stop
        msg->eventType = CS_EVENT_STOP_SCAN;
        if (msginfo->scanDuration > 0) {
            MESSAGE_Send(node, msg, msginfo->scanDuration);
        }
        else {
            MESSAGE_Free(node, msg);
        }
        break;
    }
    case CS_EVENT_STOP_SCAN:
    {
        ChannelScannerTimerInfo* msginfo =
                (ChannelScannerTimerInfo *) MESSAGE_ReturnInfo(msg);
        int channelIndex = msginfo->channelIndex;
        ChannelScanner::ChannelInfo* info = scanner->channels[channelIndex];

        if (info->stacked == 0)
        {
            scanner->callback(
                    scanner->node,
                    channelIndex,
                    CHANNEL_SCANNING_STOPPED,
                    scanner->data);

            info->active = false;
        }
        else {
            info->stacked--;
        }

        msg->eventType = CS_EVENT_START_SCAN;
        MESSAGE_Send(
                node,
                msg,
                scanner->repeatInterval - msginfo->scanDuration);
        break;
    }
    case CS_EVENT_RANDOM_SCAN:
    {
        int buckets = scanner->repeatInterval / scanner->slotTime;
        double lowerFreq = scanner->startFrequency +
                (scanner->bandwidth
                        * (RANDOM_nrand(scanner->randomSeed) % buckets));
        double upperFreq = lowerFreq + scanner->bandwidth;
        if (upperFreq > scanner->endFrequency) {
            upperFreq = scanner->endFrequency;
        }

        for (UInt32 i = 0; i < scanner->channels.size(); i++)
        {
            ChannelScanner::ChannelInfo* info = scanner->channels[i];


            double frequency = info->frequency;
            if ((frequency >= lowerFreq) && (frequency < upperFreq))
            {
                // If this channel is already active, no need to anything here
                if (!info->active)
                {
                    scanner->callback(
                            scanner->node,
                            i,
                            CHANNEL_SCANNING_STARTED,
                            scanner->data);

                    info->active = true;
                }

                continue;
            }


            if (info->active)
            {
                scanner->callback(
                        scanner->node,
                        i,
                        CHANNEL_SCANNING_STOPPED,
                        scanner->data);
                info->active = false;
            }
        }

        MESSAGE_Send(node, msg, scanner->slotTime);
        break;
    }

    }
}
