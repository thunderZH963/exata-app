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

#ifndef OS_RESOURCE_MANAGER_H_
#define OS_RESOURCE_MANAGER_H_

class OSResourceManager
{
public:
    /**
     * Constructor.
     * This object is initialized for those nodes only that have
     * OS-RESOURCE-MODEL value as YES.
     */
    OSResourceManager(Node* node);

    ~OSResourceManager(){};

    /**
     * Read the configuration parameters from config file.
     * @param nodeInput
     */
    void init(const NodeInput* nodeInput);

    /**
     * Report statistics in the stat file.
     */
    void finalize();

    // Allocation and deallocation of resources

    /**
     * Consume memory resource for a packet.
     * @param msg The packet that will be stored in the OS buffers.
     * @see packetFree()
     */
    void packetAllocated(const Message* msg);

    /**
     * Free memory resource for a packet
     * @param msg The packet that will will be freed from the OS buffers.
     * @see packetAllocated()
     */
    void packetFree(const Message* msg);

    /**
     * Consume memory resource when a new TCP connection is established.
     * @see connectionTeardown()
     */
    void connectionEstablished();

    /**
     * Free memory resource when an existing TCP connection is closed.
     * @see connectionEstablished()
     */
    void connectionTeardown();

    /**
     * Consume CPU resource when processing a protocol timer event.
     */
    void timerExpired();

    /**
     * Consume CPU resource when processing a packet.
     */
    void processPacket();


    // Current resource levels
    /**
     * Return the current memory usage.
     * @see currentCPU()
     * @see peakMemoryUsage()
     * @see peakCPUUsage()
     */
    double currentMemory();

    /**
     * Return the current CPU usage (as CPU Backlog)
     * @see currentMemory()
     * @see peakMemoryUsage()
     * @see peakCPUUsage()
     */
    clocktype currentCPU();

    /**
     * Return the peak memory usage.
     * @see currentMemory()
     * @see currentCPU()
     * @see peakCPUUsage()
     */
    long peakMemoryUsage();

    /**
     * Return the peak CPU usage (as CPU backlog).
     * @see currentMemory()
     * @see currentCPU()
     * @see peakMemoryUsage()
     */
    clocktype peakCPUUsage();


    /**
     * GUI Run Time Stats
     */
    void runTimeStats();

private:
    Node* node;

    // Memory resource modeling
    double memoryCapacity;
    double packetMemoryOverhead;
    double connectionMemoryUsage;
    double memoryUsage;

    // CPU resource modeling
    clocktype maxCPUBacklog;
    clocktype cpuLoadPerEvent;
    clocktype backlogLastUpdatedAt;
    double backloggedLoads;


    // Failure modeling
    static const int FAILURE_MODE_SHUTDOWN = 1;
    static const int FAILURE_MODE_RECOVER = 2;
    int failureMode;
    BOOL isShutdown;

    // Statistics
    double _peakMemoryUsage;
    clocktype _peakCPUBacklog;
    long numMemoryFailures;
    long numCPUFailures;

    // GUI run time stats
    int memoryGUIDisplayId;
    int cpuGUIDisplayId;

    /**
     * Helper function to read parameter values.
     */
    double readDoubleParameter(
            const char* parameterName,
            const NodeInput* nodeInput);

    clocktype readTimeParameter(
            const char* parameterName,
            const NodeInput* nodeInput);

    /**
     * Consume the indicated amount of memory.
     */
    void useMemory(double amount);

    /**
     * Free up the indicated amount of memory.
     */
    void freeMemory(double amount);

    /**
     * Consume the indicated amount of CPU resource.
     */
    void useCPU(clocktype amount);

    /**
     * Cause the node to shutdown.
     * This is modeled as turning off all the interfaces on
     * this node (via MSG_MAC_StartFault event).
     */
    void shutdown();

    /**
     * Cause the node to recover from memory failure.
     * This is modeled by free'ing up the memory used by the node.
     * This includes:
     * 1. Dropping all packets from the network layer output queue.
     * 2. Dropping all fragmented packets in the network fragment queue.
     * 3. Closing all TCP connections.
     */
    void recoverMemoryFailure();

    /**
     * Cause the node to recover from CPU failure.
     * This is modeled by turning off the interfaces on this node
     * for maxCPUBacklog duration.
     */
    void recoverCPUFailure();
};

#endif /* OS_RESOURCE_MANAGER_H_ */
