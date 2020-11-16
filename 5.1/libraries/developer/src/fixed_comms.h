#ifndef DIALED_H
#define DIALED_H


void FixedComms_Initialize(Node* node, const NodeInput* nodeInput);

static BOOL FixedComms_DetermineDrop(double dropVal, RandomSeed seed);

void FixedComms_DelayDrop(Node* node, Message* message, BOOL * wasProcessed);

static void FixedComms_SendDelay(Node* node, Message* message, BOOL * wasSentDelay);

#endif
