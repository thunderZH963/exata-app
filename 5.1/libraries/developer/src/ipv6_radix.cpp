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

//
// Ported from FreeBSD 4.7
// This file contains function for radix search mechanisim
//

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//  This product includes software developed by the University of
//  California, Berkeley and its contributors.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//

#include <stdio.h>
#include "api.h"
#include "ipv6_radix.h"
#include "ipv6.h"
#include "network_ip.h"

#define DEBUG_IPV6 0

//---------------------------------------------------------------------------
// FUNCTION             : GetValue
// PURPOSE             :: Returns the key value from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : unsigned int*: Pointer to radix key
// NOTES                : This function's pointer is stored in radix tree.
//---------------------------------------------------------------------------
unsigned char* GetValue(void* vdata)
{
     rn_leaf* tempLeaf = (rn_leaf*) vdata;

     return (tempLeaf->key.s6_addr8);
}



//---------------------------------------------------------------------------
// FUNCTION             : GetLinkLayerValue
// PURPOSE             :: Returns the LinkLayer Address from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : MacHWAdress: Link layer address
// NOTES                : This function is used in radix insertion.
//---------------------------------------------------------------------------
MacHWAddress GetLinkLayerValue(void* vdata)
{
    rn_leaf* tempLeaf = (rn_leaf*) vdata;
    return (tempLeaf->linkLayerAddr);
}



//---------------------------------------------------------------------------
// FUNCTION             : GetFlags
// PURPOSE             :: Returns the value of flags from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : unsigned char
//---------------------------------------------------------------------------
unsigned char GetFlags(void* vdata)
{
    rn_leaf* tempLeaf = (rn_leaf*)vdata;
    return (tempLeaf->flags);
}



//---------------------------------------------------------------------------
// FUNCTION             : GetIndex
// PURPOSE             :: Returns the Interface index from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : int
//---------------------------------------------------------------------------
int GetIndex(void* vdata)
{
    rn_leaf* tempLeaf = (rn_leaf*)vdata;
    return (tempLeaf->interfaceIndex);
}



//---------------------------------------------------------------------------
// FUNCTION             : GetType
// PURPOSE             :: Returns the type from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : int
//---------------------------------------------------------------------------
int GetType(void* vdata)
{
    rn_leaf* tempLeaf = (rn_leaf*)vdata;
    return (tempLeaf->type);
}



//---------------------------------------------------------------------------
// FUNCTION             : GetGateway
// PURPOSE             :: Returns the gateway from data.
// PARAMETERS          ::
// + vdata              : void* vdata: Void pointer to radix leaf data
// RETURN               : int *
//---------------------------------------------------------------------------
unsigned char* GetGateway(void* vdata)
{
     rn_leaf* tempLeaf = (rn_leaf*)vdata;

     return (tempLeaf->gateway.s6_addr8);
}



//---------------------------------------------------------------------------
// FUNCTION             : radixNodeAlloc
// PURPOSE             :: Allocates radix node.
// PARAMETERS          :: None
// RETURN               : radix_node*
//---------------------------------------------------------------------------
radix_node* radixNodeAlloc()
{
    radix_node* tempNode = (radix_node*) MEM_malloc(sizeof(radix_node));
    tempNode->nextNode[0] = NULL;
    tempNode->nextNode[1] = NULL;
    return tempNode;
}



//---------------------------------------------------------------------------
// FUNCTION             : rn_init
// PURPOSE             :: Radix tree initialization function.
// PARAMETERS          ::
// + ipv6               : struct ipv6_data_struct* ipv6: Ipv6 data pointer of
//                      :               node.
// RETURN               : None
//---------------------------------------------------------------------------
void rn_init(struct ipv6_data_struct* ipv6)
{
    int i;

    radix_node_head* temp = NULL;
    radix_node_head* ndptemp = NULL;
    radix_node* root = NULL;

    temp = (radix_node_head*)MEM_malloc(sizeof(radix_node_head));
    root = temp->root = radixNodeAlloc();
    root->childlink = 0;
    root->nextNode[0] = NULL;
    root->nextNode[1] = NULL;

    //root->rn_flags = RNF_ROOT | RNF_ACTIVE;
    temp->totalNodes = 0;
    temp->maxKeyLen = ipv6->max_keylen;
    temp->getValueFnPtr = GetValue;

    temp->stack = (radix_node**)
        MEM_malloc(ipv6->max_keylen * sizeof(radix_node*));

    temp->path_info = (int*) MEM_malloc(ipv6->max_keylen * sizeof(int));
    ipv6->rt_tables = temp;

    // NDP Table Initialize.
    ndptemp = (radix_node_head*)MEM_malloc(sizeof(radix_node_head));
    root = ndptemp->root = radixNodeAlloc();
    root->childlink = 0;

    root->nextNode[0] = NULL;
    root->nextNode[1] = NULL;

    ndptemp->totalNodes = 0;
    ndptemp->maxKeyLen = 128;
    ndptemp->getValueFnPtr = GetValue;

    ndptemp->stack = (radix_node**)
        MEM_malloc(ndptemp->maxKeyLen * sizeof(radix_node *));

    ndptemp->path_info =
        (int*) MEM_malloc(ndptemp->maxKeyLen * sizeof(int));

    ipv6->ndp_cache = ndptemp;

    // reverse lookup init
    for (i = 0; i < MAX_REVLOOKUP_SIZE; i++)
    {
        ipv6->reverse_ndp_cache[i] = NULL;
    }
    return;
}



//---------------------------------------------------------------------------
// FUNCTION             : Rn_LeafAlloc
// PURPOSE             :: Radix leaf allocation function
// PARAMETERS          :: None
// RETURN               : rn_leaf*
//---------------------------------------------------------------------------
rn_leaf*
Rn_LeafAlloc()
{
    rn_leaf* temp = (rn_leaf*)MEM_malloc(sizeof(rn_leaf));

    memset(temp, 0, sizeof(rn_leaf));

    temp->flags = (unsigned char) (-1);
    temp->interfaceIndex = -1;
    temp->keyPrefixLen = (unsigned int)-1;
    temp->type = 0;

    temp->rn_option = RTM_ADD;

    CLR_ADDR6(temp->gateway);

    return (temp);
}


//---------------------------------------------------------------------------
// FUNCTION             : rn_search
// PURPOSE             :: It searches a particular key in the specified tree
//                      : if found returns data else returns null.
// PARAMETERS          ::
// + keyNode            : void* keyNode: Void pointer to radix key node
// + tree               : radix_node_head* tree: Readix tree head.
// RETURN               : void *
//---------------------------------------------------------------------------
void*
rn_search(void* keyNode,
    radix_node_head* tree)
{
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    int index = 0;
    radix_node* current;
    int childBit;
    unsigned char bitOff[16];
    int lastPrefixLen = 0;
    int remainderBits = 0;

    if (tree->maxKeyLen <= 32)
    {
        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[0] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[0] = 7;
            bitOff[1] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = 7;
            bitOff[3] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 64)
    {
        for (index = 0; index < 4; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[4] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[4] = 7;
            bitOff[5] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = 7;
            bitOff[7] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 96)
    {
        for (index = 0; index < 8; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 64 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[8] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[8] = 7;
            bitOff[9] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = 7;
            bitOff[11] = (UInt8)remainderBits;
        }
    }
    else
    {
        for (index = 0; index < 12; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 96 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[12] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[12] = 7;
            bitOff[13] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = 7;
            bitOff[15] = (UInt8)remainderBits;
        }
    }

    key = tree->getValueFnPtr(keyNode);

    for (index = 0; index < 16; index++)
    {
        mask[index] = 0x01 << bitOff[index];
    }

    index = 0;

    // Search for the item with key `key'.
    current = tree->root;
    for (;;)
    {
        // Traverse left or right branch, depending on the current bit.
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*) current->nextNode[childBit];

        // Move to the next bit.
        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }
    }

    if (current->nextNode[childBit])
    {
        tempKey = tree->getValueFnPtr(current->nextNode[childBit]);

        if (memcmp(tempKey, key, sizeof(in6_addr)) == 0)
        {
            if (((rn_leaf *)current->nextNode[childBit])->rn_flags
                 == RNF_IGNORE)
            {
                // routes with flag RNF_IGNORE is considered as deleted
                return NULL;
            }
            else
            {
                return current->nextNode[childBit];
            }
        }
    }
    return NULL;
}

//---------------------------------------------------------------------------
// FUNCTION             : rn_bestPrefixMatch
// PURPOSE             :: It initially traverses to a valid leaf node if the
//                        current pointer has no valid leaf node,then further
//                        It matches the best available prefix basically it
//                        traverses the doubly linked list and checks for the
//                        best matching prefix available in the list.
// PARAMETERS          ::
// + current           :: radix_node* :This is a radix node pointer which
//                        is a pointer to the current node where any match
//                        has been failed in rn_match().
// + childbit          :: int :This is the bit which helps to
//                        traverse to the next node to investigated.
// + key.....          :: unsigned char*: pointer to radix tree head.
// + tree              :: radix_node_head*:This is used to request for
//                        the root of the radix trie being searched.
// RETURN              :: rn_leaf*
//---------------------------------------------------------------------------
rn_leaf* rn_bestPrefixMatch(
                           radix_node* current,
                           int childbit,
                           unsigned char* key,
                           radix_node_head* tree)
{
    radix_node* newnode = NULL;
    radix_node* radixNode = (radix_node*)tree->root;
    rn_leaf* leaf_node = NULL;
    rn_leaf* traverse_node = (rn_leaf*)current->nextNode[childbit];
    in6_addr prefix;

    int flag = 0;


// if the condition is not true and means their is no valid leaf node to
// match the key,hence the loop terminates at a valid leaf node so that the
//search and backtracking code can follow


    if (!current->nextNode[childbit] ||
       ((rn_leaf*)current->nextNode[childbit])->rn_flags == RNF_IGNORE)
    {
        flag = 0;
        while (!flag)
        {
            if (current->childlink & 0x01)
            {
                current = (radix_node*)current->nextNode[0];

                while (current->childlink & 0x02)
                {
                    current = (radix_node*)current->nextNode[1];
                }

                if (current->nextNode[1] != NULL)
                {
                    traverse_node = (rn_leaf*)current->nextNode[1];
                    flag = 1;

                    Ipv6GetPrefix((in6_addr* )key,
                                  &prefix,
                                  traverse_node->keyPrefixLen);

                    if (traverse_node->rn_flags == RNF_ACTIVE)
                    {
                        if (CMP_ADDR6(prefix,
                           *(in6_addr*)GetValue((void*)traverse_node)) == 0)
                        {
                            return  traverse_node;
                        }
                    }
                    break;
                }
                else
                {
                    if (!(current->childlink & 0x01))
                    {
                        if (current->nextNode[0] != NULL)
                        {
                            traverse_node = (rn_leaf*)current->nextNode[0];
                            flag = 1;

                            if (traverse_node->rn_flags == RNF_ACTIVE)
                            {
                                Ipv6GetPrefix((in6_addr* )key,
                                               &prefix,
                                               traverse_node->keyPrefixLen);

                                if (CMP_ADDR6(prefix,
                                *(in6_addr*)GetValue((void*)traverse_node))
                                                                        == 0)
                                {
                                    return traverse_node;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            else if (!(current->childlink & 0x01))
            {
                if (current->nextNode[0] == NULL)
                {
                     while(current->parent != NULL &&
                         current->parent->nextNode[1] != current)
                     {
                        current = current->parent;
                     }
                     if(current->parent != NULL &&
                         current->parent->nextNode[1] == current)
                     {
                        current = current->parent;
                     }
                }
                else if(current->nextNode[0] != NULL)
                {
                    traverse_node = (rn_leaf*)current->nextNode[0];
                    flag = 1;
                    if (traverse_node->rn_flags == RNF_ACTIVE)
                    {
                        Ipv6GetPrefix((in6_addr* )key,
                                     &prefix,
                                     traverse_node->keyPrefixLen);
                        if (CMP_ADDR6(prefix,
                            *(in6_addr*)GetValue((void*)traverse_node)) == 0)
                        {
                            return(traverse_node);
                        }
                    }
                        break;
                }
           }
        }
    }

//This code traverses the whole tree towards the left to search for the
//leftmost leaf so that this leaf can act as the terminating node to search
//for the best prefix match algorithm

    flag = 0;

    while(!flag)
    {
        while (radixNode->childlink & 0x01)
        {
            radixNode = (radix_node*)radixNode->nextNode[0];
        }

        if (radixNode->nextNode[0] != NULL)
        {
            flag = 1;
            leaf_node = (rn_leaf*)radixNode->nextNode[0];
            break;
        }
        else if (radixNode->nextNode[0] == NULL)
        {
            if (radixNode->childlink & 0x02)
            {
               radixNode = (radix_node*)radixNode->nextNode[1];
            }
            else if (radixNode->nextNode[1] != NULL)
            {
                leaf_node = (rn_leaf*)radixNode->nextNode[1];
                flag = 1;
                break;
            }
        }
    }

//If the node at which the search is currently is the required node then
//we compare the two nodes at this point and check if the two nodes match


    Ipv6GetPrefix((in6_addr*)key, &prefix, traverse_node->keyPrefixLen);

    if(traverse_node->rn_flags == RNF_ACTIVE)
    {
      if (CMP_ADDR6(prefix, *(in6_addr*)GetValue((void*)traverse_node)) == 0)
      {
        return traverse_node;
      }
    }


//This is the basic code for the best prefix match,this code traverses the
//wholeRadix Trie towards the left and at every leaf using Ipv6GetPrefix
//function masks the key for the number of bits equal to the prefix length of
//the key in the leaf node


    while (traverse_node != leaf_node)
    {
        flag = 0;
        newnode = traverse_node->parent;

        if (newnode->nextNode[1] == traverse_node)
        {
            if (newnode->nextNode[0] == NULL)
            {
                 if (newnode->parent->nextNode[1] == newnode
                     && newnode->parent != NULL)
                 {
                    radixNode = newnode->parent;
                 }
                 else if (newnode->parent->nextNode[0] == newnode
                     && newnode->parent != NULL)
                 {
                      radixNode = newnode->parent;
                      while(radixNode->parent->nextNode[1] != radixNode
                          && radixNode->parent != NULL)
                      {
                          radixNode = radixNode->parent;
                      }
                      if(radixNode->parent->nextNode[1] == radixNode
                          && radixNode->parent != NULL)
                      {
                          radixNode = radixNode->parent;
                      }
                 }
            }
            else if (newnode->nextNode[0] != NULL)
            {
                if (!(newnode->childlink & 0x01))
                {
                    traverse_node = (rn_leaf*)newnode->nextNode[0];
                    flag = 1;
                    if(traverse_node->rn_flags == RNF_ACTIVE)
                    {
                        Ipv6GetPrefix(
                                (in6_addr* )key,
                                &prefix,
                                traverse_node->keyPrefixLen);

                        if(DEBUG_IPV6)
                        {
                            char addressStr[MAX_ADDRESS_STRING_LENGTH];
                            IO_ConvertIpAddressToString(&prefix, addressStr);
                            printf("\n%20s\t\n",addressStr);
                        }

                        if (CMP_ADDR6(prefix,
                                *(in6_addr*)GetValue((void*)traverse_node))
                                                                        == 0)
                        {
                            return traverse_node;
                        }
                    }
                    continue;
                 }
                 radixNode = newnode;
            }
        }
        else if (newnode->nextNode[0] == traverse_node)
        {
            flag = 0;
            if (newnode->parent->nextNode[1]==newnode
                && newnode->parent != NULL)
            {
                radixNode = newnode->parent;
            }
            else if (newnode->parent->nextNode[0] == newnode
                && newnode->parent != NULL)
            {
                radixNode = newnode->parent;
                while(radixNode->parent->nextNode[1] != radixNode
                    && radixNode->parent != NULL)
                {
                    radixNode = radixNode->parent;
                }
                if(radixNode->parent->nextNode[1] == radixNode
                    && radixNode->parent != NULL)
                {
                    radixNode = radixNode->parent;
                }
            }
        }

        while (!flag)
        {
            if (radixNode->childlink & 0x01)
            {
                radixNode = (radix_node*)radixNode->nextNode[0];

                while (radixNode->childlink & 0x02)
                {
                    radixNode = (radix_node*)radixNode->nextNode[1];
                }
                if (radixNode->nextNode[1] != NULL)
                {
                    traverse_node = (rn_leaf*)radixNode->nextNode[1];
                    flag = 1;
                    if(traverse_node->rn_flags == RNF_ACTIVE)
                    {
                        Ipv6GetPrefix(
                            (in6_addr* )key,
                            &prefix,
                            traverse_node->keyPrefixLen);

                        if (CMP_ADDR6(prefix,
                            *(in6_addr*)GetValue((void*)traverse_node)) == 0)
                        {
                            return traverse_node;
                        }
                    }
                    break;
                }
                else if (radixNode->nextNode[1] == NULL)
                {
                    if (!(radixNode->childlink & 0x01))
                    {
                        if (radixNode->nextNode[0]!=NULL)
                        {
                            traverse_node = (rn_leaf*)radixNode->nextNode[0];
                            flag = 1;
                            if(traverse_node->rn_flags == RNF_ACTIVE)
                            {
                                Ipv6GetPrefix(
                                    (in6_addr* )key,
                                    &prefix,
                                    traverse_node->keyPrefixLen);

                                if (CMP_ADDR6(prefix,
                                *(in6_addr*)GetValue((void*)traverse_node))
                                                                        == 0)
                                {
                                    return traverse_node;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            else if (!(radixNode->childlink & 0x01))
            {
                if (radixNode->nextNode[0] == NULL)
                {
                    while(radixNode->parent->nextNode[1] != radixNode
                        && radixNode->parent != NULL)
                    {
                        radixNode = radixNode->parent;
                    }
                    if(radixNode->parent->nextNode[1] == radixNode
                        && radixNode->parent != NULL)
                    {
                        radixNode = radixNode->parent;
                    }
                }
                else if(radixNode->nextNode != NULL)
                {
                    traverse_node = (rn_leaf*)radixNode->nextNode[0];
                    flag = 1;
                    if(traverse_node->rn_flags == RNF_ACTIVE)
                    {
                        Ipv6GetPrefix(
                            (in6_addr* )key,
                            &prefix,
                            traverse_node->keyPrefixLen);

                        if (CMP_ADDR6(prefix,
                            *(in6_addr*)GetValue((void*)traverse_node)) == 0)
                        {
                            return traverse_node;
                        }
                    }
                    break;
                }
            }
        }
    }
    return NULL;
}

//---------------------------------------------------------------------------
// FUNCTION             : rn_match
// PURPOSE             :: It matches a particular key in the specified tree
//                      : if found returns data else returns null.
// PARAMETERS          ::
// + keyNode            : void* keyNode: Void pointer to radix key node.
// + tree               : radix_node_head* tree: pointer to radix tree head.
// RETURN               : void *
//---------------------------------------------------------------------------
void*
rn_match(
    void* keyNode,
    radix_node_head* tree,
    Node* node)
{
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    int index = 0;
    radix_node* current;
    int childBit;
    unsigned char bitOff[16];
    int lastPrefixLen = 0;
    int remainderBits = 0;
    rn_leaf* best_match_leaf;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;

    if (tree->maxKeyLen <= 32)
    {
        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[0] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[0] = 7;
            bitOff[1] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = 7;
            bitOff[3] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 64)
    {
        for (index = 0; index < 4; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[4] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[4] = 7;
            bitOff[5] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = 7;
            bitOff[7] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 96)
    {
        for (index = 0; index < 8; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 64 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[8] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[8] = 7;
            bitOff[9] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = 7;
            bitOff[11] = (UInt8)remainderBits;
        }
    }
    else
    {
        for (index = 0; index < 12; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 96 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[12] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[12] = 7;
            bitOff[13] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = 7;
            bitOff[15] = (UInt8)remainderBits;
        }
    }

    key = tree->getValueFnPtr(keyNode);

    for (index = 0; index < 16; index++)
    {
        mask[index] = 0x01 << bitOff[index];
    }

    index = 0;

    // Search for the item with key `key'.
    current = tree->root;
    for (;;)
    {
        // Traverse left or right branch, depending on the current bit.
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*) current->nextNode[childBit];

        // Move to the next bit.
        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }
    }

    if (current->nextNode[childBit])
    {
        BOOL matchFound = FALSE;
        in6_addr destPrefix = {{{0, 0, 0, 0}}};
        rn_leaf* destLeaf = NULL;

        destLeaf = (rn_leaf* )current->nextNode[childBit];

        tempKey = tree->getValueFnPtr(current->nextNode[childBit]);

        if (CMP_ADDR6(*(in6_addr* )key, *(in6_addr* )tempKey) == 0)
        {
            matchFound = TRUE;
        }
        else
        {
            Ipv6GetPrefix(
                (in6_addr* )key,
                &destPrefix,
                destLeaf->keyPrefixLen);
        }

        if (matchFound || CMP_ADDR6(destPrefix, *(in6_addr* )tempKey) == 0)
        {
            if (((rn_leaf *)current->nextNode[childBit])->rn_flags
                 == RNF_IGNORE)
            {
                // routes with flag RNF_IGNORE is considered as deleted
                if(ipv6->defaultRouteFlag == TRUE)
                {
                    best_match_leaf =
                        rn_bestPrefixMatch(current,childBit,key,tree);
                    return (best_match_leaf);
                }
                return NULL;
            }
            return current->nextNode[childBit];
        }
        else if(matchFound != TRUE && ipv6->defaultRouteFlag == TRUE)
        {
            best_match_leaf = rn_bestPrefixMatch(current,childBit,key,tree);
            return (best_match_leaf);
        }
    }
    else if(!(current->nextNode[childBit]) && ipv6->defaultRouteFlag == TRUE)
    {
        best_match_leaf = rn_bestPrefixMatch(current, childBit, key, tree);
        return (best_match_leaf);
    }
    return NULL;
}


//---------------------------------------------------------------------------
// FUNCTION             : rn_insert
// PURPOSE             :: Inserts an item into the radix search tree
//                        pointed to by tree , according the the value
//                        its key.  The key of an item in the radix
//                        search trie must be unique among items in the
//                        tree.  If an item with the same key already exists
//                        in the tree, a pointer to that item is returned.
//                        Otherwise, NULL is returned, indicating insertion
//                        was successful.
// PARAMETERS          ::
// + keyNode            : void* keyNode: Void pointer to radix key node
// + tree               : radix_node_head* tree: Pointer to radix tree head.
// RETURN               : void *
//---------------------------------------------------------------------------
void* rn_insert(Node* node, void* keyNode, radix_node_head* tree)
{
    radix_node* root;
    radix_node* current;
    radix_node* tempNode;
    int index = 0;
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    unsigned char stopMask = 0;

    int childBit = 0;
    unsigned char bitOff[16] = {0};

    int lastPrefixLen = 0;
    int remainderBits = 0;

    if (DEBUG_IPV6)
    {
        rn_leaf* temp = (rn_leaf*)keyNode;
        printf("keyPrefixLen = %u\n", temp->keyPrefixLen);
    }

    if (tree->maxKeyLen <= 32)
    {
        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[0] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[0] = 7;
            bitOff[1] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = 7;
            bitOff[3] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 64)
    {
        for (index = 0; index < 4; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[4] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[4] = 7;
            bitOff[5] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = 7;
            bitOff[7] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 96)
    {
        for (index = 0; index < 8; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 64 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[8] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[8] = 7;
            bitOff[9] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = 7;
            bitOff[11] = (UInt8)remainderBits;
        }
    }
    else
    {
        for (index = 0; index < 12; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 96 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[12] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[12] = 7;
            bitOff[13] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = 7;
            bitOff[15] = (UInt8)remainderBits;
        }
    }

    root = tree->root;
    tree->root->parent = NULL;
    current = root;
    key = tree->getValueFnPtr(keyNode);

    for (index = 0; index < 16; index++)
    {
        mask[index] = 0x01 << bitOff[index];
    }

    index = 0;
    current = root;
    while (current && index < 16)
    {
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (DEBUG_IPV6)
        {
                printf("index %d Mask %x key %x cb = %d\n",
                    index, mask[index], key[index], childBit);
        }

        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*)current->nextNode[childBit];

        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }
     }// end of finding position.

    // Check for duplicate Key.
    if (current->nextNode[childBit])
    {
        void* temp2Node = current->nextNode[childBit];
        tempKey = tree->getValueFnPtr(temp2Node);

        if (CMP_ADDR6(*(in6_addr*)tempKey, *(in6_addr*)key) == 0)
        {
            // revive virtually deleted route
            if (((rn_leaf *)temp2Node)->rn_flags == RNF_IGNORE)
            {
                ((rn_leaf*)temp2Node)->keyPrefixLen =
                                          ((rn_leaf*)keyNode)->keyPrefixLen;
                // Here "equal to" operator is overloaded for link layer
                // address assignment.
                ((rn_leaf*)temp2Node)->linkLayerAddr =
                                          ((rn_leaf*)keyNode)->linkLayerAddr;
                ((rn_leaf*)temp2Node)->flags =
                                          ((rn_leaf*)keyNode)->flags;
                ((rn_leaf*)temp2Node)->type =
                                          ((rn_leaf*)keyNode)->type;
                ((rn_leaf*)temp2Node)->rn_option =
                                          ((rn_leaf*)keyNode)->rn_option;
                ((rn_leaf*)temp2Node)->ln_state =
                                          ((rn_leaf*)keyNode)->ln_state;
                ((rn_leaf*)temp2Node)->expire =
                                          ((rn_leaf*)keyNode)->expire;
                memcpy(&((rn_leaf*)temp2Node)->gateway,
                       &((rn_leaf*)keyNode)->gateway,
                       sizeof(in6_addr));

                ((rn_leaf*)temp2Node)->parent =
                                          ((rn_leaf*)keyNode)->parent;

                ((rn_leaf *)temp2Node)->rn_flags = RNF_ACTIVE;
            }
            ((rn_leaf*)current->nextNode[childBit])->parent = current;
            return current->nextNode[childBit];
        }
        // If not duplicate insert the key in proper place.
        stopMask = tempKey[index] ^ key[index];

        tempNode = radixNodeAlloc();
        tree->totalNodes++;

        current->childlink = current->childlink | (childBit + 1);
        current->nextNode[childBit] = (void*)tempNode;
        tempNode->parent = current;
        for (;;)
        {
            current = tempNode;
            mask[index] >>= 1;
            if (mask[index] == 0)
            {
                index++;
                stopMask = tempKey[index] ^ key[index];
            }
            else
            {
                bitOff[index]--;
            }
            childBit = (key[index] & mask[index]) >> bitOff[index];

            if (mask[index] & stopMask)
            {
                break;
            }
            tempNode = radixNodeAlloc();
            tree->totalNodes++;
            current->nextNode[childBit] = (void*)tempNode;
            tempNode->parent=current;
            current->nextNode[!childBit] = NULL;
            current->childlink = (childBit + 1);
        }
            current->nextNode[childBit] = keyNode;
            ((rn_leaf*)keyNode)->parent=current;
            tree->totalNodes++;
            current->nextNode[!childBit] = temp2Node;
            ((rn_leaf*)temp2Node)->parent=current;
            current->childlink = 0;
    }
    else // No leaf or data is present
    {
        current->nextNode[childBit] = keyNode;
        tree->totalNodes++;
        ((rn_leaf*)keyNode)->parent=current;
    }
    ((rn_leaf *)current->nextNode[childBit])->rn_flags = RNF_ACTIVE;

    return current->nextNode[childBit];
} // end of function.




//---------------------------------------------------------------------------
// FUNCTION             : rst_find
// PURPOSE             :: It finds a particular key in the specified tree
//                      : if found returns data else returns null.
// PARAMETERS          ::
// + keyNode            : void* keyNode: Void pointer to radix key node.
// + tree               : radix_node_head* tree: Pointer to radix tree head.
// RETURN               : void *
//---------------------------------------------------------------------------
void* rst_find(void* keyNode, radix_node_head* tree)
{
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    int index = 0;
    radix_node* current;

    int childBit;
    int bitOff[4];

    if (tree->maxKeyLen <= 32)
    {
        bitOff[0] = tree->maxKeyLen - 1;
        bitOff[1] = bitOff[2] = bitOff[3] = 0;
    }
    else if (tree->maxKeyLen <= 64)
    {
        bitOff[0] = 31;
        bitOff[1] = tree->maxKeyLen - 32 - 1;;
        bitOff[2] = bitOff[3] = 0;
    }
    else if (tree->maxKeyLen <= 96)
    {
        bitOff[0] = bitOff[1] = 31;
        bitOff[2] = tree->maxKeyLen - 64 - 1;
        bitOff[3] = 0;
    }
    else
    {
       bitOff[0] = bitOff[1] = bitOff[2] = 31;
       bitOff[3] = tree->maxKeyLen - 96 - 1;
    }

    key = tree->getValueFnPtr(keyNode);
    mask[0] = (unsigned char) (0x01 << bitOff[0]);
    mask[1] = (unsigned char) (0x01 << bitOff[1]);
    mask[2] = (unsigned char) (0x01 << bitOff[2]);
    mask[3] = (unsigned char) (0x01 << bitOff[3]);

    // Search for the item with key `key'.
    current = tree->root;
    for (;;)
    {
        // Traverse left or right branch, depending on the current bit.
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*)current->nextNode[childBit];

        // Move to the next bit.
        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }
    }

    if (current->nextNode[childBit])
    {
        tempKey = tree->getValueFnPtr(current->nextNode[childBit]);
        if (tempKey[0] == key[0] &&
            tempKey[1] == key[1] &&
            tempKey[2] == key[2] &&
            tempKey[3] == key[3])
        {
            // route with flag RNF_IGNORE is considered as virtually deleted
            if (((rn_leaf *)current->nextNode[childBit])->rn_flags
                 == RNF_IGNORE)
            {
                return NULL;
            }
            else
            {
                return current->nextNode[childBit];
            }
        }
    }
    return NULL;
}

//---------------------------------------------------------------------------
// FUNCTION             : rst_delete
// PURPOSE             :: rst_delete() - Delete the first item found in
//                      : the radix search trie with the same key as the
//                      : item pointed to by `key_item'.  Returns a pointer
//                      : to the deleted item, and NULL if no item was found.
// PARAMETERS          ::
// + keyNode            : void* keyNode:Void pointer to radix key node
// + tree               : radix_node_head* tree: Pointer to radix tree.
// RETURN               : void *
//---------------------------------------------------------------------------
void* rst_delete(void* keyNode, radix_node_head* tree)
{
    radix_node **stack;
    int *path_info;
    int top = 0;
    void *y;
    void *return_item = NULL;
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    int index = 0;
    radix_node* current;

    int childBit;
    int bitOff[4];

    if (tree->maxKeyLen <= 32)
    {
        bitOff[0] = tree->maxKeyLen - 1;
        bitOff[1] = bitOff[2] = bitOff[3] = 0;
    }
    else if (tree->maxKeyLen <= 64)
    {
        bitOff[0] = 31;
        bitOff[1] = tree->maxKeyLen - 32 - 1;
        bitOff[2] = bitOff[3] = 0;
    }
    else if (tree->maxKeyLen <= 96)
    {
        bitOff[0] = bitOff[1] = 31;
        bitOff[2] = tree->maxKeyLen - 64 - 1;
        bitOff[3] = 0;
    }
    else
    {
       bitOff[0] = bitOff[1] = bitOff[2] = 31;
       bitOff[3] = tree->maxKeyLen - 96 - 1;
    }

    key = tree->getValueFnPtr(keyNode);
    mask[0] = (unsigned char) (0x01 << bitOff[0]);
    mask[1] = (unsigned char) (0x01 << bitOff[1]);
    mask[2] = (unsigned char) (0x01 << bitOff[2]);
    mask[3] = (unsigned char) (0x01 << bitOff[3]);

    // Search for the item with key `key'.
    current = tree->root;
    stack = tree->stack;
    path_info = tree->path_info;
    top = 0;
    for (;;)
    {
        // Traverse left or right branch, depending on the current bit.
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*)current->nextNode[childBit];
        stack[top] = current;
        path_info[top] = childBit;
        top++;
        // Move to the next bit.
        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }

    }

    // The delete operation fails if the tree contains no items,
    // or no matching item was found.
    if (current->nextNode[childBit])
    {
        tempKey = tree->getValueFnPtr(current->nextNode[childBit]);
        if (tempKey[0] == key[0] &&
            tempKey[1] == key[1] &&
            tempKey[2] == key[2] &&
            tempKey[3] == key[3])
        {
            return_item = current->nextNode[childBit];
        }
        else
        {
            return NULL;
        }
    }
    // Currently current->nextNode[childBit] points to the item which
    // is to be removed.  After removing the deleted item, the parent
    // node must also be deleted if its other child pointer is NULL.
    // This deletion can propagate up to the next level.

    top--;
    for (;;)
    {
        if (top == 0)
        {  // Special case: deleting a child of the root node.
            current->nextNode[childBit] = NULL;
            // Clear bit childBit.
            current->childlink = current->childlink & !(childBit + 1);
            return return_item;
        }
        if (current->nextNode[!childBit])
        {
            break;
        }
        MEM_free(current);
        current = stack[--top];
        childBit = path_info[top];
    }
    // For the current node, "current", the child pointer
    // current->nextNode[childBit] is not NULL.If current->nextNode[!childBit]
    // points to a node, we set current->nextNode[childBit] to NULL.
    // Otherwise if current->nextNode[!childBit]  points to an item,
    // we keep a pointer to the item, and continue to delete parent nodes
    // if their other child pointer is NULL.

    if (current->childlink & (!childBit + 1))
    {
        // current->nextNode[!childBit]
        current->nextNode[childBit] = NULL;
    }
    else
    {  // current->nextNode[!childBit] points to an item.
       // Delete current, and parent nodes for which the other child
       // pointer is  NULL.
        y =  current->nextNode[!childBit];
        do {
            MEM_free(current);
            current = stack[--top];
            childBit = path_info[top];
            if (current->nextNode[!childBit])
            {
                break;
            }
        } while (top != 0);

        // For the current node, current, current->nextNode[!childBit] is
        // not NULL.  We assign item y to current->nextNode[childBit].
        current->nextNode[childBit] = y;
    }
    // Clear bit childBit.
    current->childlink = current->childlink & ~(childBit + 1);
    return return_item;
}


//---------------------------------------------------------------------------
// FUNCTION             : rn_delete
// PURPOSE             :: Delete the first item found in
//                        the radix search tree with the same key as the
//                        item pointed to by `key_item'.  Returns a pointer
//                        to the deleted item, and NULL if no item was found.
//                        Items are virtually deleted by setting its flag as
//                        RNF_IGNORE.
// PARAMETERS          ::
// + keyNode            : void* keyNode:Void pointer to radix key node
// + tree               : radix_node_head* tree: Pointer to radix tree.
// RETURN               : void *
//---------------------------------------------------------------------------
void* rn_delete(void* keyNode, radix_node_head* tree)
{
    radix_node **stack;
    int *path_info;
    int top = 0;
    unsigned char* key;
    unsigned char* tempKey;
    unsigned char mask[16];
    int index = 0;
    radix_node* current;
    int childBit;
    //int bitOff[4];
    unsigned char bitOff[16];

    int lastPrefixLen = 0;
    int remainderBits = 0;

    if (tree->maxKeyLen <= 32)
    {
        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[0] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[0] = 7;
            bitOff[1] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[0] = 7;
            bitOff[1] = 7;
            bitOff[2] = 7;
            bitOff[3] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 64)
    {
        for (index = 0; index < 4; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 32 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[4] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[4] = 7;
            bitOff[5] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[4] = 7;
            bitOff[5] = 7;
            bitOff[6] = 7;
            bitOff[7] = (UInt8)remainderBits;
        }
    }
    else if (tree->maxKeyLen <= 96)
    {
        for (index = 0; index < 8; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 64 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[8] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[8] = 7;
            bitOff[9] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[8] = 7;
            bitOff[9] = 7;
            bitOff[10] = 7;
            bitOff[11] = (UInt8)remainderBits;
        }
    }
    else
    {
        for (index = 0; index < 12; index++)
        {
            bitOff[index] = 7;
        }

        lastPrefixLen = tree->maxKeyLen - 96 - 1;
        remainderBits = lastPrefixLen % 8;

        if (lastPrefixLen < 8)
        {
            bitOff[12] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 16)
        {
            bitOff[12] = 7;
            bitOff[13] = (UInt8)remainderBits;
        }
        else if (lastPrefixLen < 24)
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = (UInt8)remainderBits;
        }
        else
        {
            bitOff[12] = 7;
            bitOff[13] = 7;
            bitOff[14] = 7;
            bitOff[15] = (UInt8)remainderBits;
        }
    }
    key = tree->getValueFnPtr(keyNode);
    for (index = 0; index < 16; index++)
    {
        mask[index] = 0x01 << bitOff[index];
    }

    index = 0;

    // Search for the item with key `key'.
    current = tree->root;
    stack = tree->stack;
    path_info = tree->path_info;
    top = 0;
    for (;;)
    {
        // Traverse left or right branch, depending on the current bit.
        childBit = (key[index] & mask[index]) >> (bitOff[index]);
        if (!(current->childlink & (childBit + 1)))
        {
            break;
        }
        current = (radix_node*)current->nextNode[childBit];
        stack[top] = current;
        path_info[top] = childBit;
        top++;
        // Move to the next bit.
        mask[index] >>= 1;
        if (mask[index] == 0)
        {
            index++;
        }
        else
        {
            bitOff[index]--;
        }
    }
    // The delete operation fails if the tree contains no items,
    // or no matching item was found.
    if (current->nextNode[childBit])
    {
        tempKey = tree->getValueFnPtr(current->nextNode[childBit]);

        if (CMP_ADDR6(*(in6_addr*)tempKey, *(in6_addr*)key) == 0)
        {
            if (((rn_leaf *)current->nextNode[childBit])->rn_flags
                 == RNF_IGNORE)
            {
                return NULL;
            }
            else
            {
                ((rn_leaf *)current->nextNode[childBit])->rn_flags =
                                                                RNF_IGNORE;

                return current->nextNode[childBit];
            }
        }
        else
        {
            return NULL;
        }
    }
    return NULL;
}

//---------------------------------------------------------------------------
// FUNCTION             : PrintRadixTableRow
// PURPOSE             :: Static function to print the radix table row.
// PARAMETERS          ::
// +  key              :: unsigned mint*: Pointer to key value.
// +  gway             :: unsigned int*: Pointer Gateway information flag.
// +  ll               :: NodeAddress: LinkLayer address.
// +  index            :: int: Interface index.
// +  type             :: int: Type of route
// +  flags            :: int: flags for route.
// + printNextHopInfoFlag: int:prints next hop information.
// RETURN               : None
//---------------------------------------------------------------------------
static void
PrintRadixTableRow(
    unsigned int* key,
    unsigned int* gway,
    MacHWAddress& ll,
    int index,
    int type,
    int flags,
    int printNextHopInfoFlag,
    UInt32 prefixLen)
{
    in6_addr tAddr;
    char addressStr[MAX_ADDRESS_STRING_LENGTH];

    tAddr.s6_addr32[0] = key[0];
    tAddr.s6_addr32[1] = key[1];
    tAddr.s6_addr32[2] = key[2];
    tAddr.s6_addr32[3] = key[3];

    if (type == AUTOCONF)
    {
        printf("AutoConf\t");
    }
    else
    {
        printf("Config. \t");
    }

    IO_ConvertIpAddressToString(&tAddr, addressStr);

    printf("%20s\t%d\t",addressStr,index);
    MAC_PrintHWAddr(&ll);
    printf("\t");

    if (!printNextHopInfoFlag)
    {
        printf("\n");
        return;
    }
    if (flags == RT_LOCAL)
    {
        printf("Local Connection.");
    }
    else
    {
        tAddr.s6_addr32[0] = gway[0];
        tAddr.s6_addr32[1] = gway[1];
        tAddr.s6_addr32[2] = gway[2];
        tAddr.s6_addr32[3] = gway[3];
        IO_ConvertIpAddressToString(&tAddr, addressStr);
        printf("%s",addressStr);
    }

    if (DEBUG_IPV6)
    {
        printf("\t\t%d\n", prefixLen);
    }

    printf("\n");
}

//---------------------------------------------------------------------------
// FUNCTION             : radix_traversal
// PURPOSE             :: Function to print the radix tree in-orderly.
// PARAMETERS          ::
// + radixNode          : radix_node* radixNode: Void pointer to radix node.
// + printNextHopInfoFlag: int :: prints next hop information flag.
// RETURN               : None
//---------------------------------------------------------------------------
void radix_traversal(Node* node, radix_node* radixNode, int printNextHopInfoFlag)
{
    if (radixNode != NULL)
     {
        //Visit Left.
        if (radixNode->childlink & 0x01)
        {
            radix_traversal(node,
                (radix_node*)radixNode->nextNode[0],
                printNextHopInfoFlag);
        }
        // Print the Information.
        if (!(radixNode->childlink & 0x01) && radixNode->nextNode[0])
        {
            if (((rn_leaf *)radixNode->nextNode[0])->rn_flags != RNF_IGNORE)
            {
                unsigned int* k;
                MacHWAddress ll;
                int flags;
                int type;
                int index;

                k = (unsigned int*)GetValue(radixNode->nextNode[0]);
                ll = GetLinkLayerValue(radixNode->nextNode[0]);
                flags = GetFlags(radixNode->nextNode[0]);
                index = GetIndex(radixNode->nextNode[0]);
                type = GetType(radixNode->nextNode[0]);

                if (flags == RT_LOCAL)
                {
                    PrintRadixTableRow(k, (unsigned int*)NULL, ll,
                        index, type, flags, printNextHopInfoFlag,
                        ((rn_leaf*)radixNode->nextNode[0])->keyPrefixLen);

                }
                else
                {
                    unsigned int* gtway;
                    gtway = (unsigned int*)GetGateway(radixNode->nextNode[0]);
                    PrintRadixTableRow(k, gtway, ll,
                        index, type, flags, printNextHopInfoFlag,
                        ((rn_leaf*)radixNode->nextNode[0])->keyPrefixLen);
                }
            }
        }
        if (!(radixNode->childlink & 0x02) && radixNode->nextNode[1])
        {
            if (((rn_leaf *)radixNode->nextNode[1])->rn_flags != RNF_IGNORE)
            {
                unsigned int* k;
                MacHWAddress ll;
                int flags;
                int type;
                int index;
                k = (unsigned int*)GetValue(radixNode->nextNode[1]);
                ll = GetLinkLayerValue(radixNode->nextNode[1]);
                flags = GetFlags(radixNode->nextNode[1]);
                index = GetIndex(radixNode->nextNode[1]);
                type = GetType(radixNode->nextNode[1]);

                if (flags == RT_LOCAL)
                {
                    PrintRadixTableRow(k, (unsigned int*)NULL, ll,
                        index, type, flags, printNextHopInfoFlag,
                        ((rn_leaf*)radixNode->nextNode[1])->keyPrefixLen);
                }
                else
                {
                    unsigned int* gtway;
                    gtway = (unsigned int*)GetGateway(radixNode->nextNode[1]);
                    PrintRadixTableRow(k, gtway, ll,
                        index, type, flags, printNextHopInfoFlag,
                        ((rn_leaf*)radixNode->nextNode[1])->keyPrefixLen);
                }
            }
        }//End of Printing Information.
        //Visit Right.
        if (radixNode->childlink & 0x02)
        {
            radix_traversal(node,
                (radix_node*)radixNode->nextNode[1],
                printNextHopInfoFlag);
        }
     }
}//End of IN-Order traversal.

//---------------------------------------------------------------------------
// FUNCTION             : radix_empty
// PURPOSE             :: Function to print empty radix tree.
// PARAMETERS          ::
// + radixNode          : radix_node* radixNode: Void pointer to radix node.
// + nrpType            : NetworkRoutingProtocolType :: Routing protocol type.
// RETURN               : None
//---------------------------------------------------------------------------
void radix_empty(radix_node* radixNode, NetworkRoutingProtocolType nrpType)
{
     if (radixNode != NULL)
     {
        // Check the left node.
        if (radixNode->childlink & 0x01)
        {
            radix_empty(
                (radix_node*)radixNode->nextNode[0],
                nrpType);
        }
        // Check the information
        if (!(radixNode->childlink & 0x01) && radixNode->nextNode[0])
        {
            if (((rn_leaf *)radixNode->nextNode[0])->rn_flags != RNF_IGNORE)
            {
                unsigned int* k;
                MacHWAddress ll;
                int flags;
                int type;
                int index;

                k = (unsigned int*)GetValue(radixNode->nextNode[0]);
                ll = GetLinkLayerValue(radixNode->nextNode[0]);
                flags = GetFlags(radixNode->nextNode[0]);
                index = GetIndex(radixNode->nextNode[0]);
                type = GetType(radixNode->nextNode[0]);

                // Compare with the type
                if (type == (int)nrpType)
                {
                    ((rn_leaf *)radixNode->nextNode[0])->rn_flags = RNF_IGNORE;
                }

            }
        }
        if (!(radixNode->childlink & 0x02) && radixNode->nextNode[1])
        {
            if (((rn_leaf *)radixNode->nextNode[1])->rn_flags != RNF_IGNORE)
            {
                unsigned int* k;
                MacHWAddress ll;
                int flags;
                int type;
                int index;
                k = (unsigned int*)GetValue(radixNode->nextNode[1]);
                ll = GetLinkLayerValue(radixNode->nextNode[1]);
                flags = GetFlags(radixNode->nextNode[1]);
                index = GetIndex(radixNode->nextNode[1]);
                type = GetType(radixNode->nextNode[1]);

                // Compare the type
                if (type == (int)nrpType)
                {
                    ((rn_leaf *)radixNode->nextNode[0])->rn_flags = RNF_IGNORE;
                }
            }
        }//End if
        //check the right node.
        if (radixNode->childlink & 0x02)
        {
            radix_empty(
                (radix_node*)radixNode->nextNode[1],
                nrpType);
        }
     }
}//End


// /**
// FUNCTION   :: rn_hashIndex_reverse_lookup
// LAYER      :: NETWORK
// PURPOSE    :: Get hash Index for linkLayerAddress.
// PARAMETERS ::
//  +linkLayerAddress   : MacHWAddress*   : Link Layer address.
// RETURN     :: int : hash index.
// **/
int rn_hashIndex_reverse_lookup(MacHWAddress* linkLayerAddress)
{
    //the logic of creating hash should be replaced by some efficient hashing
    // machanism like CRC hashing
    NodeAddress nodeId;
    if (linkLayerAddress->hwLength == 6)
{
        memcpy(&nodeId, &(linkLayerAddress->byte[0]), sizeof(NodeAddress));
        return nodeId % 100;
    }
    else
    {
        return linkLayerAddress->byte[0] % 100;
    }
}


// /**
// FUNCTION   :: radix_GetNextHopFromLinkLayerAddress
// LAYER      :: NETWORK
// PURPOSE    :: Get Ipv6 Next Hop Address from Link Layer Address.
// PARAMETERS ::
//  +node           : Node*         : Pointer to Node.
//  +nextHopAddr    : in6_addr*     : Pinter to Next Hop Address.
//  +llAddr         : NodeAddress   : Link Layer address.
// RETURN     :: void : NULL.
// **/
BOOL
radix_GetNextHopFromLinkLayerAddress(
    Node* node,
    in6_addr* nextHopAddr,
    MacHWAddress* linkLayerAddr)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    rn_rev_ndplookup* ndpEntry = NULL;

    if (ipv6->reverse_ndp_cache[rn_hashIndex_reverse_lookup(linkLayerAddr)] == NULL)
    {
        return FALSE;
    }

    ndpEntry = ipv6->reverse_ndp_cache[rn_hashIndex_reverse_lookup(linkLayerAddr)];

    while (ndpEntry)
    {
        if (*linkLayerAddr == ndpEntry->ndp_cache_entry->linkLayerAddr)
        {
            break;
        }
        ndpEntry = ndpEntry->next;
    }
    if (ndpEntry)
    {
        unsigned int* key;

        key = (unsigned int*)GetValue(ndpEntry->ndp_cache_entry);

        nextHopAddr->s6_addr32[0] = key[0];
        nextHopAddr->s6_addr32[1] = key[1];
        nextHopAddr->s6_addr32[2] = key[2];
        nextHopAddr->s6_addr32[3] = key[3];

        return TRUE;
    }
    return FALSE;
}

void rn_insert_reverse_lookup(Node* node, rn_leaf* route)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;


    int queueIndex = rn_hashIndex_reverse_lookup(&route->linkLayerAddr);

    if (route->linkLayerAddr.hwType == HW_TYPE_UNKNOWN)
    {
        return;
    }

    if (ipv6->reverse_ndp_cache[queueIndex] == NULL)
    {
        ipv6->reverse_ndp_cache[queueIndex] =
            (rn_rev_ndplookup* )MEM_malloc(sizeof(rn_rev_ndplookup));

        ipv6->reverse_ndp_cache[queueIndex]->ndp_cache_entry = route;

        ipv6->reverse_ndp_cache[queueIndex]->next = NULL;
    }
    else
    {
        rn_rev_ndplookup* ndpEntry = ipv6->reverse_ndp_cache[queueIndex];

        while (ndpEntry)
        {
            if (route->linkLayerAddr
                == ndpEntry->ndp_cache_entry->linkLayerAddr)
            {
                break;
            }
            ndpEntry = ndpEntry->next;
        }
        if (!ndpEntry)
        {
            ndpEntry =
                (rn_rev_ndplookup* )MEM_malloc(sizeof(rn_rev_ndplookup));

            ndpEntry->ndp_cache_entry = route;

            ndpEntry->next = ipv6->reverse_ndp_cache[queueIndex];

            ipv6->reverse_ndp_cache[queueIndex] = ndpEntry;
        }
    }
}

void rn_delete_reverse_lookup(Node* node, MacHWAddress& linkLayerAddress)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    if (linkLayerAddress.hwType == HW_TYPE_UNKNOWN)
    {
        return;
    }

    rn_rev_ndplookup* ndpEntry =
        ipv6->reverse_ndp_cache[rn_hashIndex_reverse_lookup(&linkLayerAddress)];

    rn_rev_ndplookup* prevNDPEntry = NULL;

    BOOL firstEntry = TRUE;

    while (ndpEntry)
    {
        if (ndpEntry->ndp_cache_entry->linkLayerAddr == linkLayerAddress)
        {
            if (firstEntry)
            {
                ipv6->reverse_ndp_cache[rn_hashIndex_reverse_lookup(
                    &linkLayerAddress)] = ndpEntry->next;

                firstEntry = FALSE;
            }
            else
            {
                prevNDPEntry->next = ndpEntry->next;
            }

            MEM_free(ndpEntry);

            break;
        }
        firstEntry = FALSE;
        prevNDPEntry = ndpEntry;
        ndpEntry = ndpEntry->next;
    }
}
