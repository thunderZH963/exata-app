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
/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * (1) source code distributions retain this paragraph in its entirety,
 *
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided
 *     with the distribution, and
 *
 * (3) all advertising materials mentioning features or use of this
 *     software display the following acknowledgment:
 *
 *      "This product includes software written and developed
 *       by Brian Adamson and Joe Macker of the Naval Research
 *       Laboratory (NRL)."
 *
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/

#ifndef _MDP_ITEM
#define _MDP_ITEM

// The classes defined here let us build lists of files and directories
// to transmit

#include "mdpFile.h"

class MdpFileItem
{
    friend class MdpFileList;
    friend class MdpFileCache;

    protected:
    // Methods
        MdpFileItem(const char *fullPath);
        virtual ~MdpFileItem();
        void GetFullName(char *buf, int len);

    // Members
        // (TBD) Make these dynamically allocated and managed
        //char        path[MDP_PATH_MAX];
        //char        name[MDP_PATH_MAX];
        char        *path;
        char        *name;
        MdpFileItem *prev, *next;
        UInt32      size;

    // Methods
        virtual bool GetNextFile(char *thePath,
                                 char *theName,
                                 bool reset,
                                 bool updates_only,
                                 clocktype last_time,
                                 clocktype this_time,
                                 clocktype *big_time);
        UInt32 Size() {return size;}
};  // end class MdpFileItem


class MdpDirectoryItem : public MdpFileItem
{
    friend class MdpFileList;

    private:
        MdpDirectoryIterator diterator;  // from "mdpFile.h"

    private:
        MdpDirectoryItem(const char *fullPath);
        ~MdpDirectoryItem();
        bool GetNextFile(char *thePath,
                         char *theName,
                         bool reset,
                         bool updates_only,
                         clocktype last_time,
                         clocktype this_time,
                         clocktype *big_time);
};  // end class MdpDirectoryItem


class MdpFileList
{
    // Methods
    public:
        MdpFileList();
        ~MdpFileList();
        void Destroy();
        MdpFileItem* NewFileItem(const char *path);
        void DeleteFileItem(MdpFileItem *theItem)
        {
            Remove(theItem);
            delete theItem;
        }
        void ResetIterator();
        bool UpdatesOnly() {return updates_only;}
        void SetUpdatesOnly(bool value) {updates_only = value;}
        void InitUpdateTime(clocktype initTime)
        {
            last_time = this_time;
            this_time = big_time = initTime;
        }
        bool GetNextFile(char *path, char *name);
        // (TBD) more routines for organizing items in list??

    private:
    // Members
        class MdpFileItem *head, *tail;
        class MdpFileItem *next;  // for the list's iterator
        bool updates_only;
        //time_t  last_time, this_time, big_time;
        clocktype  last_time, this_time, big_time;
        bool reset_next;

    // Methods
        void Prepend(MdpFileItem *theItem);
        void Append(MdpFileItem *theItem);
        void Remove(MdpFileItem *theItem);
};


// Simple FIFO file caching for receive files
class MdpFileCache
{
    public:
    // Methods
        MdpFileCache();
        ~MdpFileCache();
        void SetCacheSize(UInt32 minCount, UInt32 maxCount,
                          UInt32 maxSize);
        bool CacheFile(const char *thePath);
        void Destroy();

    private:
    // Members
        MdpFileItem *head, *tail;
        UInt32 file_count, byte_count;
        UInt32 count_min, count_max, size_max;

    // Methods
        void PurgeHead();
};

#endif // _MDP_FILE_LIST
