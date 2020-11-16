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


#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "mdpItem.h"

#ifdef MDP_FOR_WINDOWS
#include <windows.h>
#include <direct.h>
#else
// for unix
#include <unistd.h>
//#include <dirent.h>
#endif

/********************************************************************
 * The MdpItem is a helper class for queueing "items" to be served
 * (the client code may use this item for summary state information)
 * The MdpItemList keeps a linked list of generic MdpItems
 */


MdpFileList::MdpFileList()
    : head(NULL), tail(NULL), next(NULL),
      updates_only(0), last_time(0), this_time(0), big_time(0),
      reset_next(true)
{

}

MdpFileList::~MdpFileList()
{
    Destroy();
}

void MdpFileList::Destroy()
{
    next = head;
    while (next)
    {
        head = next->next;
        delete next;
        next = head;
    }
    tail = NULL;
}  // end MdpFileList::Destroy();

// Transmute directories into "DirectoryItems"
MdpFileItem *MdpFileList::NewFileItem(const char* path)
{
    MdpFileItem *theItem = NULL;
    switch (MdpFileGetType(path))
    {
        // We "transmute" FILE_ITEMs into DIR_ITEMs if they are directories
        case MDP_FILE_NORMAL:
            theItem = new MdpFileItem(path);
            break;

        case MDP_FILE_DIRECTORY:
            theItem = new MdpDirectoryItem(path);
            break;

        default:
            // Allow non-existent files for updates only
            // (TBD) Allow non-existent directories?
            if (updates_only)
                theItem = new MdpFileItem(path);
            else
                printf("MdpFileItem: Bad file/directory name!\n");
            break;
    }
    if (theItem) Append(theItem);
    return theItem;
}  // end MdpFileList::NewItem()


void MdpFileList::Prepend(MdpFileItem *theItem)
{
    ASSERT(theItem);
    if (next == head) next = theItem;
    theItem->prev = NULL;
    theItem->next = head;
    if (theItem->next)
        head->prev =  theItem;
    else
        tail = theItem;
    head = theItem;
}  // end MdpServerItemList::Prepend()

void MdpFileList::Append(MdpFileItem *theItem)
{
    ASSERT(theItem);
    if (next == NULL)
    {
        next = theItem;
        reset_next = true;
    }
    theItem->next = NULL;
    theItem->prev = tail;
    if (theItem->prev)
        tail->next = theItem;
    else
        head = theItem;
    tail = theItem;
}  // end MdpServerItemList::Append()

void MdpFileList::Remove(MdpFileItem *theItem)
{
    ASSERT(theItem);  // item is _assumed_ to be part of this list
    if (theItem == next)
    {
        next = theItem->next;
        reset_next = true;
    }
    if (theItem->prev)
        theItem->prev->next = theItem->next;
    else
        head = theItem->next;
    if (theItem->next)
        theItem->next->prev = theItem->prev;
    else
        tail = theItem->prev;
}  // end MdpFileList::Remove()


void MdpFileList::ResetIterator()
{
    next = head;
    reset_next = true;
    if (updates_only)
    {
        last_time = this_time;
        this_time = big_time;
    }
}  // end MdpFileList::ResetIterator()

// Slightly recursive routine to retrieve next file for
// transmission from our MdpFileList.  Recursion because
// some item types (directories) may contain multiple objects.
bool MdpFileList::GetNextFile(char *path, char *name)
{
    if (next)
    {
        char temp[MDP_PATH_MAX];
        next->GetFullName(temp, MDP_PATH_MAX);
        if (next->GetNextFile(path, name, reset_next, updates_only,
                              last_time, this_time, &big_time))
        {
            reset_next = false;
            return true;
        }
        else
        {
            next = next->next;
            reset_next = true;
            return GetNextFile(path, name);
        }
    }
    else
    {
        return  false; // end of list
    }
}  // end MdpFileList::GetNextItem()


MdpFileItem::MdpFileItem(const char *full_path)
    : prev(NULL), next(NULL)
{
    //before anything init the class variables
    path = new char [MDP_PATH_MAX + 1];
    name = new char [MDP_PATH_MAX + 1];

    // Break full_path into path + name components
    char fpath[MDP_PATH_MAX+1];
    strncpy(fpath, full_path, MDP_PATH_MAX);
    fpath[MDP_PATH_MAX] = '\0';
    int len = strlen(fpath);
    if (MDP_PROTO_PATH_DELIMITER == fpath[len-1])
    {
        fpath[len-1] = '\0';
        len--;
    }
    char *ptr = strrchr(fpath, MDP_PROTO_PATH_DELIMITER);
    if (ptr)
    {
        *ptr++ = '\0';
        strncpy(name, ptr, MDP_PATH_MAX);
        strcpy(path, fpath);
        len = strlen(path);
        path[len++] = MDP_PROTO_PATH_DELIMITER;
        if (len < MDP_PATH_MAX) path[len] = '\0';
    }
    else
    {
        path[0] = '\0';
        strncpy(name, fpath, MDP_PATH_MAX);
    }
    size = MdpFileGetSize(full_path);
}

MdpFileItem::~MdpFileItem()
{
    if (path)
        delete []path;
    path = NULL;

    if (name)
        delete []name;
    name = NULL;
}

void MdpFileItem::GetFullName(char *buf, int buflen)
{
    int len = MIN(buflen, MDP_PATH_MAX);
    strncpy(buf, path, len);
    int name_len = MIN((int)strlen(path), len);
    strncpy(buf + name_len, name, (unsigned int)(len - name_len));
    name_len += MIN((int)strlen(name), len);
    if (name_len > len) name_len = len;
    if (name_len < buflen) buf[name_len] = '\0';
}  // end MdpFileItem::GetFullName()

// A MdpFileItem only contains info on a single file
bool MdpFileItem::GetNextFile(char *thePath,
                              char *theName,
                              bool reset,
                              bool updates_only,
                              clocktype last_time,
                              clocktype this_time,
                              clocktype *big_time)
{
    if (reset)
    {
        if (updates_only)
        {
            char full_name[MDP_PATH_MAX];
            strncpy(full_name, path, MDP_PATH_MAX);
            int len = MIN(MDP_PATH_MAX, strlen(full_name));
            strncat(full_name, name, MDP_PATH_MAX - len);
            clocktype update_time = MdpFileGetUpdateTime(full_name);
            if (update_time > *big_time) *big_time = update_time;
            if ((update_time <= last_time) || (update_time > this_time))
                return false;
        }
        strncpy(thePath, path, MDP_PATH_MAX);
        strncpy(theName, name, MDP_PATH_MAX);
        return true;
    }
    else
    {
        return false;
    }
}  // end MdpFileItem::GetNextFile()




/*****************************************************************************
 * The MdpDirectoryItem class is used to walk through a directory.
 * The "GetNextItem()" method returns MdpFileItem objects from the
 * given directory.  The "SetUpdatesOnly()" method allows the user
 * to specify that only files updated after a certain date/time are
 * to be retrieved.
 */


MdpDirectoryItem::MdpDirectoryItem(const char *thePath)
    : MdpFileItem(thePath)
{

}

MdpDirectoryItem::~MdpDirectoryItem()
{

}


bool MdpDirectoryItem::GetNextFile(char *thePath,
                                   char *theName,
                                   bool reset,
                                   bool updates_only,
                                   clocktype last_time,
                                   clocktype this_time,
                                   clocktype *big_time)
{
    char dir_name[MDP_PATH_MAX];
    strncpy(dir_name, path, MDP_PATH_MAX);
    int len = MIN(MDP_PATH_MAX, strlen(dir_name));
    strncat(dir_name, name, MDP_PATH_MAX - len);
    len = MIN(MDP_PATH_MAX, len + MIN(MDP_PATH_MAX, strlen(name)));
    if (len < MDP_PATH_MAX)
    {
        if (dir_name[len-1] != MDP_PROTO_PATH_DELIMITER)
        {
            dir_name[len++] = MDP_PROTO_PATH_DELIMITER;
            if (len < MDP_PATH_MAX) dir_name[len] = '\0';
        }
    }

    if (reset)
    {
        /* For now we are going to poll all files in a directory individually
           since directory update times aren't always changed when files are
           are replaced within the directory tree ... uncomment this code
           if you only want to check directory nodes that have had their
           change time updated
        if (updates_only)
        {
            // Check to see if directory has been touched
            char full_name[MDP_PATH_MAX];
            strcpy(full_name, path);
            strcat(full_name, name);
            clocktype update_time = MdpFileGetUpdateTime(full_name);
            if (update_time > *big_time) *big_time = update_time;
            if ((update_time <= last_time) || (update_time > this_time))
                return false;
        } */
        if (!diterator.Init(dir_name))
        {
            printf("MdpDirectoryItem::GetNextFile() Error initing directory iterator!\n");
            return false;
        }
    }
    char file_name[MDP_PATH_MAX];
    while (diterator.GetNextFile(file_name))
    {
        // Use directory item path+name as file path
        char full_name[MDP_PATH_MAX];
        strncpy(full_name, dir_name, MDP_PATH_MAX);
        len = MIN(MDP_PATH_MAX, strlen(full_name));
        strncat(full_name, file_name, MDP_PATH_MAX-len);
        if (updates_only)
        {
            clocktype update_time = MdpFileGetUpdateTime(full_name);
            if (update_time > *big_time) *big_time = update_time;
            if ((update_time <= last_time) || (update_time > this_time))
                continue;
        }
        strncpy(thePath, dir_name, MDP_PATH_MAX);
        strncpy(theName, file_name, MDP_PATH_MAX);
        return true;
    }
    return false;
}  // end MdpDirectoryItem::GetNextObject()


MdpFileCache::MdpFileCache()
    : head(NULL), tail(NULL), file_count(0), byte_count(0),
      count_min(8), count_max(16), size_max(8*1024*1024)
{
}

MdpFileCache::~MdpFileCache()
{
    Destroy();
}

void MdpFileCache::SetCacheSize(UInt32 minCount,
                                UInt32 maxCount,
                                UInt32 maxSize)
{
    count_min = minCount;
    count_max = maxCount;
    size_max = maxSize;
    while ((file_count > count_max) ||
           ((file_count > count_min) && (byte_count > size_max)))
    {
        PurgeHead();
    }
}  // end MdpFileCache::SetCacheSize()

void MdpFileCache::Destroy()
{
    while (file_count) PurgeHead();
    byte_count = 0;
}  // end MdpFileCache::Destroy();

bool MdpFileCache::CacheFile(const char *thePath)
{
    // Allocate cache item state
    MdpFileItem *theItem = new MdpFileItem(thePath);
    if (!theItem) return false;
    // Make room for the file if needed
    UInt32 theSize = theItem->Size();
    while ((file_count >= count_max) ||
           ((file_count >= count_min) && ((byte_count+theSize) > size_max)))
    {
        PurgeHead();
    }
    // Add file to the cache
    byte_count += theSize;
    file_count++;
    theItem->prev = tail;
    if (theItem->prev)
        tail->next = theItem;
    else
        head = theItem;
    tail = theItem;
    theItem->next = NULL;
    return true;
}

void MdpFileCache::PurgeHead()
{
    MdpFileItem *fitem;
    fitem = head;
    if (fitem)
    {
        head = fitem->next;
        if (head)
            head->prev = NULL;
        else
            tail = NULL;
        char full_name[MDP_PATH_MAX];
        fitem->GetFullName(full_name, MDP_PATH_MAX);
        MdpFile file;
        file.Unlink(full_name);
        byte_count -= fitem->Size();
        file_count--;
        delete fitem;
    }
}  // end MdpFileCache::PurgeHead()
