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

/*************************************************************
Multicast Dissemination Protocol version 2 (MDPv2)

This source code is part of the prototype NRL MDPv2 release
and was written and developed by Brian Adamson and Joe Macker.
This is presently experimental code and therefore use it at your
own risk.  Please include this notice and provide credit to the
authors and NRL if this program or parts of it are used for any
purpose.

We would appreciate receiving any contributed enhancements
or modifications to this code release. Please contact the developers
with comments/questions regarding this code release.  Feedback on
use of this code can help continue support for further development.

Joe Macker                  Brian Adamson
Email: <macker@itd.nrl.navy.mil>    <adamson@newlink.net>
Telephone: +1-202-767-2001      +1-202-404-1194
Naval Research Laboratory       Newlink Global Engineering Corp.
Information Technology Division     6506 Loisdale Road Suite 209
4555 Overlook Avenue            Springfield VA 22150
Washington DC 20375                     <http://www.ngec.com>
**************************************************************/
#ifndef _MDP_FILE
#define _MDP_FILE

// This is the WIN and UNIX 32 implementation of the MdpFile class

//#include "sysdefs.h"  // for Boolean definition, PATH_MAX, etc
//#include "debug.h"    // for DEBUG stuff
#include "mdpProtoDefs.h"

enum MdpFileType
{
    MDP_FILE_INVALID,
    MDP_FILE_NORMAL,
    MDP_FILE_DIRECTORY
};

class MdpFile
{
    // Members
    private:
        int fd;  // file handle
        int flags;
        off_t offset;

    // Methods
    public:
        MdpFile();
        ~MdpFile();
        bool Open(char *path, int theFlags);
        bool Lock();
        void Unlock();
        bool Rename(char *old_name, char *new_name);
        bool Unlink(char *path);
        void Close();
        bool IsOpen() {return (bool)(fd >= 0);}
        int Read(char *buffer, int len);
        int Write(char *buffer, int len);
        bool Seek(UInt32 theOffset);
        UInt32 Size();
        UInt32 Offset() {return ((UInt32) offset);}
        void SetOffset(UInt32 value) {offset = value;}
};

/******************************************
* The MdpDirectory and MdpDirectoryIterator classes
* are used to walk directory trees for file transmission
*/

class MdpDirectory
{
    friend class MdpDirectoryIterator;

    private:
#ifdef MDP_FOR_WINDOWS
        HANDLE          hSearch;
#else
        DIR             *dptr;
#endif
        //char            path[MDP_PATH_MAX];
        char            *path;
        MdpDirectory    *parent;

    private:
        MdpDirectory(const char *thePath, MdpDirectory *theParent = NULL);
        void GetFullName(char *ptr);
        bool Open();
        void Close();

#ifdef MDP_FOR_UNIX
        void SetDPtr(DIR *value) {dptr = value;}
#endif

        char *Path() {return path;}
        void RecursiveCatName(char *ptr);
};

class MdpDirectoryIterator
{
    private:
        MdpDirectory    *current;
        int             path_len;

    public:
        MdpDirectoryIterator();
        ~MdpDirectoryIterator();
        bool Init(const char *thePath);
        bool GetNextFile(char *file_name);

    private:
        void Destroy();
};

UInt32 MdpFileGetSize(const char* path);
MdpFileType MdpFileGetType(const char* path);
time_t MdpFileGetUpdateTime(const char* path);
bool MdpFileExists(const char* path);
bool MdpFileIsWritable(const char* path);

bool MdpFileIsLocked(char *path);


#endif // _MDP_FILE
