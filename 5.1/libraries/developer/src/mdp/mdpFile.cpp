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

// This is the WIN and UNIX 32 implementation of the MdpFile class
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "mdpFile.h"

#ifdef MDP_FOR_WINDOWS
#include <windows.h>
#include <direct.h>
#include <share.h>
#else
#include <unistd.h>
//#include <dirent.h>
#endif

#ifdef MDP_FOR_UNIX
// Most don't have the dirfd() function
#ifndef HAVE_DIRFD
//static inline int dirfd(DIR *dir) {return (dir->dd_fd);}
#endif // HAVE_DIRFD
#endif

MdpFile::MdpFile()
    : fd(-1)
{
}

MdpFile::~MdpFile()
{
    if (IsOpen()) Close();
}  // end MdpFile::~MdpFile()

// This should be called with a full path only!
bool MdpFile::Open(char *path, int theFlags)
{
    ASSERT(!IsOpen());

#ifdef MDP_FOR_WINDOWS
    // See if we need to build a directory
    if (theFlags & O_CREAT)
    {
        char *ptr = path;
        if (MDP_PROTO_PATH_DELIMITER == *ptr) ptr += 1;
        // Descend path, making and cd to dirs as needed
        // Save current directory
        char dirBuf[MDP_PATH_MAX];
        memset(dirBuf, 0, MDP_PATH_MAX);
        char* cwd = _getcwd(dirBuf, MDP_PATH_MAX);
        ptr = strchr(ptr, MDP_PROTO_PATH_DELIMITER);
        while (ptr)
        {
            *ptr = '\0';
            if (_chdir(path))
            {
                if (MDP_DEBUG)
                {
                    printf("Making directory: %s\n", path);
                }
                if (_mkdir(path))
                {
                    if (MDP_DEBUG)
                    {
                        char errStr[MAX_STRING_LENGTH];
                        sprintf(errStr,"mdp: Error opening file \"%s\": "
                                       "%s\n",
                                       path, strerror(errno));
                        ERROR_ReportWarning(errStr);
                    }
                    return false;
                }
            }
            *ptr++ = MDP_PROTO_PATH_DELIMITER;
            ptr = strchr(ptr, MDP_PROTO_PATH_DELIMITER);
        }
        if (cwd)
        {
            if (_chdir(cwd) < 0)
            {
                if (MDP_DEBUG)
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,"mdp: Change directory to %s "
                               "failed: %s\n", cwd, strerror(errno));
                    ERROR_ReportWarning(errStr);
                }
            }
        }
    }

    // Make sure we're in binary mode
    theFlags |= _O_BINARY;

    // Allow sharing of tx files but not of receive files
    if (theFlags & _O_RDONLY)
        fd = _sopen(path, theFlags, _SH_DENYNO);
    else
        fd = _open(path, theFlags, 0640);

    if (fd >= 0)
    {
        offset = 0;
        flags = theFlags;
        return true;  // no error
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"mdp: Error opening file \"%s\": %s\n",
                        path, strerror(errno));
        ERROR_ReportWarning(errStr);

        flags = 0;
        return false;
    }
#else
    // See if we need to build a directory
    if (theFlags & O_CREAT)
    {
        char *ptr = path;
        if (MDP_PROTO_PATH_DELIMITER == *ptr) ptr += 1;
        // Descend path, making and cd to dirs as needed
        // Save current directory
        char dirBuf[MDP_PATH_MAX];
        memset(dirBuf, 0, MDP_PATH_MAX);
        char* cwd = getcwd(dirBuf, MDP_PATH_MAX);
        while ((ptr = strchr(ptr, MDP_PROTO_PATH_DELIMITER)))
        {
            *ptr = '\0';
            if (chdir(path))
            {
                if (mkdir(path, 0777))
                {
                    if (MDP_DEBUG)
                    {
                        char errStr[MAX_STRING_LENGTH];
                        sprintf(errStr,"mdp: Error opening file \"%s\": %s",
                                        path, strerror(errno));
                        ERROR_ReportWarning(errStr);
                    }
                    return false;
                }
            }
            *ptr++ = MDP_PROTO_PATH_DELIMITER;
        }
        if (cwd)
        {
            if (chdir(cwd) < 0)
            {
                if (MDP_DEBUG)
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,"mdp: Change directory to %s "
                               "failed: %s\n", cwd, strerror(errno));
                    ERROR_ReportWarning(errStr);
                }
            }
        }
    }

    if ((fd = open(path, theFlags, 0640)) >= 0)
    {
        offset = 0;
        return true;  // no error
    }
    else
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"mdp: Error opening file: %s\n", strerror(errno));
        ERROR_ReportWarning(errStr);

        flags = 0;
        return false;
    }
#endif

}  // end MdpFile::Open()


// Routines to try to get an exclusive lock on
// a file
bool MdpFile::Lock()
{
#ifdef MDP_FOR_WINDOWS
    // do nothing for windows, Open routine locks wronly files
    return true;
#else  //else of #ifdef MDP_FOR_WINDOWS
    fchmod(fd, 0640 | S_ISGID);
#ifdef HAVE_FLOCK
    if (flock(fd, LOCK_EX | LOCK_NB))
#else
#ifdef HAVE_LOCKF
    if (lockf(fd, F_LOCK, 0))
#else
    if (0)  // some systems have neither
#endif // HAVE_LOCKF
#endif // HAVE_FLOCK
        return false;
    else
        return true;
#endif  //end of #ifdef MDP_FOR_WINDOWS
}  // end MdpFile::Lock()

void MdpFile::Unlock()
{
#ifdef MDP_FOR_WINDOWS
    // do nothing for windows, files unlocked when closed
    return;
#else //else of #ifdef MDP_FOR_WINDOWS
#ifdef HAVE_FLOCK
    flock(fd, LOCK_UN);
#else
#ifdef HAVE_LOCKF
    lockf(fd, F_ULOCK, 0);
#endif // HAVE_LOCKF
#endif // HAVE_FLOCK
    fchmod(fd, 0640);
#endif //end of #ifdef MDP_FOR_WINDOWS
}  // end MdpFile::UnLock()


bool MdpFile::Rename(char *old_name, char *new_name)
{
    // Make sure the new file name isn't an existing "busy" file
    // (This also builds sub-directories as needed)
    if (MdpFileIsLocked(new_name))
        return false;

#ifdef MDP_FOR_WINDOWS
    // In Win32, the new file can't already exist
    if (MdpFileExists(new_name))
        _unlink(new_name);

    // Close the current file
    int old_flags = 0;
    if (IsOpen())
    {
        old_flags = flags;
        old_flags &= ~(O_CREAT | O_TRUNC);  // unset these
        Close();
    }
    if (rename(old_name, new_name))
    {
        if (MDP_DEBUG)
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"File rename() error: %s\n", strerror(errno));
            ERROR_ReportWarning(errStr);
        }
        if (old_flags) Open(old_name, old_flags);
        return false;
    }
    else
    {
        if (old_flags) Open(new_name, old_flags);
        return true;
    }
#else //else of #ifdef MDP_FOR_WINDOWS
    else if (rename(old_name, new_name))
        return false;
    else
        return true;
#endif //end of #ifdef MDP_FOR_WINDOWS
}  // end MdpFile::Rename()

bool MdpFile::Unlink(char *path)
{
    // Don't unlink a file that is open (locked)
    if (MdpFileIsLocked(path))
    {
        return false;
    }
#ifdef MDP_FOR_WINDOWS
    else if (_unlink(path))
#else
    else if (unlink(path))
#endif
    {
        if (MdpFileExists(path))
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"Warning on unlinking file(%s): %s. ",
                            path, strerror(errno));
            ERROR_ReportWarning(errStr);
        }
        return false;
    }
    else
    {
        return true;
    }
}  // end MdpFile::Unlink()

void MdpFile::Close()
{
    ASSERT(IsOpen());
#ifdef MDP_FOR_WINDOWS
    _close(fd);
#else
    close(fd);
#endif
    flags = 0;
    fd = -1;
}  // end MdpFile::Close()

int MdpFile::Read(char *buffer, int len)
{
    ASSERT(IsOpen());
#ifdef MDP_FOR_WINDOWS
    return _read(fd, buffer, len);
#else
    return read(fd, buffer, len);
#endif
}  // end MdpFile::Read()

int MdpFile::Write(char *buffer, int len)
{
    ASSERT(IsOpen());

#ifdef MDP_FOR_WINDOWS
    return _write(fd, buffer, len);
#else
    return write(fd, buffer, len);
#endif
}  // end MdpFile::Write()


bool MdpFile::Seek(UInt32 theOffset)
{
    ASSERT(IsOpen());
#ifdef MDP_FOR_WINDOWS
    off_t result = _lseek(fd, theOffset, SEEK_SET);
#else
    off_t result = lseek(fd, theOffset, SEEK_SET);
#endif
    if (result < 0)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"mdp: Error positioning file pointer: %s\n",
                        strerror(errno));
        ERROR_ReportWarning(errStr);

        return false;
    }
    else
    {
        offset = result;
        return true; // no error
    }
}  // end MdpFile::Seek()

UInt32 MdpFile::Size()
{
    ASSERT(IsOpen());

#ifdef MDP_FOR_WINDOWS
    struct _stat info;
    int result = _fstat(fd, &info);
#else
    struct stat info;
    int result = fstat(fd, &info);
#endif
    if (result)
    {
        if (MDP_DEBUG)
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"Error getting file size: %s\n", strerror(errno));
            ERROR_ReportWarning(errStr);
        }
        return 0;
    }
    else
    {
        return info.st_size;
    }
}  // end MdpFile::Size()

/******************************************
 * The MdpDirectory and MdpDirectoryIterator classes
 * are used to walk directory trees for file transmission
 */

MdpDirectory::MdpDirectory(const char *thePath, MdpDirectory *theParent)
#ifdef MDP_FOR_WINDOWS
    : hSearch((HANDLE)-1), parent(theParent)
#else
    : dptr(NULL), parent(theParent)
#endif
{
    //first init the path variable of the class
    path = new char [MDP_PATH_MAX];

    //now proceed further
    strncpy(path, thePath, MDP_PATH_MAX);
    int len = MIN(MDP_PATH_MAX, (int) strlen(path));
    if ((len < MDP_PATH_MAX) && (MDP_PROTO_PATH_DELIMITER != path[len-1]))
    {
        path[len++] = MDP_PROTO_PATH_DELIMITER;
        if (len < MDP_PATH_MAX) path[len] = '\0';
    }
}

// Make sure it's a valid directory and set dir name
bool MdpDirectory::Open()
{
#ifdef MDP_FOR_WINDOWS
    if (hSearch != (HANDLE) -1)
    {
        FindClose(hSearch);
        hSearch = (HANDLE) -1;
    }
    char full_name[MDP_PATH_MAX];
    GetFullName(full_name);
    // Get rid of trailing DIR_DELIMITER
    int len = MIN(MDP_PATH_MAX, (int) strlen(full_name));
    if (MDP_PROTO_PATH_DELIMITER == full_name[len-1])
        full_name[len-1] = '\0';
    DWORD attr = GetFileAttributes(full_name);
    if (0xFFFFFFFF == attr)
        return false;
    else if (attr & FILE_ATTRIBUTE_DIRECTORY)
        return true;
    else
        return false;
#else //else of #ifdef MDP_FOR_WINDOWS

    if (dptr) Close();
    char full_name[MDP_PATH_MAX];
    GetFullName(full_name);
    // Get rid of trailing PROTO_PATH_DELIMITER
    int len = MIN(MDP_PATH_MAX, strlen(full_name));
    if (MDP_PROTO_PATH_DELIMITER == full_name[len-1])
    {
        full_name[len-1] = '\0';
    }
    if ((dptr = opendir(full_name)))
        return true;
    else
        return false;
#endif //end of #ifdef MDP_FOR_WINDOWS

} // end MdpDirectory::Open()

void MdpDirectory::Close()
{
#ifdef MDP_FOR_WINDOWS
    if (hSearch != (HANDLE) -1)
    {
        FindClose(hSearch);
        hSearch = (HANDLE) -1;
    }
#else
    closedir(dptr);
    dptr = NULL;
#endif

    if (path)
        delete []path;
    path = NULL;
}  // end MdpDirectory::Close()


void MdpDirectory::GetFullName(char *ptr)
{
    ptr[0] = '\0';
    RecursiveCatName(ptr);
}  // end GetFullName()

void MdpDirectory::RecursiveCatName(char *ptr)
{
    if (parent) parent->RecursiveCatName(ptr);
    int len = MIN(MDP_PATH_MAX, (int)strlen(ptr));
    strncat(ptr, path, MDP_PATH_MAX-len);
}  // end RecursiveCatName()



MdpDirectoryIterator::MdpDirectoryIterator()
    : current(NULL)
{

}

MdpDirectoryIterator::~MdpDirectoryIterator()
{
    Destroy();
}


bool MdpDirectoryIterator::Init(const char *thePath)
{
    if (current) Destroy();

#ifdef MDP_FOR_UNIX
    if (thePath && access(thePath, X_OK))
    {
        printf("MdpDirectoryIterator: can't access directory: %s\n",thePath);
        return false;
    }
#endif

    // Make sure it's a valid directory
    current = new MdpDirectory(thePath);
    if (current && current->Open())
    {
        path_len = MIN(MDP_PATH_MAX, (int)strlen(current->Path()));
        return true;
    }
    else
    {
        printf("MdpDirectoryIterator: can't open directory: %s\n", thePath);
        if (current) delete current;
        current = NULL;
        return false;
    }
}  // end MdpDirectoryIterator::Init()

void MdpDirectoryIterator::Destroy()
{
    MdpDirectory *ptr;
    ptr = current;
    while (ptr)
    {
        current = ptr->parent;
        ptr->Close();
        delete ptr;
        ptr = current;
    }
}  // end MdpDirectoryIterator::Destroy()

bool MdpDirectoryIterator::GetNextFile(char *file_name)
{
    if (!current) return false;

#ifdef MDP_FOR_WINDOWS
    bool success = true;

    while (success)
    {
        WIN32_FIND_DATA find_data;
        if (current->hSearch == (HANDLE) -1)
        {
            // Construct search string
            current->GetFullName(file_name);
            strcat(file_name, "\\*");
            if ((HANDLE) -1 ==
                  (current->hSearch = FindFirstFile(file_name, &find_data)))
                success = false;
            else
                success = true;
        }
        else
        {
            success = (0 != FindNextFile(current->hSearch, &find_data));
        }

        // Do we have a candidate file?
        if (success)
        {
            char *ptr = strrchr(find_data.cFileName,
                                MDP_PROTO_PATH_DELIMITER);
            if (ptr)
                ptr += 1;
            else
                ptr = find_data.cFileName;

            // Skip "." and ".." directories
            if (ptr[0] == '.')
            {
                if ((1 == strlen(ptr)) ||
                    ((ptr[1] == '.') && (2 == strlen(ptr))))
                {
                    continue;
                }
            }

            current->GetFullName(file_name);
            strcat(file_name, ptr);
            int type = MdpFileGetType(file_name);
            if (MDP_FILE_NORMAL == type)
            {
                int name_len = MIN(MDP_PATH_MAX, (int) strlen(file_name)) -
                                                                    path_len;
                memmove(file_name, file_name+path_len, name_len);
                if (name_len < MDP_PATH_MAX) file_name[name_len] = '\0';
                return true;
            }
            else if (MDP_FILE_DIRECTORY == type)
            {

                MdpDirectory *dir = new MdpDirectory(ptr, current);
                if (dir && dir->Open())
                {
                    // Push sub-directory onto stack and search it
                    current = dir;
                    return GetNextFile(file_name);
                }
                else
                {
                    // Couldn't open try next one
                    if (dir) delete dir;
                }
            }
            else
            {
                // Invalid file, try next one
            }
        }  // end if (success)
    }  // end while (success)

    // if parent, popup a level and continue search
    if (current->parent)
    {
        current->Close();
        MdpDirectory *dir = current;
        current = current->parent;
        delete dir;
        return GetNextFile(file_name);
    }
    else
    {
        current->Close();
        delete current;
        current = NULL;
        return false;
    }

#else // else of #ifdef MDP_FOR_WINDOWS
    struct dirent *dp;
    while ((dp = readdir(current->dptr)))
    {
        // Make sure it's not "." or ".."
        if (dp->d_name[0] == '.')
        {
            if ((1 == strlen(dp->d_name)) ||
                ((dp->d_name[1] == '.' ) && (2 == strlen(dp->d_name))))
            {
                continue;  // skip "." and ".." directory names
            }
        }
        current->GetFullName(file_name);
        strcat(file_name, dp->d_name);
        int type = MdpFileGetType(file_name);
        if (MDP_FILE_NORMAL == type)
        {
            int name_len = MIN(MDP_PATH_MAX, (int) strlen(file_name)) - 
                                                                    path_len;
            memmove(file_name, file_name+path_len, name_len);
            if (name_len < MDP_PATH_MAX) file_name[name_len] = '\0';
            return true;
        }
        else if (MDP_FILE_DIRECTORY == type)
        {
            MdpDirectory *dir = new MdpDirectory(dp->d_name, current);
            if (dir && dir->Open())
            {
                // Push sub-directory onto stack and search it
                current = dir;
                return GetNextFile(file_name);
            }
            else
            {
                // Couldn't open this one, try next one
                if (dir) delete dir;
            }
        }
        else
        {
            // MDP_FILE_INVALID, try next
        }
    }  // end while (readdir())

    // Popup a level and recursively continue or finish if done
    if (current->parent)
    {
        char path[MDP_PATH_MAX];
        current->parent->GetFullName(path);
        current->Close();
        MdpDirectory *dir = current;
        current = current->parent;
        delete dir;
        return GetNextFile(file_name);
    }
    else
    {
        current->Close();
        delete current;
        current = NULL;
        return false;  // no more files remain
    }

#endif // end of #ifdef MDP_FOR_WINDOWS
}  // end MdpDirectoryIterator::GetNextFile()

UInt32 MdpFileGetSize(const char* path)
{
#ifdef MDP_FOR_WINDOWS
    struct _stat info;
    int result = _stat(path, &info);
#else
    struct stat info;
    int result = stat(path, &info);
#endif
    if (result)
    {
        if (MDP_DEBUG)
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"Error getting file size: %s\n", strerror(errno));
            ERROR_ReportWarning(errStr);
        }
        return 0;
    }
    else
    {
        return info.st_size;
    }
}  // end MdpFileGetSize

// Is the named item a valid directory or file (or neither)??
MdpFileType MdpFileGetType(const char *path)
{
#ifdef MDP_FOR_WINDOWS
    DWORD attr = GetFileAttributes(path);
    if (0xFFFFFFFF == attr)
    {
        return MDP_FILE_INVALID;  // error
    }
    else if (attr & FILE_ATTRIBUTE_DIRECTORY)
    {
        return MDP_FILE_DIRECTORY;
    }
#else
    struct stat file_info;
    if (stat(path, &file_info))
    {
        return MDP_FILE_INVALID;  // stat() error
    }
    else if ((S_ISDIR(file_info.st_mode)))
    {
        return MDP_FILE_DIRECTORY;
    }
#endif
    else
    {
        return MDP_FILE_NORMAL;
    }
}  // end MdpFileGetType


time_t MdpFileGetUpdateTime(const char *path)
{
#ifdef MDP_FOR_WINDOWS
    struct _stat info;
    if (_stat(path, &info))
    {
        return (time_t) 0;
    }
    else
    {
        // Hack because Win2K and Win98 seem to work differently
        time_t updateTime = MAX(info.st_ctime, info.st_atime);
        updateTime = MAX(updateTime, info.st_mtime);
        return updateTime;
    }
#else
    struct stat file_info;
    if (stat(path, &file_info))
        return (time_t) 0;  // stat() error
    else
        return file_info.st_ctime;
#endif
}  // end MdpFileGetUpdateTime()

bool MdpFileExists(const char* path)
{
#ifdef MDP_FOR_WINDOWS
    return (0xFFFFFFFF != GetFileAttributes(path));
#else
    return (0 == access(path, F_OK));
#endif
}  // end MdpFileExists()


bool MdpFileIsWritable(const char* path)
{
#ifdef MDP_FOR_WINDOWS
    DWORD attr = GetFileAttributes(path);
    return (0xFFFFFFFF == attr) ? 
            FALSE : (0 == (attr & FILE_ATTRIBUTE_READONLY));
#else
    return (0 == access(path, W_OK));
#endif
}  // end MdpFileIsWritable()


bool MdpFileIsLocked(char *path)
{
    // If file doesn't exist, it's not locked
    if (!MdpFileExists(path))
    {
        return false;
    }

    MdpFile testFile;

#ifdef MDP_FOR_WINDOWS
    if (testFile.Open(path, O_WRONLY))
    {
        testFile.Close();
        return false;
    }
    else
    {
        return true;  // Couldn't open, must be in use
    }
#else
    if (!testFile.Open(path, O_WRONLY | O_CREAT))
    {
        return true;
    }
    else if (testFile.Lock())
    {
        // We were able to lock the file successfully
        testFile.Unlock();
        testFile.Close();
        return false;
    }
    else
    {
        testFile.Close();
        return true;
    }
#endif
}  // end MdpFileIsLocked()
