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

#include "api.h"
#include "ip6_opts.h"
#include "ipv6.h"

#define DEBUG_IPV6 0

// The option processing is not used for this version.
// Kept for future use.

//---------------------------------------------------------------------------
// FUNCTION             : ip6SaveOption
// PURPOSE             :: This function is used to save the ipv6 options
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to the Message Structure
// +option              : optionList** option : Pointer to the pointer of
//                      :       starting option.
// RETURN               : optionList*: returns pointer to start of option
//                      :   list.
//---------------------------------------------------------------------------

optionList* ip6SaveOption(Message* msg, optionList** option)
{
    //unsigned
    char* payload = MESSAGE_ReturnPacket(msg);
    ip6_hdr* ip;
    opt6_any* optAny;
    headerInfo* hInfo;

    if (*option == NULL)
    {
        (*option) = (optionList*)MEM_malloc(sizeof(optionList));
        if ((*option))
        {
            ip = (ip6_hdr*)payload;
            (*option)->headerType = 1;
            (*option)->headerSize = sizeof(ip6_hdr);
            (*option)->optionNextHeader = ip->ip6_nxt;
            (*option)->optionPointer = payload;
            (*option)->nextOption = NULL;
            return ((*option));
        } // end of inserting first header i.e. ip6 header.
        else
        {
            return (NULL);
        }
    } // end of saving first ip header
    else
    {
        // Goto last option  and then save the new one;
        while ((*option)->nextOption != NULL)
        {
            (*option) = (*option)->nextOption;

        }
        (*option)->nextOption = (optionList*)MEM_malloc(sizeof(optionList));
        if ((*option)->nextOption)
        {
            optAny = (opt6_any*)payload;
            payload += (sizeof(opt6_any) + 1);
            hInfo = (headerInfo*)payload;

            (*option)->nextOption->headerType = (*option)->optionNextHeader;
            (*option)->nextOption->headerSize = hInfo->headerLength;
            (*option)->nextOption->optionNextHeader = hInfo->nextHeader;
            (*option)->nextOption->optionPointer = payload;
            (*option)->nextOption->nextOption = NULL;
            return ((*option)->nextOption);
        } // end of saving option if allocated
        else
        {
            return (NULL);
        } // return if unable to allocate due to memory shortage.

    } // end of saving other option.
} // end of function save option.

//---------------------------------------------------------------------------
// FUNCTION             : ip6deleteOption
// PURPOSE             :: This function is used to delete the ipv6 options
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to the Message Structure
// +option              : optionList** option : Pointer to the pointer of
//                      :       starting option.
// +which               : int which : which option to delete.
// RETURN               : optionList*: returns pointer to start of option
//                      :  list
//---------------------------------------------------------------------------
optionList* ip6deleteOption(Message* msg, optionList** option, int which)
{
     optionList* curOption = NULL;
     optionList* tempOption = NULL;

     if (!(*option)) // Extra error checking.
     {
         return (NULL);
     }
     if ((*option)->headerType == (unsigned)which)
     {
         tempOption = (*option);
         (*option) = (*option)->nextOption;
         MEM_free(tempOption);
         return((*option));
     }
     else
     {
         // Find the option first and then delete;
         curOption = (*option);
         while (curOption != NULL)
         {
             if (curOption->headerType == (unsigned) which)
             {
                 break;
             }
             tempOption = curOption;
             curOption = curOption->nextOption;
         } // End of finding the option;

         if (!curOption)
         {
             //ERROR_ASSERT(NULL,"Unable to find ipv6 option\n");
             return (NULL);
         }
         // Delete the option
         tempOption->nextOption = curOption->nextOption;
         MEM_free(curOption);
         return ((*option));
     }
}

//---------------------------------------------------------------------------
// FUNCTION             : ip6insertOption
// PURPOSE             :: This function is used to insert the ipv6 options
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to the Message Structure
// +option              : optionList** option : Pointer to the pointer of
//                      :       starting option.
// +which               : int whichType : which option to be inserted.
// RETURN               : optionList*: returns pointer to start of option
//                      :  list
//---------------------------------------------------------------------------
optionList* ip6insertOption(
    Message* msg,
    optionList** option,
    int whichType)
{
    //
    return (NULL);
}

//---------------------------------------------------------------------------
// FUNCTION             : ip6CopyOption
// PURPOSE             :: This function is used to copy the ipv6 options
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to the Message Structure
// +option              : optionList** option : Pointer to the pointer of
//                      :       starting option.
// RETURN               : optionList*: returns pointer to start of option
//                      :  list
//---------------------------------------------------------------------------
optionList* ip6CopyOption(Message* msg, optionList** option)
{
    return (NULL);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6OptionAlloc
// PURPOSE             :: This function is used to allocate ipv6 options
// PARAMETERS          ::
// +size                : int size : Size of option to allocate
// RETURN               : optionList*: returns pointer to start of option
//                      :  list
//---------------------------------------------------------------------------
optionList* Ipv6OptionAlloc(int size)
{
    optionList* temp = NULL;
    temp = (optionList*) MEM_malloc(sizeof(optionList));
    temp->nextOption = NULL;
    temp->optionPointer = (char*) MEM_malloc(size);
    return(temp);
}

