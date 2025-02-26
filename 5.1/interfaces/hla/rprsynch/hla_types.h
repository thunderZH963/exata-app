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

#ifndef _HLA_TYPES_H_
#define _HLA_TYPES_H_

#include <RTI.hh>
#include "archspec.h"

namespace SNT_HLA
{




// convert basic types between net and host
template <typename T> T fromNet(const unsigned char* net_data);
template <typename T> void toNet(T x, unsigned char* net_data);

class abstractAttribute
{
    public:
        virtual void reflectAttribute(const RTI::AttributeHandleValuePairSet& theAttributes, int idx) throw (RTI::FederateInternalError) = 0;
};

template <class T> class Attribute : public abstractAttribute
{
    private:
        T& value;
        void copyData(const RTI::AttributeHandleValuePairSet& theAttributes, int idx, unsigned char* data, size_t data_len) throw (RTI::FederateInternalError)
        {
            RTI::ULong size = theAttributes.getValueLength(idx);
            if( size != data_len )
            {
                throw RTI::FederateInternalError("Data size mismatch");
            }
            theAttributes.getValue(idx, (char*) data, size);
        }
    public:
        Attribute( T& data ) : value(data) {}
        virtual void reflectAttribute(const RTI::AttributeHandleValuePairSet& theAttributes, int idx) throw (RTI::FederateInternalError);
};

};

#endif

