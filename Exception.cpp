//Author: Jeremy. Wildsmith

#include "stdafx.h"
#include "Exception.h"

using namespace PeLoaderLib;

Exception::Exception(const std::string& sReason)
{
	m_sReason = sReason;
}

Exception::~Exception()
{
}

std::string Exception::getReason() const
{
	return m_sReason;
}
