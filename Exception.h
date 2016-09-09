//Author: Jeremy

#pragma once
#include <string>

namespace PeLoaderLib
{
	class Exception
	{
	private:
		std::string m_sReason;

	public:
		Exception(const std::string& sReason);

		~Exception();

		std::string getReason() const;
	};
};