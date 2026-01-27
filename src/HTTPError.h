/*
Copyright (C) Giuliano Catrambone (giulianocatrambone@gmail.com)

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either
 version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 Commercial use other than under the terms of the GNU General Public
 License is allowed only after express negotiation of conditions
 with the authors.
*/

#pragma once

#include "ThreadLogger.h"
#include <format>
#include <stdexcept>
#include <string>

namespace FastCGIError
{

struct HTTPError final : std::runtime_error
{
	int16_t httpErrorCode;
	explicit HTTPError(const int16_t httpErrorCode, const std::string& errorMessage = "") :
		std::runtime_error(errorMessage.empty() ? getHtmlStandardMessage(httpErrorCode) : errorMessage),
		httpErrorCode(httpErrorCode) {};

	static std::string getHtmlStandardMessage(int htmlResponseCode)
	{
		switch (htmlResponseCode)
		{
		case 200:
			return {"OK"};
		case 201:
			return {"Created"};
		case 204:
			return {"No Content"};
		case 301:
			return {"Moved Permanently"};
		case 302:
			return {"Found"};
		case 307:
			return {"Temporary Redirect"};
		case 308:
			return {"Permanent Redirect"};
		case 400:
			return {"Bad Request"};
		case 401:
			return {"Unauthorized"};
		case 403:
			return {"Forbidden"};
		case 404:
			return {"Not Found"};
		case 500:
			return {"Internal Server Error"};
		default:
			std::string errorMessage = std::format(
				"HTTP status code not managed"
				", htmlResponseCode: {}",
				htmlResponseCode
			);
			LOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}
	}

};

} // namespace mms::fc
