//
// Created by Giuliano on 13.12.2025.
//

#include "FCGIRequestData.h"
#include <curl/curl.h>

using namespace std;

void FCGIRequestData::init(const FCGX_Request & request, int64_t& maxAPIContentLength)
{
 	try
 	{
 		fillEnvironmentDetails(request.envp);

 		requestMethod = getMapParameter(_requestDetails, "REQUEST_METHOD", "", false);

 		// contentLength
 		{
 			if (requestMethod == "POST" || requestMethod == "PUT")
 			{
 				string sContentLength = getMapParameter(_requestDetails, "CONTENT_LENGTH", "0", false);
 				contentLength = stoul(sContentLength);
 			}
 			else
 				contentLength = 0;

 			if (contentLength > maxAPIContentLength)
 			{
 				string errorMessage = std::format(
					 "ContentLength too long"
					 ", contentLength: {}"
					 ", _maxAPIContentLength: {}",
					 contentLength, maxAPIContentLength
				 );
 				SPDLOG_ERROR(errorMessage);

 				throw runtime_error(errorMessage);
 			}
 		}

 		// requestBody
 		if (contentLength > 0)
 		{
			auto content = new char[contentLength];
 			contentLength = FCGX_GetStr(content, contentLength, request.in);
 			requestBody.assign(content, contentLength);
 			delete[] content;
 		}

 		requestURI = getMapParameter(_requestDetails, "REQUEST_URI", "", false);

	 	responseBodyCompressed = getHeaderParameter("x-responseBodyCompressed", "false", false) == "true";

 		// REMOTE_ADDR is the address of the load balancer
 		// auto remoteAddrIt = requestDetails.find("REMOTE_ADDR");
 		clientIPAddress = getHeaderParameter("x-forwarded-for", "", false);
 	}
 	catch (exception &e)
 	{
 		SPDLOG_ERROR("FCGIRequestData failed"
 			", exception: {}", e.what()
 		);
 		throw;
 	}
}

string FCGIRequestData::escape(const string &url)
{
	CURL *curl = curl_easy_init();
	if (!curl)
	{
		SPDLOG_ERROR("curl_easy_init failed");

		throw runtime_error("curl_easy_init failed");
	}

	char *encoded = curl_easy_escape(curl, url.c_str(), url.size());
	if (!encoded)
	{
		SPDLOG_ERROR("curl_easy_escape failed");
		curl_easy_cleanup(curl);
		throw runtime_error("curl_easy_escape failed");
	}

	string buffer = encoded;

	curl_free(encoded);

	curl_easy_cleanup(curl);

	return buffer;
}

string FCGIRequestData::unescape(const string &url)
{
	CURL *curl = curl_easy_init();
	if (!curl)
	{
		SPDLOG_ERROR("curl_easy_init failed");

		throw runtime_error("curl_easy_init failed");
	}

	int decodelen;
	char *decoded = curl_easy_unescape(curl, url.c_str(), url.size(), &decodelen);
	if (!decoded)
	{
		SPDLOG_ERROR("curl_easy_unescape failed");
		curl_easy_cleanup(curl);
		throw runtime_error("curl_easy_unescape failed");
	}

	string buffer = decoded;

	curl_free(decoded);

	curl_easy_cleanup(curl);

	return buffer;
}

void FCGIRequestData::parseContentRange(string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd, uint64_t &contentRangeSize)
{
	// Content-Range: bytes 0-99999/100000

	try
	{
		auto pos = contentRange.find("bytes ");
		if (pos == string_view::npos)
		{
			string errorMessage = std::format(
				"Content-Range does not start with 'bytes '"
				", contentRange: {}",
				contentRange
			);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}
		contentRange.remove_prefix(pos + 6);

		// Trova i separatori
		const auto dash = contentRange.find('-');
		const auto slash = contentRange.find('/');

		uint64_t start = 0, end = 0, size = 0;

		from_chars(contentRange.data(), contentRange.data() + dash, contentRangeStart);
		from_chars(contentRange.data() + dash + 1, contentRange.data() + slash, contentRangeEnd);
		from_chars(contentRange.data() + slash + 1, contentRange.data() + contentRange.size(), contentRangeSize);
	}
	catch (exception &e)
	{
		string errorMessage = std::format(
			"Content-Range is not well done. Expected format: 'Content-Range: bytes <start>-<end>/<size>'"
			", contentRange: {}",
			contentRange
		);
		SPDLOG_ERROR(errorMessage);

		throw runtime_error(errorMessage);
	}


	/*
	contentRangeStart = -1;
	contentRangeEnd = -1;
	contentRangeSize = -1;

	try
	{
		string prefix("bytes ");
		if (!(contentRange.size() >= prefix.size() && 0 == contentRange.compare(0, prefix.size(), prefix)))
		{
			string errorMessage = std::format(
				"Content-Range does not start with 'bytes '"
				", contentRange: {}",
				contentRange
			);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		size_t startIndex = prefix.size();
		size_t endIndex = contentRange.find('-', startIndex);
		if (endIndex == string::npos)
		{
			string errorMessage = std::format(
				"Content-Range does not have '-'"
				", contentRange: {}",
				contentRange
			);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		contentRangeStart = stoll(contentRange.substr(startIndex, endIndex - startIndex));

		endIndex++;
		size_t sizeIndex = contentRange.find('/', endIndex);
		if (sizeIndex == string::npos)
		{
			string errorMessage = std::format(
				"Content-Range does not have '/'"
				", contentRange: {}",
				contentRange
			);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		contentRangeEnd = stoll(contentRange.substr(endIndex, sizeIndex - endIndex));

		sizeIndex++;
		contentRangeSize = stoll(contentRange.substr(sizeIndex));
	}
	catch (exception &e)
	{
		string errorMessage = std::format(
			"Content-Range is not well done. Expected format: 'Content-Range: bytes <start>-<end>/<size>'"
			", contentRange: {}",
			contentRange
		);
		SPDLOG_ERROR(errorMessage);

		throw runtime_error(errorMessage);
	}
	*/
}

string FCGIRequestData::getHtmlStandardMessage(int htmlResponseCode)
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
 		string errorMessage = std::format(
			 "HTTP status code not managed"
			 ", htmlResponseCode: {}",
			 htmlResponseCode
		 );
 		SPDLOG_ERROR(errorMessage);

 		throw runtime_error(errorMessage);
 	}
 }

void FCGIRequestData::fillEnvironmentDetails(const char *const *envp)
{
	int valueIndex;

	for (; *envp; ++envp)
	{
		string environmentKeyValue = *envp;

		if ((valueIndex = environmentKeyValue.find('=')) == string::npos)
		{
			SPDLOG_ERROR(
				"Unexpected environment variable"
				", environmentKeyValue: {}",
				environmentKeyValue
			);

			continue;
		}

		string key = environmentKeyValue.substr(0, valueIndex);
		string value = environmentKeyValue.substr(valueIndex + 1);

		_requestDetails.emplace(key, value);

		if (key == "REQUEST_URI")
			SPDLOG_TRACE(
				"Environment variable"
				", key/Name: {}={}",
				key, value
			);
		else
			SPDLOG_TRACE(
				"Environment variable"
				", key/Name: {}={}",
				key, value
			);
	}

	if (unordered_map<string, string>::iterator it; (it = _requestDetails.find("QUERY_STRING")) != _requestDetails.end())
		fillQueryString(it->second);
}

void FCGIRequestData::fillQueryString(const string& queryString)
{
	stringstream ss(queryString);
	string token;
	char delim = '&';
	while (getline(ss, token, delim))
	{
		if (!token.empty())
		{
			size_t keySeparator;

			if ((keySeparator = token.find('=')) == string::npos)
			{
				SPDLOG_ERROR(
					"Wrong query parameter format"
					", token: {}",
					token
				);

				continue;
			}

			string key = token.substr(0, keySeparator);
			string value = token.substr(keySeparator + 1);

			_queryParameters[key] = value;

			SPDLOG_TRACE(
				"Query parameter"
				", key/Name: {}={}",
				key, value
			);
		}
	}
}

unordered_map<string, string> FCGIRequestData::getQueryParameters() const
{
	return _queryParameters;
}

vector<pair<string, string>> FCGIRequestData::getHeaders() const
{
	vector<pair<string, string>> headers;
	for (const auto &[key, value]: _requestDetails)
	{
		if (key.starts_with("HTTP_"))
			headers.emplace_back(StringUtils::replaceAll(StringUtils::lowerCase(key.substr(5)), "_", "-"),
				value);
	}
	return headers;
}