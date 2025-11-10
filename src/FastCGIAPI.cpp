
#include "Compressor.h"
#include <deque>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <utility>
#include <sys/utsname.h>
#include <curl/curl.h>
//
#include "FastCGIAPI.h" // has to be the last one otherwise errors...

extern char **environ;

FastCGIAPI::FastCGIAPI(const json& configurationRoot, mutex *fcgiAcceptMutex) { init(configurationRoot, fcgiAcceptMutex); }

FastCGIAPI::~FastCGIAPI() = default;

string FastCGIAPI::escape(const string &url)
{
	CURL *curl = curl_easy_init();
	if (!curl)
		throw runtime_error("curl_easy_init failed");

	char *encoded = curl_easy_escape(curl, url.c_str(), url.size());
	if (!encoded)
	{
		curl_easy_cleanup(curl);
		throw runtime_error("curl_easy_escape failed");
	}

	string buffer = encoded;

	curl_free(encoded);

	curl_easy_cleanup(curl);

	return buffer;
}

string FastCGIAPI::unescape(const string &url)
{
	CURL *curl = curl_easy_init();
	if (!curl)
		throw runtime_error("curl_easy_init failed");

	int decodelen;
	char *decoded = curl_easy_unescape(curl, url.c_str(), url.size(), &decodelen);
	if (!decoded)
	{
		curl_easy_cleanup(curl);
		throw runtime_error("curl_easy_unescape failed");
	}

	string buffer = decoded;

	curl_free(decoded);

	curl_easy_cleanup(curl);

	return buffer;
}

void FastCGIAPI::init(const json &configurationRoot, mutex *fcgiAcceptMutex)
{
	_shutdown = false;
	// _configurationRoot = configurationRoot;
	_fcgiAcceptMutex = fcgiAcceptMutex;

	_fcgxFinishDone = false;

	{
		struct utsname unUtsname{};
		if (uname(&unUtsname) != -1)
			_hostName = unUtsname.nodename;
	}

	_requestIdentifier = 0;

	loadConfiguration(configurationRoot);
}

void FastCGIAPI::loadConfiguration(json configurationRoot)
{
	_maxAPIContentLength = JSONUtils::asInt64(configurationRoot["api"], "maxContentLength", static_cast<int64_t>(0));
	SPDLOG_TRACE(
		"Configuration item"
		", api->maxContentLength: {}",
		_maxAPIContentLength
	);
}

int FastCGIAPI::operator()()
{
	string sThreadId;
	{
		thread::id threadId = this_thread::get_id();
		stringstream ss;
		ss << threadId;
		sThreadId = ss.str();
	}

	FCGX_Request request;

	// 0 is file number for STDIN by default
	// The fastcgi process is launched by spawn-fcgi (see scripts/mmsApi.sh
	// scripts/mmsEncoder.sh) specifying the port to be used to listen to nginx
	// calls The nginx process is configured to proxy the requests to
	// 127.0.0.1:<port> specified by spawn-fcgi
	int sock_fd = 0;
	SPDLOG_TRACE(
		"FastCGIAPI::FCGX_OpenSocket"
		", threadId: {}"
		", sock_fd: {}",
		sThreadId, sock_fd
	);
	FCGX_InitRequest(&request, sock_fd, 0);

	while (!_shutdown)
	{
		_requestIdentifier++;

		int returnAcceptCode;
		{
			SPDLOG_TRACE(
				"FastCGIAPI::ready"
				", _requestIdentifier: {}"
				", threadId: {}",
				_requestIdentifier, sThreadId
			);
			lock_guard<mutex> locker(*_fcgiAcceptMutex);

			SPDLOG_TRACE(
				"FastCGIAPI::listen"
				", _requestIdentifier: {}"
				", threadId: {}",
				_requestIdentifier, sThreadId
			);

			if (_shutdown)
				continue;

			returnAcceptCode = FCGX_Accept_r(&request);
		}
		SPDLOG_TRACE(
			"FCGX_Accept_r"
			", _requestIdentifier: {}"
			", threadId: {}"
			", returnAcceptCode: {}",
			_requestIdentifier, sThreadId, returnAcceptCode
		);

		if (returnAcceptCode != 0)
		{
			_shutdown = true;

			FCGX_Finish_r(&request);

			continue;
		}

		_fcgxFinishDone = false;

		SPDLOG_TRACE(
			"Request to be managed"
			", _requestIdentifier: {}"
			", threadId: {}",
			_requestIdentifier, sThreadId
		);

		unordered_map<string, string> requestDetails;
		unordered_map<string, string> queryParameters;
		string requestBody;
		unsigned long contentLength = 0;
		try
		{
			fillEnvironmentDetails(request.envp, requestDetails);
			// fillEnvironmentDetails(environ, requestDetails);

			{
				if (unordered_map<string, string>::iterator it; (it = requestDetails.find("QUERY_STRING")) != requestDetails.end())
					fillQueryString(it->second, queryParameters);
			}

			{
				unordered_map<string, string>::iterator it;
				if ((it = requestDetails.find("REQUEST_METHOD")) != requestDetails.end() && (it->second == "POST" || it->second == "PUT"))
				{
					if ((it = requestDetails.find("CONTENT_LENGTH")) != requestDetails.end())
					{
						if (!it->second.empty())
						{
							contentLength = stol(it->second);
							if (contentLength > _maxAPIContentLength)
							{
								string errorMessage = std::format(
									"ContentLength too long"
									", _requestIdentifier: {}"
									", threadId: {}"
									", contentLength: {}"
									", _maxAPIContentLength: {}",
									_requestIdentifier, sThreadId, contentLength, _maxAPIContentLength
								);

								SPDLOG_ERROR(errorMessage);

								throw runtime_error(errorMessage);
							}
						}
						else
						{
							contentLength = 0;
						}
					}
					else
					{
						contentLength = 0;
					}

					if (contentLength > 0)
					{
						char *content = new char[contentLength];

						contentLength = FCGX_GetStr(content, contentLength, request.in);

						requestBody.assign(content, contentLength);

						delete[] content;
					}
				}
			}
		}
		catch (runtime_error &e)
		{
			SPDLOG_ERROR(e.what());

			sendError(request, 500, e.what());

			if (!_fcgxFinishDone)
				FCGX_Finish_r(&request);

			// throw runtime_error(errorMessage);
			continue;
		}
		catch (exception &e)
		{
			string errorMessage = "Internal server error";
			SPDLOG_ERROR(errorMessage);

			sendError(request, 500, errorMessage);

			if (!_fcgxFinishDone)
				FCGX_Finish_r(&request);

			// throw runtime_error(errorMessage);
			continue;
		}

		string requestURI;
		{
			unordered_map<string, string>::iterator it;

			if ((it = requestDetails.find("REQUEST_URI")) != requestDetails.end())
				requestURI = it->second;
		}

		json permissionsRoot;
		bool authorizationPresent = basicAuthenticationRequired(requestURI, queryParameters);
		shared_ptr<AuthorizationDetails> authorizationDetails = nullptr;
		if (authorizationPresent)
		{
			try
			{
				unordered_map<string, string>::iterator it;

				if ((it = requestDetails.find("HTTP_AUTHORIZATION")) == requestDetails.end())
				{
					SPDLOG_ERROR("No 'Basic' authorization is present into the request");

					throw HTTPError(401);
				}

				string authorizationPrefix = "Basic ";
				if (!(it->second.size() >= authorizationPrefix.size() && 0 == it->second.compare(0, authorizationPrefix.size(), authorizationPrefix)))
				{
					SPDLOG_ERROR(
						"No 'Basic' authorization is present into the request"
						", _requestIdentifier: {}"
						", threadId: {}"
						", Authorization: {}",
						_requestIdentifier, sThreadId, it->second
					);

					throw HTTPError(401);
				}

				string usernameAndPasswordBase64 = it->second.substr(authorizationPrefix.length());
				string usernameAndPassword = base64_decode(usernameAndPasswordBase64);
				size_t userNameSeparator = usernameAndPassword.find(':');
				if (userNameSeparator == string::npos)
				{
					SPDLOG_ERROR(
						"Wrong Authorization format"
						", _requestIdentifier: {}"
						", threadId: {}"
						", usernameAndPasswordBase64: {}"
						", usernameAndPassword: {}",
						_requestIdentifier, sThreadId, usernameAndPasswordBase64, usernameAndPassword
					);

					throw HTTPError(401);
				}

				string userName = usernameAndPassword.substr(0, userNameSeparator);
				string password = usernameAndPassword.substr(userNameSeparator + 1);

				authorizationDetails = checkAuthorization(sThreadId, userName, password);
			}
			catch (exception &e)
			{
				SPDLOG_ERROR(
					"checkAuthorization failed"
					", _requestIdentifier: {}"
					", threadId: {}"
					", e.what(): {}",
					_requestIdentifier, sThreadId, e.what()
				);

				int htmlResponseCode = 500;
				if (dynamic_cast<HTTPError*>(&e))
					htmlResponseCode = dynamic_cast<HTTPError*>(&e)->httpErrorCode;

				string errorMessage = getHtmlStandardMessage(htmlResponseCode);
				SPDLOG_ERROR(errorMessage);

				sendError(request, htmlResponseCode, errorMessage); // unauthorized

				if (!_fcgxFinishDone)
					FCGX_Finish_r(&request);

				//  throw runtime_error(errorMessage);
				continue;
			}
		}

		chrono::system_clock::time_point startManageRequest = chrono::system_clock::now();
		try
		{
			unordered_map<string, string>::iterator it;

			string requestMethod;
			if ((it = requestDetails.find("REQUEST_METHOD")) != requestDetails.end())
				requestMethod = it->second;

			bool responseBodyCompressed = false;
			{
				if ((it = requestDetails.find("HTTP_X_RESPONSEBODYCOMPRESSED")) != requestDetails.end() && it->second == "true")
					responseBodyCompressed = true;
			}

			manageRequestAndResponse(
				sThreadId, _requestIdentifier, request, authorizationDetails, requestURI, requestMethod,
				requestBody, responseBodyCompressed, contentLength, requestDetails, queryParameters
			);
		}
		catch (exception &e)
		{
			SPDLOG_ERROR(
				"manageRequestAndResponse failed"
				", _requestIdentifier: {}"
				", threadId: {}"
				", exception: {}",
				_requestIdentifier, sThreadId, e.what()
			);
		}
		{
			auto method = getQueryParameter(queryParameters, "x-api-method", "", false);

			string clientIPAddress = getClientIPAddress(requestDetails);

			chrono::system_clock::time_point endManageRequest = chrono::system_clock::now();
			if (!requestURI.ends_with("/status"))
				SPDLOG_INFO(
					"manageRequestAndResponse"
					", _requestIdentifier: {}"
					", threadId: {}"
					", clientIPAddress: @{}@"
					", method: @{}@"
					", requestURI: {}"
					", authorizationPresent: {}"
					", @MMS statistics@ - manageRequestDuration (millisecs): @{}@",
					_requestIdentifier, sThreadId, clientIPAddress, method, requestURI, authorizationPresent,
					chrono::duration_cast<chrono::milliseconds>(endManageRequest - startManageRequest).count()
				);
		}

		SPDLOG_TRACE(
			"FastCGIAPI::request finished"
			", _requestIdentifier: {}"
			", threadId: {}",
			_requestIdentifier, sThreadId
		);

		if (!_fcgxFinishDone)
			FCGX_Finish_r(&request);

		// Note: the fcgi_streambuf destructor will auto flush
	}

	SPDLOG_INFO(
		"FastCGIAPI shutdown"
		", threadId: {}",
		sThreadId
	);

	return 0;
}

bool FastCGIAPI::handleRequest(
	const string_view &sThreadId, int64_t requestIdentifier, FCGX_Request &request,
	const shared_ptr<AuthorizationDetails>& authorizationDetails, const string_view &requestURI,
	const string_view &requestMethod, const string_view &requestBody, bool responseBodyCompressed,
	const unordered_map<string, string> &requestDetails,
	const unordered_map<string, string> &queryParameters, const bool exceptionIfNotManaged)
{
	bool isParamPresent;
	const string method = getQueryParameter(queryParameters, "x-api-method", "", false, &isParamPresent);
	if (!isParamPresent)
	{
		if (exceptionIfNotManaged)
			throw runtime_error( std::format(
				"request is not managed because 'x-api-method' is missing"
				", requestIdentifier: {}"
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}",
				requestIdentifier, sThreadId, requestURI, requestMethod)
			);
		else
			return true; // request not managed
	}

	const auto handlerIt = _handlers.find(method);
	if (handlerIt == _handlers.end())
	{
		if (exceptionIfNotManaged)
			throw runtime_error( std::format(
				"request is not managed because no registration found for method {}"
				", requestIdentifier: {}"
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}",
				method, requestIdentifier, sThreadId, requestURI, requestMethod)
			);
		else
			return true; // request not managed
	}

	handlerIt->second(sThreadId, requestIdentifier, request, authorizationDetails, requestURI, requestMethod, requestBody, responseBodyCompressed,
		requestDetails, queryParameters);

	return false;
}

void FastCGIAPI::stopFastcgi() { _shutdown = true; }

bool FastCGIAPI::basicAuthenticationRequired( const string& requestURI, const unordered_map<string, string>& queryParameters)
{
	bool basicAuthenticationRequired = true;

	return basicAuthenticationRequired;
}

void FastCGIAPI::sendSuccess(
	const string_view& sThreadId, int64_t requestIdentifier, bool responseBodyCompressed, FCGX_Request &request, const string_view& requestURI,
	const string_view& requestMethod, int htmlResponseCode, const string_view& responseBody, const string_view& contentType, const string_view& cookieName,
	const string_view& cookieValue, const string_view& cookiePath, bool enableCorsGETHeader, const string_view& originHeader
)
{
	if (_fcgxFinishDone)
	{
		// se viene chiamato due volte
		// sendSuccess/sendRedirect/sendHeadSuccess/sendError la seconda volta
		// provocherebbe un segmentation fault perchè probabilmente request.out è
		// stato resettato nella prima chiamata Questo controllo è una protezione
		// rispetto al segmentation fault
		SPDLOG_ERROR(
			"response was already done"
			", requestIdentifier: {}"
			", threadId: {}"
			", requestURI: {}"
			", requestMethod: {}"
			", responseBody.size: @{}@",
			requestIdentifier, sThreadId, requestURI, requestMethod, responseBody.size()
		);

		return;
	}

	string endLine = "\r\n";

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode, getHtmlStandardMessage(htmlResponseCode), endLine);

	string localContentType;
	if (!responseBody.empty())
	{
		if (contentType.empty())
			localContentType = std::format("Content-Type: application/json; charset=utf-8{}", endLine);
		else
			localContentType = std::format("{}{}", contentType, endLine);
	}

	string cookieHeader;
	if (!cookieName.empty() && !cookieValue.empty())
	{
		cookieHeader = std::format("Set-Cookie: {}={}", cookieName, cookieValue);

		if (!cookiePath.empty())
			cookieHeader += (std::format("; Path={}", cookiePath));

		cookieHeader += endLine;
	}

	string corsGETHeader;
	if (enableCorsGETHeader)
	{
		string origin = "*";
		if (!originHeader.empty())
			origin = originHeader;

		corsGETHeader = std::format(
			"Access-Control-Allow-Origin: {}{}"
			"Access-Control-Allow-Methods: GET, POST, OPTIONS{}"
			"Access-Control-Allow-Credentials: true{}"
			"Access-Control-Allow-Headers: "
			"DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,"
			"Content-Type,Range{}"
			"Access-Control-Expose-Headers: Content-Length,Content-Range{}",
			origin, endLine, endLine, endLine, endLine, endLine
		);
	}

	if (responseBodyCompressed)
	{
		string compressedResponseBody = Compressor::compress_string(responseBody);

		unsigned long contentLength = compressedResponseBody.size();

		string headResponse = std::format(
			"{}"
			"{}"
			"{}"
			"{}"
			"Content-Length: {}{}"
			"X-CompressedBody: true{}"
			"{}",
			httpStatus, localContentType, cookieHeader, corsGETHeader, contentLength,
			endLine, endLine, endLine
		);

		FCGX_FPrintF(request.out, headResponse.c_str());

		SPDLOG_INFO(
			"sendSuccess"
			", requestIdentifier: {}"
			", threadId: {}"
			", requestURI: {}"
			", requestMethod: {}"
			", headResponse.size: {}"
			", responseBody.size: @{}@"
			", compressedResponseBody.size: @{}@"
			", headResponse: {}",
			requestIdentifier, sThreadId, requestURI, requestMethod, headResponse.size(), responseBody.size(), contentLength, headResponse
		);

		FCGX_PutStr(compressedResponseBody.data(), compressedResponseBody.size(), request.out);
	}
	else
	{
		string completeHttpResponse;

		// 2020-02-08: content length has to be calculated before the substitution
		// from % to %% because for FCGX_FPrintF (below used) %% is just one
		// character
		unsigned long contentLength = responseBody.length();

		// responseBody cannot have the '%' char because FCGX_FPrintF will not work
		if (responseBody.find('%') != string::npos)
		{
			string toBeSearched = "%";
			string replacedWith = "%%";
			string newResponseBody = StringUtils::replaceAll(responseBody, toBeSearched, replacedWith);

			completeHttpResponse = std::format(
				"{}"
				"{}"
				"{}"
				"{}"
				"Content-Length: {}{}"
				"{}"
				"{}",
				httpStatus, localContentType, cookieHeader, corsGETHeader, contentLength, endLine, endLine, newResponseBody
			);
		}
		else
		{
			completeHttpResponse = std::format(
				"{}"
				"{}"
				"{}"
				"{}"
				"Content-Length: {}{}"
				"{}"
				"{}",
				httpStatus, localContentType, cookieHeader, corsGETHeader, contentLength, endLine, endLine, responseBody
			);
		}

		if (!requestURI.ends_with("/status"))
			SPDLOG_INFO(
				"sendSuccess"
				", requestIdentifier: {}"
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}"
				", responseBody.size: @{}@"
				", httpStatus: {}",
				// ", completeHttpResponse: {}", spesso la response è troppo lunga, per cui logghiamo solo httpStatus
				requestIdentifier, sThreadId, requestURI, requestMethod, responseBody.size(), httpStatus //, completeHttpResponse
			);

		// si potrebbe usare anche FCGX_PutStr, in questo caso
		// non bisogna gestire %% (vedi sopra)
		// FCGX_PutStr(responseBody.data(), responseBody.size(), request.out);
		FCGX_FPrintF(request.out, completeHttpResponse.c_str());
	}

	FCGX_Finish_r(&request);
	_fcgxFinishDone = true;
}

void FastCGIAPI::sendRedirect(FCGX_Request &request, const string_view& locationURL, bool permanently, const string_view& contentType)
{
	if (_fcgxFinishDone)
	{
		// se viene chiamato due volte
		// sendSuccess/sendRedirect/sendHeadSuccess/sendError la seconda volta
		// provocherebbe un segmentation fault perchè probabilmente request.out è
		// stato resettato nella prima chiamata Questo controllo è una protezione
		// rispetto al segmentation fault
		SPDLOG_ERROR("response was already done");

		return;
	}

	string endLine = "\r\n";

	int htmlResponseCode = permanently ? 301 : 302;

	string completeHttpResponse = std::format(
		"Status: {} {}{}"
		"Location: {}{}",
		htmlResponseCode, getHtmlStandardMessage(htmlResponseCode), endLine, locationURL, endLine
	);
	if (!contentType.empty())
		completeHttpResponse += std::format("Content-Type: {}{}{}", contentType, endLine, endLine);
	else
		completeHttpResponse += endLine;

	SPDLOG_INFO(
		"HTTP Success"
		", response: {}",
		completeHttpResponse
	);

	FCGX_FPrintF(request.out, completeHttpResponse.c_str());

	FCGX_Finish_r(&request);
	_fcgxFinishDone = true;
}

void FastCGIAPI::sendHeadSuccess(FCGX_Request &request, int htmlResponseCode, unsigned long fileSize)
{
	if (_fcgxFinishDone)
	{
		// se viene chiamato due volte
		// sendSuccess/sendRedirect/sendHeadSuccess/sendError la seconda volta
		// provocherebbe un segmentation fault perchè probabilmente request.out è
		// stato resettato nella prima chiamata Questo controllo è una protezione
		// rispetto al segmentation fault
		SPDLOG_ERROR("response was already done");

		return;
	}

	string endLine = "\r\n";

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode, getHtmlStandardMessage(htmlResponseCode), endLine);

	string completeHttpResponse = std::format(
		"{}"
		"Content-Range: bytes 0-{}{}{}",
		httpStatus, fileSize, endLine, endLine
	);

	SPDLOG_INFO(
		"HTTP HEAD Success"
		", response: {}",
		completeHttpResponse
	);

	FCGX_FPrintF(request.out, completeHttpResponse.c_str());

	FCGX_Finish_r(&request);
	_fcgxFinishDone = true;
}

void FastCGIAPI::sendHeadSuccess(int htmlResponseCode, unsigned long fileSize)
{
	string endLine = "\r\n";

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode, getHtmlStandardMessage(htmlResponseCode), endLine);

	string completeHttpResponse = std::format(
		"{}"
		"X-CatraMMS-Resume: {}{}"
		"{}",
		httpStatus, fileSize, endLine, endLine
	);

	SPDLOG_INFO(
		"HTTP HEAD Success"
		", response: {}",
		completeHttpResponse
	);
}

void FastCGIAPI::sendError(FCGX_Request &request, int htmlResponseCode, const string_view& responseBody)
{
	if (_fcgxFinishDone)
	{
		// se viene chiamato due volte
		// sendSuccess/sendRedirect/sendHeadSuccess/sendError la seconda volta
		// provocherebbe un segmentation fault perchè probabilmente request.out è
		// stato resettato nella prima chiamata Questo controllo è una protezione
		// rispetto al segmentation fault
		SPDLOG_ERROR("response was already done");

		return;
	}

	string endLine = "\r\n";

	unsigned long contentLength;
	string localResponseBody;

	// string responseBody;
	// errorMessage cannot have the '%' char because FCGX_FPrintF will not work
	if (responseBody.find('%') != string::npos)
	{
		// 2020-02-08: content length has to be calculated before the substitution
		// from % to %% because for FCGX_FPrintF (below used) %% is just one
		// character
		contentLength = responseBody.length();

		const string toBeSearched = "%";
		const string replacedWith = "%%";
		localResponseBody = StringUtils::replaceAll(responseBody, toBeSearched, replacedWith);
	}
	else
	{
		contentLength = responseBody.length();
		localResponseBody = responseBody;
	}

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode, getHtmlStandardMessage(htmlResponseCode), endLine);

	string completeHttpResponse = std::format(
		"{}"
		"Content-Type: application/json; charset=utf-8{}"
		"Content-Length: {}{}"
		"{}"
		"{}",
		httpStatus, endLine, contentLength, endLine, endLine, localResponseBody
	);

	SPDLOG_INFO(
		"HTTP Error"
		", response: {}",
		completeHttpResponse
	);

	FCGX_FPrintF(request.out, completeHttpResponse.c_str());

	FCGX_Finish_r(&request);
	_fcgxFinishDone = true;
}

string FastCGIAPI::getClientIPAddress(const unordered_map<string, string> &requestDetails)
{

	string clientIPAddress;

	// REMOTE_ADDR is the address of the load balancer
	// auto remoteAddrIt = requestDetails.find("REMOTE_ADDR");
	auto remoteAddrIt = requestDetails.find("HTTP_X_FORWARDED_FOR");
	if (remoteAddrIt != requestDetails.end())
		clientIPAddress = remoteAddrIt->second;

	return clientIPAddress;
}

void FastCGIAPI::parseContentRange(string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd, uint64_t &contentRangeSize)
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

string FastCGIAPI::getHtmlStandardMessage(int htmlResponseCode)
{
	switch (htmlResponseCode)
	{
	case 200:
		return {"OK"};
	case 201:
		return {"Created"};
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

/*
int32_t FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, int32_t defaultParameter, bool mandatory, bool *isParamPresent
)
{

	int32_t parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		parameterValue = stol(it->second);
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = defaultParameter;
	}

	return parameterValue;
}


int32_t FastCGIAPI::getMapParameter(
	const unordered_map<string, string> &mapParameters, string parameterName, int32_t defaultParameter, bool mandatory, bool *isParamPresent
)
{
	int32_t parameterValue;

	auto it = mapParameters.find(parameterName);
	if (it != mapParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		parameterValue = stol(it->second);
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = defaultParameter;
	}

	return parameterValue;
}

int64_t FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, int64_t defaultParameter, bool mandatory, bool *isParamPresent
)
{

	int64_t parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		parameterValue = stoll(it->second);
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = defaultParameter;
	}

	return parameterValue;
}

bool FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, bool defaultParameter, bool mandatory, bool *isParamPresent
)
{

	bool parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		parameterValue = it->second == "true";
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = defaultParameter;
	}

	return parameterValue;
}

string FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, string defaultParameter, bool mandatory, bool *isParamPresent
)
{

	string parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		parameterValue = it->second;

		// 2021-01-07: Remark: we have FIRST to replace + in space and then apply
		// unescape
		//	That  because if we have really a + char (%2B into the string), and we
		// do the replace 	after unescape, this char will be changed to space and we
		// do not want it
		string plus = "\\+";
		string plusDecoded = " ";
		string firstDecoding = regex_replace(parameterValue, regex(plus), plusDecoded);

		parameterValue = unescape(firstDecoding);
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = std::move(defaultParameter);
	}

	return parameterValue;
}

string FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, const string &parameterName, const char *defaultParameter, bool mandatory,
	bool *isParamPresent
)
{
	return getQueryParameter(queryParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
}

vector<int32_t> FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<int32_t> defaultParameter, bool mandatory,
	bool *isParamPresent
)
{
	vector<int32_t> parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		stringstream ss(it->second);
		string token;
		while (getline(ss, token, delim))
		{
			if (!token.empty())
				parameterValue.push_back(stol(token));
		}
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = std::move(defaultParameter);
	}

	return parameterValue;
}

vector<int64_t> FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<int64_t> defaultParameter, bool mandatory,
	bool *isParamPresent
)
{
	vector<int64_t> parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		stringstream ss(it->second);
		string token;
		while (getline(ss, token, delim))
		{
			if (!token.empty())
				parameterValue.push_back(stoll(token));
		}
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = std::move(defaultParameter);
	}

	return parameterValue;
}

vector<string> FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<string> defaultParameter, bool mandatory,
	bool *isParamPresent
)
{
	vector<string> parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		stringstream ss(it->second);
		string token;
		while (getline(ss, token, delim))
		{
			if (!token.empty())
				parameterValue.push_back(token);
		}
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = std::move(defaultParameter);
	}

	return parameterValue;
}

set<string> FastCGIAPI::getQueryParameter(
	const unordered_map<string, string> &queryParameters, string parameterName, char delim, set<string> defaultParameter, bool mandatory,
	bool *isParamPresent
)
{
	set<string> parameterValue;

	auto it = queryParameters.find(parameterName);
	if (it != queryParameters.end() && !it->second.empty())
	{
		if (isParamPresent != nullptr)
			*isParamPresent = true;
		stringstream ss(it->second);
		string token;
		while (getline(ss, token, delim))
		{
			if (!token.empty())
				parameterValue.insert(token);
		}
	}
	else
	{
		if (isParamPresent != nullptr)
			*isParamPresent = false;
		if (mandatory)
		{
			string errorMessage = std::format("The {} query parameter is missing", parameterName);
			SPDLOG_ERROR(errorMessage);

			throw runtime_error(errorMessage);
		}

		parameterValue = std::move(defaultParameter);
	}

	return parameterValue;
}
*/

void FastCGIAPI::fillEnvironmentDetails(const char *const *envp, unordered_map<string, string> &requestDetails)
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

		requestDetails[key] = value;

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
}

void FastCGIAPI::fillQueryString(const string& queryString, unordered_map<string, string> &queryParameters)
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

			queryParameters[key] = value;

			SPDLOG_TRACE(
				"Query parameter"
				", key/Name: {}={}",
				key, value
			);
		}
	}
}

// #define BOOTSERVICE_DEBUG_LOG

json FastCGIAPI::loadConfigurationFile(const string& configurationPathName, const string& environmentPrefix)
{

#ifdef BOOTSERVICE_DEBUG_LOG
	ofstream of("/tmp/bootservice.log", ofstream::app);
	of << "loadConfigurationFile..." << endl;
#endif

	string sConfigurationFile;
	{
		ifstream configurationFile(configurationPathName, ifstream::binary);
		stringstream buffer;
		buffer << configurationFile.rdbuf();
		if (environmentPrefix.empty())
			sConfigurationFile = buffer.str();
		else
			sConfigurationFile = FastCGIAPI::applyEnvironmentToConfiguration(buffer.str(), environmentPrefix);
	}

	json configurationRoot = json::parse(
		sConfigurationFile,
		nullptr, // callback
		true,	 // allow exceptions
		true	 // ignore_comments
	);

	return configurationRoot;
}

string FastCGIAPI::applyEnvironmentToConfiguration(string configuration, const string& environmentPrefix)
{
	char **s = environ;

#ifdef BOOTSERVICE_DEBUG_LOG
	ofstream of("/tmp/bootservice.log", ofstream::app);
#endif

	int envNumber = 0;
	for (; *s; s++)
	{
		string envVariable = *s;
#ifdef BOOTSERVICE_DEBUG_LOG
//					of << "ENV " << *s << endl;
#endif
		if (envVariable.starts_with(environmentPrefix))
		{
			size_t endOfVarName = envVariable.find('=');
			if (endOfVarName == string::npos)
				continue;

			envNumber++;

			// sarebbe \$\{ZORAC_SOLR_PWD\}
			string envLabel = std::format(R"(\$\{{{}\}})", envVariable.substr(0, endOfVarName));
			string envValue = envVariable.substr(endOfVarName + 1);
#ifdef BOOTSERVICE_DEBUG_LOG
			of << "ENV " << envLabel << ": " << envValue << endl;
#endif
			configuration = regex_replace(configuration, regex(envLabel), envValue);
		}
	}

	return configuration;
}

string FastCGIAPI::base64_encode(const string &in)
{
	string out;

	int val = 0, valb = -6;
	for (unsigned char c : in)
	{
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0)
		{
			out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
		out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4)
		out.push_back('=');
	return out;
}

string FastCGIAPI::base64_decode(const string &in)
{
	string out;

	vector<int> T(256, -1);
	for (int i = 0; i < 64; i++)
		T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in)
	{
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}
