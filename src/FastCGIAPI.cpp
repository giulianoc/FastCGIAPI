
#include "Compressor.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <utility>
#include <sys/utsname.h>
#include <curl/curl.h>
//
#include "FastCGIAPI.h" // has to be the last one otherwise errors...

extern char **environ;

FastCGIAPI::FastCGIAPI(const json& configurationRoot, mutex *fcgiAcceptMutex) { init(configurationRoot, fcgiAcceptMutex); }

FastCGIAPI::~FastCGIAPI() = default;

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
		int returnAcceptCode;
		{
			SPDLOG_TRACE(
				"FastCGIAPI::ready"
				", threadId: {}",
				sThreadId
			);
			lock_guard<mutex> locker(*_fcgiAcceptMutex);

			SPDLOG_TRACE(
				"FastCGIAPI::listen"
				", threadId: {}",
				sThreadId
			);

			if (_shutdown)
				continue;

			returnAcceptCode = FCGX_Accept_r(&request);
		}
		SPDLOG_TRACE(
			"FCGX_Accept_r"
			", threadId: {}"
			", returnAcceptCode: {}",
			sThreadId, returnAcceptCode
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
			", threadId: {}",
			sThreadId
		);

		FCGIRequestData requestData;
		try
		{
			requestData.init(request, _maxAPIContentLength);
		}
		catch (exception &e)
		{
			SPDLOG_ERROR(e.what());

			sendError(request, 500, e.what());

			if (!_fcgxFinishDone)
				FCGX_Finish_r(&request);

			// throw runtime_error(errorMessage);
			continue;
		}

		bool authorizationPresent = basicAuthenticationRequired(requestData);
		if (authorizationPresent)
		{
			try
			{
				string authorization = requestData.getHeaderParameter("authorization", "", true);

				string authorizationPrefix = "Basic ";
				if (!authorization.starts_with(authorizationPrefix))
				{
					SPDLOG_ERROR(
						"No 'Basic' authorization is present into the request"
						", threadId: {}"
						", Authorization: {}",
						sThreadId, authorization
					);

					throw FCGIRequestData::HTTPError(401);
				}

				string usernameAndPasswordBase64 = authorization.substr(authorizationPrefix.length());
				string usernameAndPassword = base64_decode(usernameAndPasswordBase64);
				size_t userNameSeparator = usernameAndPassword.find(':');
				if (userNameSeparator == string::npos)
				{
					SPDLOG_ERROR(
						"Wrong Authorization format"
						", threadId: {}"
						", usernameAndPasswordBase64: {}"
						", usernameAndPassword: {}",
						sThreadId, usernameAndPasswordBase64, usernameAndPassword
					);

					throw FCGIRequestData::HTTPError(401);
				}

				string userName = usernameAndPassword.substr(0, userNameSeparator);
				string password = usernameAndPassword.substr(userNameSeparator + 1);

				requestData.authorizationDetails = checkAuthorization(sThreadId, requestData, userName, password);
			}
			catch (exception &e)
			{
				SPDLOG_ERROR(
					"checkAuthorization failed"
					", threadId: {}"
					", e.what(): {}",
					sThreadId, e.what()
				);

				int htmlResponseCode = 500;
				if (dynamic_cast<FCGIRequestData::HTTPError*>(&e))
					htmlResponseCode = dynamic_cast<FCGIRequestData::HTTPError*>(&e)->httpErrorCode;

				string errorMessage = FCGIRequestData::getHtmlStandardMessage(htmlResponseCode);
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
			manageRequestAndResponse(sThreadId, request, requestData);
		}
		catch (exception &e)
		{
			SPDLOG_ERROR(
				"manageRequestAndResponse failed"
				", threadId: {}"
				", exception: {}",
				sThreadId, e.what()
			);
		}
		{
			auto method = requestData.getQueryParameter("x-api-method", "", false);

			chrono::system_clock::time_point endManageRequest = chrono::system_clock::now();
			if (!requestData.requestURI.ends_with("/status"))
				SPDLOG_INFO(
					"manageRequestAndResponse"
					", threadId: {}"
					", clientIPAddress: @{}@"
					", method: @{}@"
					", requestURI: {}"
					", authorizationPresent: {}"
					", @MMS statistics@ - manageRequestDuration (millisecs): @{}@",
					sThreadId, requestData.clientIPAddress, method, requestData.requestURI, authorizationPresent,
					chrono::duration_cast<chrono::milliseconds>(endManageRequest - startManageRequest).count()
				);
		}

		SPDLOG_TRACE(
			"FastCGIAPI::request finished"
			", threadId: {}",
			sThreadId
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
	const string_view &sThreadId, FCGX_Request &request,
	const FCGIRequestData& requestData, const bool exceptionIfNotManaged)
{
	bool isParamPresent;
	const string method = requestData.getQueryParameter("x-api-method", "", false, &isParamPresent);
	if (!isParamPresent)
	{
		if (exceptionIfNotManaged)
		{
			string errorMessage = std::format(
				"request is not managed because 'x-api-method' is missing"
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}",
				sThreadId, requestData.requestURI, requestData.requestMethod);
			SPDLOG_ERROR(errorMessage);
			throw runtime_error(errorMessage);
		}
		return true; // request not managed
	}

	const auto handlerIt = _handlers.find(method);
	if (handlerIt == _handlers.end())
	{
		if (exceptionIfNotManaged)
		{
			string errorMessage = std::format(
				"request is not managed because no registration found for method {}"
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}",
				method, sThreadId, requestData.requestURI, requestData.requestMethod);
			SPDLOG_ERROR(errorMessage);
			throw runtime_error(errorMessage);
		}
		return true; // request not managed
	}

	handlerIt->second(sThreadId, request, requestData);

	return false;
}

void FastCGIAPI::stopFastcgi() { _shutdown = true; }

bool FastCGIAPI::basicAuthenticationRequired(const FCGIRequestData& requestData)
{
	bool basicAuthenticationRequired = true;

	return basicAuthenticationRequired;
}

void FastCGIAPI::sendSuccess(
	const string_view& sThreadId, bool responseBodyCompressed, FCGX_Request &request, const string_view& requestURI,
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
			", threadId: {}"
			", requestURI: {}"
			", requestMethod: {}"
			", responseBody.size: @{}@",
			sThreadId, requestURI, requestMethod, responseBody.size()
		);

		return;
	}

	string endLine = "\r\n";

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode,
		FCGIRequestData::getHtmlStandardMessage(htmlResponseCode), endLine);

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
			", threadId: {}"
			", requestURI: {}"
			", requestMethod: {}"
			", headResponse.size: {}"
			", responseBody.size: @{}@"
			", compressedResponseBody.size: @{}@"
			", headResponse: {}",
			sThreadId, requestURI, requestMethod, headResponse.size(), responseBody.size(), contentLength, headResponse
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
				", threadId: {}"
				", requestURI: {}"
				", requestMethod: {}"
				", responseBody.size: @{}@"
				", httpStatus: {}",
				// ", completeHttpResponse: {}", spesso la response è troppo lunga, per cui logghiamo solo httpStatus
				sThreadId, requestURI, requestMethod, responseBody.size(), httpStatus //, completeHttpResponse
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
		htmlResponseCode, FCGIRequestData::getHtmlStandardMessage(htmlResponseCode), endLine, locationURL, endLine
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

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode,
		FCGIRequestData::getHtmlStandardMessage(htmlResponseCode), endLine);

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

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode,
		FCGIRequestData::getHtmlStandardMessage(htmlResponseCode), endLine);

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

	string httpStatus = std::format("Status: {} {}{}", htmlResponseCode,
		FCGIRequestData::getHtmlStandardMessage(htmlResponseCode), endLine);

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