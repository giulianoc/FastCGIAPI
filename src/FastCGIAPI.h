
#pragma once

#include <set>
#include <unordered_map>
#include <utility>
#include <vector>
#include "StringUtils.h"
#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif
#include "spdlog/spdlog.h"
#include "JSONUtils.h"
#include "fcgi_stdio.h"

using namespace std;


class FastCGIAPI
{
  public:
	struct HTTPError final : runtime_error
	{
		int16_t httpErrorCode;
		explicit HTTPError(const int16_t httpErrorCode, const string& errorMessage = "") :
			runtime_error(errorMessage.empty() ? getHtmlStandardMessage(httpErrorCode) : errorMessage),
			httpErrorCode(httpErrorCode) {};
	};

	class AuthorizationDetails
	{
	public:
		string userName;
		string password;

		virtual ~AuthorizationDetails() = default;
	};

	using Handler = function<void(
		const string_view&, // sThreadId
		int64_t, // requestIdentifier
		FCGX_Request &, // request
		const shared_ptr<AuthorizationDetails>&, // authorizationDetails
		const string_view&, // requestURI
		const string_view&, // requestMethod
		const string_view&, // requestBody
		bool // responseBodyCompressed
	)>;

	virtual void stopFastcgi();

	int operator()();

	// static json loadConfigurationFile(const string& configurationPathName, const string& environmentPrefix);

protected:

	FastCGIAPI(const json& configuration, mutex *fcgiAcceptMutex);

	void init(const json &configuration, mutex *fcgiAcceptMutex);

	virtual ~FastCGIAPI();

	static string escape(const string &url);
	static string unescape(const string &url);

	static void parseContentRange(string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd, uint64_t &contentRangeSize);

	// static string applyEnvironmentToConfiguration(string configuration, const string& environmentPrefix);

	string getHeaderParameter(
		const string& headerName, const char *defaultParameter = "", const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		return getHeaderParameter(headerName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getHeaderParameter(
		const string& headerName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(_requestDetails, std::format("HTTP_{}",
			StringUtils::replaceAll(StringUtils::upperCase(headerName), "-", "_")),
			std::move(defaultParameter), mandatory, isParamPresent);
	}

	string getQueryParameter(
		const string& parameterName, const char *defaultParameter = "", const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getQueryParameter(
		const string& parameterName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(_queryParameters, parameterName, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	C<T> getQueryParameter(
		const string& parameterName, char delim, C<T> defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(_queryParameters, parameterName, delim, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T>
	optional<T> getOptHeaderParameter(
		const string& parameterName)
	{
		return getOptMapParameter<T>(_requestDetails, parameterName);
	}

	template <typename T>
	optional<T> getOptQueryParameter(
		const string& parameterName)
	{
		return getOptMapParameter<T>(_queryParameters, parameterName);
	}

	template <typename T>
	static optional<T> getOptMapParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName)
	{
		T parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if constexpr (std::is_same_v<T, std::string>)
			{
				// 2021-01-07: Remark: we have FIRST to replace + in space and then apply
				// unescape
				//	That  because if we have really a + char (%2B into the string), and we
				// do the replace 	after unescape, this char will be changed to space and we
				// do not want it
				string plus = "+";
				string plusDecoded = " ";
				const string firstDecoding = StringUtils::replaceAll(StringUtils::getValue<T>(it->second), plus, plusDecoded);

				return unescape(firstDecoding);
			}
			else
				parameterValue = StringUtils::getValue<T>(it->second);

			return parameterValue;
		}

		return nullopt;
	}

	static string getMapParameter(
		const unordered_map<string, string> &mapParameters, const string &parameterName, const char *defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	static T getMapParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		T parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if (isParamPresent != nullptr)
				*isParamPresent = true;
			if constexpr (std::is_same_v<T, std::string>)
			{
				// 2021-01-07: Remark: we have FIRST to replace + in space and then apply
				// unescape
				//	That  because if we have really a + char (%2B into the string), and we
				// do the replace 	after unescape, this char will be changed to space and we
				// do not want it
				string plus = "+";
				string plusDecoded = " ";
				const string firstDecoding = StringUtils::replaceAll(StringUtils::getValue<T>(it->second), plus, plusDecoded);

				return unescape(firstDecoding);
			}
			else
				parameterValue = StringUtils::getValue<T>(it->second);
		}
		else
		{
			if (isParamPresent != nullptr)
				*isParamPresent = false;
			if (mandatory)
			{
				SPDLOG_ERROR("Missing mandatory query parameter: {}", parameterName);
				throw HTTPError(400);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	static C<T> getMapParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, char delim, C<T> defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		C<T> parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if (isParamPresent != nullptr)
				*isParamPresent = true;
			stringstream ss(it->second);
			string token;
			while (getline(ss, token, delim))
			{
				if (!token.empty())
				{
					if constexpr (is_same_v<C<T>, vector<T>>)
						parameterValue.push_back(StringUtils::getValue<T>(token));
					else
						parameterValue.insert(StringUtils::getValue<T>(token));
				}
			}
		}
		else
		{
			if (isParamPresent != nullptr)
				*isParamPresent = false;
			if (mandatory)
			{
				SPDLOG_ERROR("Missing mandatory query parameter: {}", parameterName);
				throw HTTPError(400);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}

  protected:
	bool _shutdown{};
	// json _configurationRoot;

	bool _fcgxFinishDone{};

	int64_t _requestIdentifier{};
	string _hostName;
	int64_t _maxAPIContentLength{};
	mutex *_fcgiAcceptMutex{};

	unordered_map<string, string> _requestDetails{};
	unordered_map<string, string> _queryParameters{};

	unordered_map<std::string, Handler> _handlers;

	virtual void manageRequestAndResponse(
		const string_view& sThreadId, int64_t requestIdentifier, FCGX_Request &request,
		const shared_ptr<AuthorizationDetails>& authorizationDetails, const string_view& requestURI, const string_view& requestMethod,
		const string_view& requestBody, bool responseBodyCompressed, unsigned long contentLength
	) = 0;

	virtual bool handleRequest(
		const string_view &sThreadId, int64_t requestIdentifier, FCGX_Request &request,
		const shared_ptr<AuthorizationDetails>& authorizationDetails, const string_view &requestURI,
		const string_view &requestMethod, const string_view &requestBody, bool responseBodyCompressed,
		bool exceptionIfNotManaged
	);

	template <typename Derived, typename Method>
	void registerHandler(const string& name, Method method)
	{
		_handlers[name] = [this, method](
			const string_view& sThreadId, int64_t requestIdentifier, FCGX_Request& request,
			const shared_ptr<AuthorizationDetails>& authorizationDetails, const string_view& requestURI, const string_view& requestMethod,
			const string_view& requestBody, bool responseBodyCompressed)
		{
			// Chiama il metodo membro specificato
			(static_cast<Derived*>(this)->*method)(sThreadId, requestIdentifier, request, authorizationDetails,
				requestURI, requestMethod, requestBody, responseBodyCompressed);
		};
	}

	virtual shared_ptr<AuthorizationDetails> checkAuthorization(const string_view& sThreadId, const string_view& userName, const string_view& password) = 0;

	virtual bool basicAuthenticationRequired(const string &requestURI);

	void sendSuccess(
		const string_view& sThreadId, int64_t requestIdentifier, bool responseBodyCompressed, FCGX_Request &request, const string_view& requestURI,
		const string_view& requestMethod, int htmlResponseCode, const string_view& responseBody = "", const string_view& contentType = "",
		const string_view& cookieName = "", const string_view& cookieValue = "",
		const string_view& cookiePath= "", bool enableCorsGETHeader = false, const string_view& originHeader = ""
	);
	void sendRedirect(FCGX_Request &request, const string_view& locationURL, bool permanently, const string_view& contentType = "");
	void sendHeadSuccess(FCGX_Request &request, int htmlResponseCode, unsigned long fileSize);
	static void sendHeadSuccess(int htmlResponseCode, unsigned long fileSize);
	virtual void sendError(FCGX_Request &request, int htmlResponseCode, const string_view& errorMessage);
	// void sendError(int htmlResponseCode, string errorMessage);

	string getClientIPAddress();

	static string getHtmlStandardMessage(int htmlResponseCode);

  private:
	void loadConfiguration(json configurationRoot);
	void fillEnvironmentDetails(const char *const *envp);

	void fillQueryString(const string &queryString);

	static string base64_encode(const string &in);

	static string base64_decode(const string &in);
};
