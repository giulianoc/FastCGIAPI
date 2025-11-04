
#pragma once

#include <set>
#include <unordered_map>
#include <vector>
#include "StringUtils.h"
#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif
#include "spdlog/spdlog.h"
#include "JSONUtils.h"
#include "fcgi_stdio.h"

using namespace std;


struct CheckAuthorizationFailed : public exception
{
	char const *what() const throw() override { return "Wrong Basic Authentication present into the Request"; };
};

class FastCGIAPI
{
  public:
	using Handler = function<void(
		const string_view&, // sThreadId
		int64_t, // requestIdentifier
		FCGX_Request &, // request
		const string_view&, // requestURI
		const string_view&, // requestMethod
		const string_view&, // requestBody
		bool, // responseBodyCompressed
		const unordered_map<string, string>&, // requestDetails
		const unordered_map<string, string>& // queryParameters
	)>;

	FastCGIAPI(const json& configuration, mutex *fcgiAcceptMutex);

	void init(const json &configuration, mutex *fcgiAcceptMutex);

	virtual ~FastCGIAPI();

	static string escape(const string &url);
	static string unescape(const string &url);

	virtual void loadConfiguration(json configurationRoot);

	int operator()();

	virtual void stopFastcgi();

	// static json loadConfigurationFile(const char *configurationPathName);
	static json loadConfigurationFile(const string& configurationPathName, const string& environmentPrefix);
	static string applyEnvironmentToConfiguration(string configuration, const string& environmentPrefix);

	static string getHeaderParameter(
		const unordered_map<string, string> &mapParameters, const string& headerName, const char *defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getHeaderParameter(mapParameters, headerName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getHeaderParameter(
		const unordered_map<string, string> &mapParameters, const string& headerName, T defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, std::format("HTTP_{}",
			StringUtils::replaceAll(StringUtils::upperCase(headerName), "-", "_")),
			string(defaultParameter), mandatory, isParamPresent);
	}

	static string getQueryParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, const char *defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getQueryParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, T defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	static C<T> getQueryParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, char delim, C<T> defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, delim, defaultParameter, mandatory, isParamPresent);
	}

	static string getMapParameter(
		const unordered_map<string, string> &mapParameters, const string &parameterName, const char *defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getMapParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, T defaultParameter, const bool mandatory,
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
				string errorMessage = std::format("The {} query parameter is missing", parameterName);
				SPDLOG_ERROR(errorMessage);

				throw runtime_error(errorMessage);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	static C<T> getMapParameter(
		const unordered_map<string, string> &mapParameters, const string& parameterName, char delim, C<T> defaultParameter, const bool mandatory,
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
				string errorMessage = std::format("The {} query parameter is missing", parameterName);
				SPDLOG_ERROR(errorMessage);

				throw runtime_error(errorMessage);
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

	unordered_map<std::string, Handler> _handlers;

	virtual void manageRequestAndResponse(
		const string_view& sThreadId, int64_t requestIdentifier, bool responseBodyCompressed, FCGX_Request &request,
		const string_view& requestURI, const string_view& requestMethod,
		const unordered_map<string, string>& queryParameters,
		bool basicAuthenticationPresent, const string_view& userName, const string_view& password, unsigned long contentLength,
		const string_view& requestBody, const unordered_map<string, string> &requestDetails
	) = 0;

	virtual void handleRequest(
		const string_view &sThreadId, int64_t requestIdentifier, FCGX_Request &request, const string_view &requestURI,
		const string_view &requestMethod, const string_view &requestBody, bool responseBodyCompressed,
		const unordered_map<std::string, std::string> &requestDetails,
		const unordered_map<std::string, std::string> &queryParameters
	);

	template <typename Derived, typename Method>
	void registerHandler(const std::string& name, Method method)
	{
		_handlers[name] = [this, method](
			const std::string& sThreadId, int64_t requestIdentifier, FCGX_Request& request,
			const std::string& requestURI, const std::string& requestMethod,
			const std::string& requestBody, const std::unordered_map<std::string, std::string>& requestDetails,
			const std::unordered_map<std::string, std::string>& queryParameters)
		{
			// Chiama il metodo membro specificato
			(static_cast<Derived*>(this)->*method)(sThreadId, requestIdentifier, request,
				requestURI, requestMethod, requestBody, requestDetails, queryParameters);
		};
	}

	virtual void checkAuthorization(const string& sThreadId, const string& userName, const string& password) = 0;

	virtual bool basicAuthenticationRequired(const string &requestURI, const unordered_map<string, string> &queryParameters);

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

	static string getClientIPAddress(const unordered_map<string, string> &requestDetails);

	static string getHtmlStandardMessage(int htmlResponseCode);

  private:
	static void fillEnvironmentDetails(const char *const *envp, unordered_map<string, string> &requestDetails);

	static void fillQueryString(const string &queryString, unordered_map<string, string> &queryParameters);

	static string base64_encode(const string &in);

	static string base64_decode(const string &in);
};
