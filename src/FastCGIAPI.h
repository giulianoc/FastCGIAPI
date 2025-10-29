
#ifndef FastCGIAPI_h
#define FastCGIAPI_h

#include "../../StringUtils/src/StringUtils.h"
#include "fcgi_config.h"
#include "fcgi_stdio.h"
#include "nlohmann/json.hpp"
#include <set>
#include <stdlib.h>
#include <unordered_map>
#include <vector>

using namespace std;

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
using namespace nlohmann::literals;


struct CheckAuthorizationFailed : public exception
{
	char const *what() const throw() override { return "Wrong Basic Authentication present into the Request"; };
};

class FastCGIAPI
{
  public:
	using Handler = function<void(
		const string&, // sThreadId
		int64_t, // requestIdentifier
		FCGX_Request &, // request
		const string&, // requestURI
		const string&, // requestMethod
		const string&, // requestBody
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
		const string& sThreadId, int64_t requestIdentifier, bool responseBodyCompressed, FCGX_Request &request,
		const string& requestURI, const string& requestMethod,
		const unordered_map<string, string>& queryParameters,
		bool basicAuthenticationPresent, const string& userName, const string& password, unsigned long contentLength,
		const string& requestBody, const unordered_map<string, string> &requestDetails
	) = 0;

	virtual void handleRequest(
		const string &sThreadId, int64_t requestIdentifier, FCGX_Request &request, const string &requestURI, const string &requestMethod,
		const string &requestBody, const unordered_map<std::string, std::string> &requestDetails,
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
		string sThreadId, int64_t requestIdentifier, bool responseBodyCompressed, FCGX_Request &request, string requestURI, string requestMethod,
		int htmlResponseCode, string responseBody = "", string contentType = "", string cookieName = "", string cookieValue = "",
		const string& cookiePath= "", bool enableCorsGETHeader = false, const string& originHeader = ""
	);
	void sendRedirect(FCGX_Request &request, string locationURL, bool permanently, string contentType = "");
	void sendHeadSuccess(FCGX_Request &request, int htmlResponseCode, unsigned long fileSize);
	static void sendHeadSuccess(int htmlResponseCode, unsigned long fileSize);
	virtual void sendError(FCGX_Request &request, int htmlResponseCode, string errorMessage);
	// void sendError(int htmlResponseCode, string errorMessage);

	static string getClientIPAddress(const unordered_map<string, string> &requestDetails);

	/*
	static int32_t getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, int32_t defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static int32_t getMapParameter(
		const unordered_map<string, string> &mapParameters, string parameterName, int32_t defaultParameter, bool mandatory, bool *isParamPresent
	);
	static int64_t getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, int64_t defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static bool getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, bool defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static string getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, string defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static string getQueryParameter(
		const unordered_map<string, string> &queryParameters, const string &parameterName, const char *defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static vector<int32_t> getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<int32_t> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static vector<int64_t> getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<int64_t> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static vector<string> getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, char delim, vector<string> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	static set<string> getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, char delim, set<string> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	);
	*/


	static string getHeaderParameter(
		const unordered_map<string, string> &mapParameters, const string &headerName, const char *defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getHeaderParameter(mapParameters, headerName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getHeaderParameter(
		const unordered_map<string, string> &mapParameters, string headerName, T defaultParameter, bool mandatory, bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, std::format("HTTP_{}",
			StringUtils::replaceAll(StringUtils::upperCase(headerName), "-", "_")),
			string(defaultParameter), mandatory, isParamPresent);
	}

	static string getQueryParameter(
		const unordered_map<string, string> &mapParameters, const string &parameterName, const char *defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getQueryParameter(
		const unordered_map<string, string> &mapParameters, string parameterName, T defaultParameter, bool mandatory, bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	static C<T> getQueryParameter(
		const unordered_map<string, string> &mapParameters, string parameterName, char delim, C<T> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, delim, defaultParameter, mandatory, isParamPresent);
	}

	static string getMapParameter(
		const unordered_map<string, string> &mapParameters, const string &parameterName, const char *defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	static T getMapParameter(
		const unordered_map<string, string> &mapParameters, string parameterName, T defaultParameter, bool mandatory, bool *isParamPresent = nullptr
	)
	{
		T parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if (isParamPresent != nullptr)
				*isParamPresent = true;
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

			parameterValue = defaultParameter;
		}

		return parameterValue;
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	static C<T> getMapParameter(
		const unordered_map<string, string> &mapParameters, string parameterName, char delim, C<T> defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		vector<T> parameterValue;

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

	static string getHtmlStandardMessage(int htmlResponseCode);

  private:
	static void fillEnvironmentDetails(const char *const *envp, unordered_map<string, string> &requestDetails);

	static void fillQueryString(const string &queryString, unordered_map<string, string> &queryParameters);

	static string base64_encode(const string &in);

	static string base64_decode(const string &in);
};

#endif
