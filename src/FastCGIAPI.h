
#ifndef FastCGIAPI_h
#define FastCGIAPI_h

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
	char const *what() const throw() { return "Wrong Basic Authentication present into the Request"; };
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

	virtual void handleRequest(const string &sThreadId,
	   int64_t requestIdentifier,
	   FCGX_Request &request,
	   const string& requestURI,
	   const string& requestMethod,
	   const string& requestBody,
	   const unordered_map<std::string, std::string> &queryParameters);

	template <typename Derived, typename Method>
	void registerHandler(const std::string& name, Method method)
	{
		_handlers[name] = [this, method](
			const std::string& sThreadId, int64_t requestIdentifier, FCGX_Request& request,
			const std::string& requestURI, const std::string& requestMethod,
			const std::string& requestBody, const std::unordered_map<std::string, std::string>& queryParameters)
		{
			// Chiama il metodo membro specificato
			(static_cast<Derived*>(this)->*method)(sThreadId, requestIdentifier, request,
							requestURI, requestMethod, requestBody, queryParameters);
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

	static int32_t getQueryParameter(
		const unordered_map<string, string> &queryParameters, string parameterName, int32_t defaultParameter, bool mandatory,
		bool *isParamPresent = nullptr
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

	static string getHtmlStandardMessage(int htmlResponseCode);

  private:
	static void fillEnvironmentDetails(const char *const *envp, unordered_map<string, string> &requestDetails);

	static void fillQueryString(const string& queryString, unordered_map<string, string> &queryParameters);

	static string base64_encode(const string &in);

	static string base64_decode(const string &in);
};

#endif
