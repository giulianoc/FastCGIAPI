
#pragma once

#include <unordered_map>
#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif
#include "spdlog/spdlog.h"
#include "FCGIRequestData.h"
#include "JSONUtils.h"
// #include "fcgi_stdio.h"

using namespace std;


class FastCGIAPI
{
  public:

	using Handler = function<void(
		const string_view&, // sThreadId
		int64_t, // requestIdentifier
		FCGX_Request &, // request
		const FCGIRequestData& // requestData
	)>;

	virtual void stopFastcgi();

	int operator()();

protected:

	FastCGIAPI(const json& configuration, mutex *fcgiAcceptMutex);

	void init(const json &configuration, mutex *fcgiAcceptMutex);

	virtual ~FastCGIAPI();

  protected:
	bool _shutdown{};

	bool _fcgxFinishDone{};

	int64_t _requestIdentifier{};
	string _hostName;
	int64_t _maxAPIContentLength{};
	mutex *_fcgiAcceptMutex{};

	unordered_map<std::string, Handler> _handlers;

	virtual void manageRequestAndResponse(
		const string_view& sThreadId, int64_t requestIdentifier, FCGX_Request &request,
		const FCGIRequestData& requestData) = 0;

	virtual bool handleRequest(
		const string_view &sThreadId, int64_t requestIdentifier, FCGX_Request &request, const FCGIRequestData &requestData, bool exceptionIfNotManaged
	);

	template <typename F>
	void registerHandler(const string& name, F&& f)
	{
		_handlers[name] = std::forward<F>(f);
	}
	/*
	template <typename Derived, typename Method>
	void registerHandler(const string& name, Method method)
	{
	// Il cast avviene una sola volta, se this non è Derived, il bug è immediato e riproducibile
	auto* self = static_cast<Derived*>(this);

	_handlers[name] = [self, method](
		const string_view& sThreadId, int64_t requestIdentifier,
		FCGX_Request& request, const FCGIRequestData& requestData)
		{
			// Chiama il metodo membro specificato
			(self->*method)(sThreadId, requestIdentifier, request, requestData);
		};
	}
	*/

	virtual shared_ptr<FCGIRequestData::AuthorizationDetails> checkAuthorization(const string_view& sThreadId,
		const string_view& userName, const string_view& password) = 0;

	virtual bool basicAuthenticationRequired(const FCGIRequestData& requestData);

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

  private:
	void loadConfiguration(json configurationRoot);

	static string base64_encode(const string &in);

	static string base64_decode(const string &in);
};