
#pragma once

#include <unordered_map>
#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif
#include "spdlog/spdlog.h"
#include "FCGIRequestData.h"
#include "JSONUtils.h"
// #include "fcgi_stdio.h"


class FastCGIAPI
{
  public:

	using Handler = std::function<void(
		const std::string_view&, // sThreadId
		FCGX_Request &, // request
		const FCGIRequestData& // requestData
	)>;

	virtual void stopFastcgi();

	int operator()();

protected:

	FastCGIAPI(const nlohmann::json& configuration, std::mutex *fcgiAcceptMutex);

	void init(const nlohmann::json &configuration, std::mutex *fcgiAcceptMutex);

	virtual ~FastCGIAPI();

  protected:
	// ATTENZIONE, questa architettura è thread-safe ma NON request-safe perchè:
	//	- thread-safe: ogni thread ha la sua istanza di FastCGIAPI
	//	- non è request-safe: ogni richiesta NON ha la sua istanza di FastCGIAPI (1 istanza di FastCGIAPI gestisce N richieste)
	// Lo stato memorizzato nei campi di FastCGIAPI viene riusato da più richieste,
	// QUINDI non aggiungere qui campi per la singola richiesta
	bool _shutdown{};

	bool _fcgxFinishDone{};

	std::string _hostName;
	int64_t _maxAPIContentLength{};
	std::mutex *_fcgiAcceptMutex{};

	std::unordered_map<std::string, Handler> _handlers;

	virtual void manageRequestAndResponse(const std::string_view& sThreadId, FCGX_Request &request, const FCGIRequestData& requestData) = 0;

	virtual bool handleRequest(const std::string_view &sThreadId, FCGX_Request &request,
		const FCGIRequestData &requestData, bool exceptionIfNotManaged);

	template <typename F>
	void registerHandler(const std::string& name, F&& f)
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

	virtual std::shared_ptr<FCGIRequestData::AuthorizationDetails> checkAuthorization(const std::string_view& sThreadId,
		const FCGIRequestData& requestData, const std::string_view& userName, const std::string_view& password) = 0;

	virtual bool basicAuthenticationRequired(const FCGIRequestData& requestData);

	void sendSuccess(
		const std::string_view& sThreadId, bool responseBodyCompressed, FCGX_Request &request, const std::string_view& requestURI,
		const std::string_view& requestMethod, int htmlResponseCode, const std::string_view& responseBody = "", const std::string_view& contentType = "",
		const std::string_view& cookieName = "", const std::string_view& cookieValue = "",
		const std::string_view& cookiePath= "", bool enableCorsGETHeader = false, const std::string_view& originHeader = ""
	);
	void sendRedirect(FCGX_Request &request, const std::string_view& locationURL, bool permanently, const std::string_view& contentType = "");
	void sendHeadSuccess(FCGX_Request &request, int htmlResponseCode, unsigned long fileSize);
	static void sendHeadSuccess(int htmlResponseCode, unsigned long fileSize);
	virtual void sendError(FCGX_Request &request, int htmlResponseCode, const std::string_view& errorMessage);
	// void sendError(int htmlResponseCode, string errorMessage);

  private:
	void loadConfiguration(nlohmann::json configurationRoot);

	static std::string base64_encode(const std::string &in);

	static std::string base64_decode(const std::string &in);
};