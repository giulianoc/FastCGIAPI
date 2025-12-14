//
// Created by Giuliano on 13.12.2025.
//

#pragma once

#include "StringUtils.h"
#ifndef SPDLOG_ACTIVE_LEVEL
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif
#include "spdlog/spdlog.h"
#include <fcgiapp.h>
#include <string>
#include <unordered_map>
#include <set>

using namespace std;

class FCGIRequestData final
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

	string requestMethod;
	string requestBody;
	unsigned long contentLength;
	string requestURI;
	shared_ptr<AuthorizationDetails> authorizationDetails;
	bool responseBodyCompressed;
	string clientIPAddress;

	virtual ~FCGIRequestData() = default;
	void init(const FCGX_Request & request, int64_t& maxAPIContentLength);

	static string getHtmlStandardMessage(int htmlResponseCode);

	static string escape(const string &url);
	static string unescape(const string &url);

	string getHeaderParameter(
		const string& headerName, const char *defaultParameter = "", const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getHeaderParameter(headerName, string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getHeaderParameter(
		const string& headerName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
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
	) const
	{
		return getMapParameter(_queryParameters, parameterName, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T, template <class...> class C>
	requires (is_same_v<C<T>, vector<T>> || is_same_v<C<T>, set<T>>)
	C<T> getQueryParameter(
		const string& parameterName, char delim, C<T> defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, delim, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T>
	optional<T> getOptHeaderParameter(const string& parameterName) const
	{
		return getOptMapParameter<T>(_requestDetails, parameterName);
	}

	template <typename T>
	optional<T> getOptQueryParameter(const string& parameterName) const
	{
		return getOptMapParameter<T>(_queryParameters, parameterName);
	}

	static void parseContentRange(string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd, uint64_t &contentRangeSize);

private:
	unordered_map<string, string> _requestDetails;
	unordered_map<string, string> _queryParameters;


	void fillEnvironmentDetails(const char *const *envp);
	void fillQueryString(const string& queryString);

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
				SPDLOG_ERROR("Missing mandatory header/query parameter: {}", parameterName);
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

};
