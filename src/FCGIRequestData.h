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

class FCGIRequestData final
{
public:
	struct HTTPError final : std::runtime_error
	{
		int16_t httpErrorCode;
		explicit HTTPError(const int16_t httpErrorCode, const std::string& errorMessage = "") :
			std::runtime_error(errorMessage.empty() ? getHtmlStandardMessage(httpErrorCode) : errorMessage),
			httpErrorCode(httpErrorCode) {};
	};

	class AuthorizationDetails
	{
	public:
		std::string userName;
		std::string password;

		virtual ~AuthorizationDetails() = default;
	};

	std::string requestMethod;
	std::string requestBody;
	unsigned long contentLength;
	std::string requestURI;
	std::shared_ptr<AuthorizationDetails> authorizationDetails;
	bool responseBodyCompressed;
	std::string clientIPAddress;

	virtual ~FCGIRequestData() = default;
	void init(const FCGX_Request & request, int64_t& maxAPIContentLength);

	static std::string getHtmlStandardMessage(int htmlResponseCode);

	static std::string escape(const std::string &url);
	static std::string unescape(const std::string &url);

	std::string getHeaderParameter(
		const std::string& headerName, const char *defaultParameter = "", const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getHeaderParameter(headerName, std::string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getHeaderParameter(
		const std::string& headerName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_requestDetails, std::format("HTTP_{}",
			StringUtils::replaceAll(StringUtils::upperCase(headerName), "-", "_")),
			std::move(defaultParameter), mandatory, isParamPresent);
	}

	std::string getQueryParameter(
		const std::string& parameterName, const char *defaultParameter = "", const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, std::string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getQueryParameter(
		const std::string& parameterName, T defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T, template <class...> class C>
	requires (std::is_same_v<C<T>, std::vector<T>> || std::is_same_v<C<T>, std::set<T>>)
	C<T> getQueryParameter(
		const std::string& parameterName, char delim, C<T> defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, delim, defaultParameter, mandatory, isParamPresent);
	}

	template <typename T>
	std::optional<T> getOptHeaderParameter(const std::string& parameterName) const
	{
		return getOptMapParameter<T>(_requestDetails, parameterName);
	}

	template <typename T>
	std::optional<T> getOptQueryParameter(const std::string& parameterName) const
	{
		return getOptMapParameter<T>(_queryParameters, parameterName);
	}

	[[nodiscard]] std::unordered_map<std::string, std::string> getQueryParameters() const;
	[[nodiscard]] std::vector<std::pair<std::string, std::string>> getHeaders() const;

	static void parseContentRange(std::string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd, uint64_t &contentRangeSize);

private:
	std::unordered_map<std::string, std::string> _requestDetails;
	std::unordered_map<std::string, std::string> _queryParameters;


	void fillEnvironmentDetails(const char *const *envp);
	void fillQueryString(const std::string& queryString);

	template <typename T>
	static std::optional<T> getOptMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string& parameterName)
	{
		T parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if constexpr (std::is_same_v<T, std::string>)
			{
				// 2021-01-07: Remark: we have FIRST to replace + in space and then apply
				// unescape
				//	That  because if we have really a + char (%2B into the std::string), and we
				// do the replace 	after unescape, this char will be changed to space and we
				// do not want it
				std::string plus = "+";
				std::string plusDecoded = " ";
				const std::string firstDecoding = StringUtils::replaceAll(StringUtils::getValue<T>(it->second), plus, plusDecoded);

				return unescape(firstDecoding);
			}
			else
			{
				try
				{
					parameterValue = StringUtils::getValue<T>(it->second);
				}
				catch (const std::exception &e)
				{
					SPDLOG_ERROR("StringUtils::getValue failed"
						", parameterName: {}"
						", exception: {}", parameterName, e.what());
					throw std::runtime_error(std::format("parameterName: {} - {}", parameterName, e.what()));
				}
			}

			return parameterValue;
		}

		return std::nullopt;
	}

	static std::string getMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string &parameterName, const char *defaultParameter, const bool mandatory,
		bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, std::string(defaultParameter), mandatory, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	static T getMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string& parameterName, T defaultParameter, const bool mandatory = false,
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
				//	That  because if we have really a + char (%2B into the std::string), and we
				// do the replace 	after unescape, this char will be changed to space and we
				// do not want it
				std::string plus = "+";
				std::string plusDecoded = " ";
				const std::string firstDecoding = StringUtils::replaceAll(StringUtils::getValue<T>(it->second), plus, plusDecoded);

				return unescape(firstDecoding);
			}
			else
			{
				try
				{
					parameterValue = StringUtils::getValue<T>(it->second);
				}
				catch (const std::exception &e)
				{
					SPDLOG_ERROR("StringUtils::getValue failed"
						", parameterName: {}"
						", exception: {}", parameterName, e.what());
					throw std::runtime_error(std::format("parameterName: {} - {}", parameterName, e.what()));
				}
			}
		}
		else
		{
			if (isParamPresent != nullptr)
				*isParamPresent = false;
			if (mandatory)
			{
				const std::string errorMessage = std::format("Missing mandatory parameter: {}", parameterName);
				SPDLOG_ERROR(errorMessage);
				throw HTTPError(400, errorMessage);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}

	template <typename T, template <class...> class C>
	requires (std::is_same_v<C<T>, std::vector<T>> || std::is_same_v<C<T>, std::set<T>>)
	static C<T> getMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string& parameterName, char delim, C<T> defaultParameter, const bool mandatory = false,
		bool *isParamPresent = nullptr
	)
	{
		C<T> parameterValue;

		auto it = mapParameters.find(parameterName);
		if (it != mapParameters.end() && !it->second.empty())
		{
			if (isParamPresent != nullptr)
				*isParamPresent = true;
			std::stringstream ss(it->second);
			std::string token;
			while (getline(ss, token, delim))
			{
				if (!token.empty())
				{
					try
					{
						if constexpr (std::is_same_v<C<T>, std::vector<T>>)
							parameterValue.push_back(StringUtils::getValue<T>(token));
						else
							parameterValue.insert(StringUtils::getValue<T>(token));
					}
					catch (const std::exception &e)
					{
						SPDLOG_ERROR("StringUtils::getValue failed"
							", parameterName: {}"
							", exception: {}", parameterName, e.what());
						throw std::runtime_error(std::format("parameterName: {} - {}", parameterName, e.what()));
					}
				}
			}
		}
		else
		{
			if (isParamPresent != nullptr)
				*isParamPresent = false;
			if (mandatory)
			{
				const std::string errorMessage = std::format("Missing mandatory parameter: {}", parameterName);
				SPDLOG_ERROR(errorMessage);
				throw HTTPError(400, errorMessage);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}

};
