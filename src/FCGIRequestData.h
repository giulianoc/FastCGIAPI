/*
Copyright (C) Giuliano Catrambone (giulianocatrambone@gmail.com)

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either
 version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 Commercial use other than under the terms of the GNU General Public
 License is allowed only after express negotiation of conditions
 with the authors.
*/


#pragma once

#include "HTTPError.h"
#include "StringUtils.h"
#include "spdlog/spdlog.h"
#include <fcgiapp.h>
#include <set>
#include <span>
#include <spdlog/fmt/bundled/ranges.h>
#include <string>
#include <unordered_map>

class FCGIRequestData final
{
public:
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

	~FCGIRequestData() = default;
	void init(const FCGX_Request & request, int64_t& maxAPIContentLength);

	static std::string escape(const std::string &url);
	static std::string unescape(const std::string &url);

	std::string getHeaderParameter(
		const std::string& headerName, const char *defaultParameter,
		const bool mandatory, const std::initializer_list<std::string> allowedValues, bool *isParamPresent = nullptr
	) const
	{
		return getHeaderParameter(headerName, std::string(defaultParameter), mandatory,
			std::span<const std::string>(allowedValues.begin(), allowedValues.size()), isParamPresent);
	}

	std::string getHeaderParameter(
		const std::string& headerName, const char *defaultParameter = "",
		const bool mandatory = false, std::span<const std::string> allowedValues = {}, bool *isParamPresent = nullptr
	) const
	{
		return getHeaderParameter(headerName, std::string(defaultParameter), mandatory, allowedValues, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getHeaderParameter(
		const std::string& headerName, T defaultParameter, const bool mandatory = false,
		std::span<const T> allowedValues = {}, bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_requestDetails, std::format("HTTP_{}",
			StringUtils::replaceAll(StringUtils::upperCase(headerName), "-", "_")),
			std::move(defaultParameter), mandatory, allowedValues, isParamPresent);
	}

	std::string getQueryParameter(
		const std::string& parameterName, const char *defaultParameter, const bool mandatory,
		const std::initializer_list<std::string> allowedValues, bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, std::string(defaultParameter),
			mandatory, std::span<const std::string>(allowedValues.begin(), allowedValues.size()), isParamPresent);
	}

	std::string getQueryParameter(
		const std::string& parameterName, const char *defaultParameter = "",
		const bool mandatory = false,
		const std::span<const std::string> allowedValues = {}, bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, std::string(defaultParameter),
			mandatory, allowedValues, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getQueryParameter(
		const std::string& parameterName, T defaultParameter, const bool mandatory,
		const std::initializer_list<T> allowedValues, bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, defaultParameter, mandatory,
			std::span<const T>(allowedValues.begin(), allowedValues.size()), isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	T getQueryParameter(
		const std::string& parameterName, T defaultParameter, const bool mandatory = false,
		std::span<const T> allowedValues = {}, bool *isParamPresent = nullptr
	) const
	{
		return getMapParameter(_queryParameters, parameterName, defaultParameter, mandatory, allowedValues, isParamPresent);
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
	std::optional<T> getOptHeaderParameter(const std::string& parameterName, std::initializer_list<T> allowedValues) const
	{
		return getOptMapParameter<T>(_requestDetails, parameterName,
			std::span<const T>(allowedValues.begin(), allowedValues.size()));
	}

	template <typename T>
	std::optional<T> getOptHeaderParameter(const std::string& parameterName, std::span<const T> allowedValues = {}) const
	{
		return getOptMapParameter<T>(_requestDetails, parameterName, allowedValues);
	}

	template <typename T>
	std::optional<T> getOptQueryParameter(const std::string& parameterName, std::initializer_list<T> allowedValues) const
	{
		return getOptMapParameter<T>(_queryParameters, parameterName,
			std::span<const T>(allowedValues.begin(), allowedValues.size()));
	}

	template <typename T>
	std::optional<T> getOptQueryParameter(const std::string& parameterName, std::span<const T> allowedValues = {}) const
	{
		return getOptMapParameter<T>(_queryParameters, parameterName, allowedValues);
	}

	[[nodiscard]] std::unordered_map<std::string, std::string> getQueryParameters() const;
	[[nodiscard]] std::vector<std::pair<std::string, std::string>> getHeaders() const;

	static void parseContentRange(std::string_view contentRange, uint64_t &contentRangeStart, uint64_t &contentRangeEnd,
		uint64_t &contentRangeSize);

private:
	std::unordered_map<std::string, std::string> _requestDetails;
	std::unordered_map<std::string, std::string> _queryParameters;


	void fillEnvironmentDetails(const char *const *envp);
	void fillQueryString(const std::string& queryString);

	template <typename T>
	static std::optional<T> getOptMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string& parameterName,
		std::span<const T> allowedValues = {})
	{
		T parameterValue;

		const auto it = mapParameters.find(parameterName);
		if (it == mapParameters.end() || it->second.empty())
			return std::nullopt;

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

			parameterValue = unescape(firstDecoding);
		}
		else
		{
			try
			{
				parameterValue = StringUtils::getValue<T>(it->second);
			}
			catch (const std::exception &e)
			{
				const std::string errorMessage = std::format("StringUtils::getValue failed"
					", parameterName: {}"
					", parameterValue: {}"
					", exception: {}", parameterName, it->second, e.what());
				LOG_ERROR(errorMessage);
				throw FastCGIError::HTTPError(400, errorMessage);
			}
		}

		if (!allowedValues.empty())
		{
			if (std::ranges::find(allowedValues, parameterValue) == allowedValues.end())
			{
				const std::string errorMessage = fmt::format("Invalid value '{}' for '{}'. Allowed values are: {}",
					parameterValue, parameterName, fmt::join(allowedValues, ", ")
					);
				LOG_ERROR(errorMessage);
				throw FastCGIError::HTTPError(400, errorMessage);
			}
		}

		return parameterValue;
	}

	static std::string getMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string &parameterName, const char *defaultParameter,
		const bool mandatory = false, std::span<const std::string> allowedValues = {}, bool *isParamPresent = nullptr
	)
	{
		return getMapParameter(mapParameters, parameterName, std::string(defaultParameter),
			mandatory, allowedValues, isParamPresent);
	}

	template <typename T>
	requires (!std::is_same_v<T, const char*>)
	static T getMapParameter(
		const std::unordered_map<std::string, std::string> &mapParameters, const std::string& parameterName, T defaultParameter,
		const bool mandatory = false, std::span<const T> allowedValues = {}, bool *isParamPresent = nullptr
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

				parameterValue = unescape(firstDecoding);
			}
			else
			{
				try
				{
					parameterValue = StringUtils::getValue<T>(it->second);
				}
				catch (const std::exception &e)
				{
					const std::string errorMessage = std::format("StringUtils::getValue failed"
						", parameterName: {}"
						", exception: {}", parameterName, e.what());
					LOG_ERROR(errorMessage);
					throw FastCGIError::HTTPError(400, errorMessage);
				}
			}
			if (!allowedValues.empty())
			{
				if (std::ranges::find(allowedValues, parameterValue) == allowedValues.end())
				{
					const std::string errorMessage = fmt::format("Invalid value '{}' for '{}'. Allowed values are: {}",
						parameterValue, parameterName, fmt::join(allowedValues, ", ")
						);
					LOG_ERROR(errorMessage);
					throw FastCGIError::HTTPError(400, errorMessage);
				}
			}
		}
		else
		{
			if (isParamPresent != nullptr)
				*isParamPresent = false;
			if (mandatory)
			{
				const std::string errorMessage = std::format("Missing mandatory header/query parameter: {}", parameterName);
				LOG_ERROR(errorMessage);
				throw FastCGIError::HTTPError(400, errorMessage);
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
						const std::string errorMessage = std::format("StringUtils::getValue failed"
							", parameterName: {}"
							", exception: {}", parameterName, e.what());
						LOG_ERROR(errorMessage);
						throw FastCGIError::HTTPError(400, errorMessage);
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
				const std::string errorMessage = std::format("Missing mandatory query parameter: {}", parameterName);
				LOG_ERROR(errorMessage);
				throw FastCGIError::HTTPError(400, errorMessage);
			}

			parameterValue = std::move(defaultParameter);
		}

		return parameterValue;
	}
};
