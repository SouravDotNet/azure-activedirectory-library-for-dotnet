// Copyright (c) Microsoft Corporation. All rights reserved. 
// Licensed under the MIT License.

using Microsoft.Identity.Core.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal.Helpers;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal.Http;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal.OAuth2;
using Microsoft.IdentityModel.Clients.ActiveDirectory.Internal.Platform;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Microsoft.Identity.Core.OAuth2
{
    internal class OAuthClient
    {
        private const string DeviceAuthHeaderName = "x-ms-PKeyAuth";
        private const string DeviceAuthHeaderValue = "1.0";
        private const string WwwAuthenticateHeader = "WWW-Authenticate";
        private const string PKeyAuthName = "PKeyAuth";
        private const int DelayTimePeriodMilliSeconds = 1000;
        internal /* internal for test only */ const string ExtraQueryParamEnvVariable = "ExtraQueryParameter";
        private readonly RequestContext _requestContext;
        internal bool Resiliency = false;
        internal bool RetryOnce = true;
        private readonly IHttpManager _httpManager;
        private const string FormUrlEncoded = "application/x-www-form-urlencoded";
        private readonly long _maxResponseSizeInBytes = 1048576;
        public int TimeoutInMilliSeconds { set; get; } = 30000;

        public IRequestParameters BodyParameters { get; set; }

        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>();

        internal string RequestUri { get; set; }

        public OAuthClient(IHttpManager httpManager, string uri, RequestContext requestContext)
        {
            RequestUri = CheckForExtraQueryParameter(uri);
            _httpManager = httpManager ?? throw new ArgumentNullException(nameof(httpManager));
            _requestContext = requestContext;
        }

        public async Task<T> GetResponseAsync<T>()
        {
            return await GetResponseAsync<T>(true).ConfigureAwait(false);
        }

        private async Task<T> GetResponseAsync<T>(bool respondToDeviceAuthChallenge)
        {
            T typedResponse = default(T);

            try
            {
                IDictionary<string, string> adalIdHeaders = AdalIdHelper.GetAdalIdParameters();
                foreach (KeyValuePair<string, string> kvp in adalIdHeaders)
                {
                    _headers[kvp.Key] = kvp.Value;
                }

                //add pkeyauth header
                _headers[DeviceAuthHeaderName] = DeviceAuthHeaderValue;
                var response = await ExecuteRequestAsync<IHttpWebResponse>().ConfigureAwait(false);
                typedResponse = EncodingHelper.DeserializeResponse<T>(response.Body);
            }
            catch (HttpRequestWrapperException ex)
            {
                if (ex.InnerException is TaskCanceledException)
                {
                    Resiliency = true;

                    _requestContext.Logger.InfoPii(
                        "Network timeout, Exception message: " + ex.InnerException.Message,
                        "Network timeout, Exception type: " + ex.InnerException.GetType());
                }

                if (!Resiliency && ex.WebResponse == null)
                {
                    _requestContext.Logger.ErrorPii(ex);
                    throw new AdalServiceException(AdalError.Unknown, ex);
                }

                //check for resiliency
                if (!Resiliency && (int)ex.WebResponse.StatusCode >= 500 && (int)ex.WebResponse.StatusCode < 600)
                {
                    _requestContext.Logger.InfoPii(
                        "HttpStatus code: " + ex.WebResponse.StatusCode + ", Exception message: " + ex.InnerException?.Message,
                        "HttpStatus code: " + ex.WebResponse.StatusCode + ", Exception type: " + ex.InnerException?.GetType());

                    Resiliency = true;
                }

                if (Resiliency)
                {
                    if (RetryOnce)
                    {
                        await Task.Delay(DelayTimePeriodMilliSeconds).ConfigureAwait(false);
                        RetryOnce = false;
                        _requestContext.Logger.Info("Retrying one more time..");
                        return await GetResponseAsync<T>(respondToDeviceAuthChallenge).ConfigureAwait(false);
                    }

                    _requestContext.Logger.ErrorPii(
                        "Retry Failed, Exception message: " + ex.InnerException?.Message,
                        "Retry Failed, Exception type: " + ex.InnerException?.GetType());

                    throw new AdalServiceException(AdalError.HttpRequestTimeoutResilience, ex);
                }

                if (!this.IsDeviceAuthChallenge(ex.WebResponse, respondToDeviceAuthChallenge))
                {
                    TokenResponse tokenResponse = TokenResponse.CreateFromErrorResponse(ex.WebResponse);
                    string[] errorCodes = tokenResponse.ErrorCodes ?? new[] { ex.WebResponse.StatusCode.ToString() };
                    AdalServiceException serviceEx = new AdalServiceException(tokenResponse.Error,
                        tokenResponse.ErrorDescription,
                        errorCodes, ex);

                    if (ex.WebResponse.StatusCode == HttpStatusCode.BadRequest &&
                        tokenResponse.Error == AdalError.InteractionRequired)
                    {
                        throw new AdalClaimChallengeException(tokenResponse.Error, tokenResponse.ErrorDescription, ex, tokenResponse.Claims);
                    }

                    throw serviceEx;
                }

                //attempt device auth
                return await HandleDeviceAuthChallengeAsync<T>(ex.WebResponse).ConfigureAwait(false);
            }

            return typedResponse;
        }

        private bool IsDeviceAuthChallenge(IHttpWebResponse response, bool respondToDeviceAuthChallenge)
        {
            return DeviceAuthHelper.CanHandleDeviceAuthChallenge
                   && response != null
                   && respondToDeviceAuthChallenge
                   && response?.Headers != null
                   && response.StatusCode == HttpStatusCode.Unauthorized
                   && response.Headers.Contains(WwwAuthenticateHeader)
                   && response.Headers.GetValues(WwwAuthenticateHeader).FirstOrDefault()
                       .StartsWith(PKeyAuthName, StringComparison.OrdinalIgnoreCase);
        }

        private IDictionary<string, string> ParseChallengeData(IHttpWebResponse response)
        {
            IDictionary<string, string> data = new Dictionary<string, string>();
            string wwwAuthenticate = response.Headers.GetValues(WwwAuthenticateHeader).FirstOrDefault();
            wwwAuthenticate = wwwAuthenticate.Substring(PKeyAuthName.Length + 1);
            List<string> headerPairs = EncodingHelper.SplitWithQuotes(wwwAuthenticate, ',');
            foreach (string pair in headerPairs)
            {
                List<string> keyValue = EncodingHelper.SplitWithQuotes(pair, '=');
                data.Add(keyValue[0].Trim(), keyValue[1].Trim().Replace("\"", ""));
            }

            return data;
        }

        private async Task<T> HandleDeviceAuthChallengeAsync<T>(IHttpWebResponse response)
        {
            IDictionary<string, string> responseDictionary = ParseChallengeData(response);

            if (!responseDictionary.ContainsKey("SubmitUrl"))
            {
                responseDictionary["SubmitUrl"] = RequestUri;
            }

            string responseHeader = await DeviceAuthHelper.CreateDeviceAuthChallengeResponseAsync(responseDictionary)
                .ConfigureAwait(false);
            IRequestParameters rp = BodyParameters;
            CheckForExtraQueryParameter(responseDictionary["SubmitUrl"]);
            BodyParameters = rp;
            _headers["Authorization"] = responseHeader;
            return await GetResponseAsync<T>(false).ConfigureAwait(false);
        }

        private static string CheckForExtraQueryParameter(string url)
        {
            string extraQueryParameter = PlatformProxyFactory.GetPlatformProxy().GetEnvironmentVariable(ExtraQueryParamEnvVariable);
            string delimiter = (url.IndexOf('?') > 0) ? "&" : "?";
            if (!string.IsNullOrWhiteSpace(extraQueryParameter))
            {
                url += string.Concat(delimiter, extraQueryParameter);
            }

            return url;
        }

        public async Task<IHttpWebResponse> ExecuteRequestAsync<T>()
        {
            bool addCorrelationId = _requestContext != null && _requestContext.Logger.CorrelationId != Guid.Empty;
            if (addCorrelationId)
            {
                _headers.Add(OAuthHeader.CorrelationId, _requestContext.Logger.CorrelationId.ToString());
                _headers.Add(OAuthHeader.RequestCorrelationIdInResponse, "true");
            }

            HttpResponse responseMessage;
            try
            {               
                if (BodyParameters != null)
                {
                    responseMessage = await _httpManager.SendPostAsync(
                        new Uri(RequestUri),
                        _headers,
                        (Dictionary<string, string>)BodyParameters,
                        _requestContext)
                        .ConfigureAwait(false);
                }
                else
                {
                    responseMessage = await _httpManager.SendGetAsync(
                         new Uri(RequestUri),
                         _headers,
                         _requestContext)
                         .ConfigureAwait(false);
                }
            }
            catch(TaskCanceledException ex)
            {
                throw new HttpRequestWrapperException(null, ex);
            }

            var webResponse = CreateResponse(responseMessage);

            if (responseMessage.StatusCode != HttpStatusCode.OK)
            {
                throw new HttpRequestWrapperException(
                    webResponse,
                    new HttpRequestException(
                        string.Format(
                            CultureInfo.CurrentCulture,
                            "Response status code does not indicate success: {0} ({1}).",
                            (int)webResponse.StatusCode,
                            webResponse.StatusCode),
                        new AdalException(webResponse.Body)));
            }

            if (addCorrelationId)
            {
                VerifyCorrelationIdHeaderInResponse(webResponse.Headers, _requestContext);
            }

            return webResponse;
        }

        public static IHttpWebResponse CreateResponse(HttpResponse response)
        {
            return new HttpWebResponseWrapper(
                response.Body,
                response.Headers,
                response.StatusCode);
        }

        public static async Task<IHttpWebResponse> CreateResponseAsync(HttpResponseMessage response)
        {
            return new HttpWebResponseWrapper(
                await response.Content.ReadAsStringAsync().ConfigureAwait(false),
                response.Headers,
                response.StatusCode);
        }

        private static void VerifyCorrelationIdHeaderInResponse(HttpResponseHeaders headers, RequestContext requestContext)
        {
            foreach (KeyValuePair<string, IEnumerable<string>> header in headers)
            {
                string responseHeaderKey = header.Key;
                string trimmedKey = responseHeaderKey.Trim();
                if (string.Compare(trimmedKey, OAuthHeader.CorrelationId, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    string correlationIdHeader = headers.GetValues(trimmedKey).FirstOrDefault().Trim();
                    if (!Guid.TryParse(correlationIdHeader, out var correlationIdInResponse))
                    {
                        requestContext.Logger.Warning(
                            string.Format(
                                CultureInfo.CurrentCulture,
                                "Returned correlation id '{0}' is not in GUID format.",
                                correlationIdHeader));
                    }
                    else if (correlationIdInResponse != requestContext.Logger.CorrelationId)
                    {
                        requestContext.Logger.Warning(
                            string.Format(
                                CultureInfo.CurrentCulture,
                                "Returned correlation id '{0}' does not match the sent correlation id '{1}'",
                                correlationIdHeader,
                                requestContext.Logger.CorrelationId));
                    }

                    break;
                }
            }
        }
    }
}
