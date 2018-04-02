using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Twilio.Security;

namespace ValidateRequestExample.Filters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class ValidateTwilioRequestAttribute : ActionFilterAttribute
    {
        private readonly string _authToken;
        private readonly string _urlSchemeAndDomain;

        public ValidateTwilioRequestAttribute()
        {
            _authToken = ConfigurationManager.AppSettings["TwilioAuthToken"];
            _urlSchemeAndDomain = ConfigurationManager.AppSettings["TwilioBaseUrl"];
        }

        public override async Task OnActionExecutingAsync(HttpActionContext actionContext, CancellationToken cancellationToken)
        {
            if (!await IsValidRequestAsync(actionContext.Request))
            {
                actionContext.Response = actionContext.Request.CreateErrorResponse(
                    HttpStatusCode.Forbidden,
                    "The Twilio request is invalid"
                );
            }

            await base.OnActionExecutingAsync(actionContext, cancellationToken);
        }

        private async Task<bool> IsValidRequestAsync(HttpRequestMessage request)
        {
            var headerExists = request.Headers.TryGetValues(
                "X-Twilio-Signature", out IEnumerable<string> signature);
            if (!headerExists) return false;

            var requestUrl = _urlSchemeAndDomain + request.RequestUri.PathAndQuery;
            var formData = await GetFormDataAsync(request.Content);
            return new RequestValidator(_authToken).Validate(requestUrl, formData, signature.First());
        }

        private async Task<IDictionary<string, string>> GetFormDataAsync(HttpContent content)
        {
            string postData;
            using (var stream = new StreamReader(await content.ReadAsStreamAsync()))
            {
                stream.BaseStream.Position = 0;
                postData = await stream.ReadToEndAsync();
            }

            if(!String.IsNullOrEmpty(postData) && postData.Contains("="))
            {
                return postData.Split('&')
                    .Select(x => x.Split('='))
                    .ToDictionary(
                        x => Uri.UnescapeDataString(x[0]),
                        x => Uri.UnescapeDataString(x[1].Replace("+", "%20"))
                    );
            }

            return new Dictionary<string, string>();
        }
    }
}
