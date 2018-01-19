/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Extensions;
using IdentityServer3.Core.Logging;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using Microsoft.Owin;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IdentityServer3.Core.Validation
{
    /// <summary>
    /// Parses a POST body for secrets
    /// </summary>
    public class PostBodySecretParser : ISecretParser
    {
        private static readonly ILog Logger = LogProvider.GetCurrentClassLogger();
        private readonly IdentityServerOptions _options;

        /// <summary>
        /// Creates the parser with options
        /// </summary>
        /// <param name="options">IdentityServer options</param>
        public PostBodySecretParser(IdentityServerOptions options)
        {
            _options = options;
        }

        /// <summary>
        /// Tries to find a secret on the environment that can be used for authentication
        /// </summary>
        /// <param name="environment">The environment.</param>
        /// <returns>
        /// A parsed secret
        /// </returns>
        public async Task<ParsedSecret> ParseAsync(IDictionary<string, object> environment)
        {
            Logger.Debug("Start parsing for secret in post body");
            var context = new OwinContext(environment);

            if (context.Request.IsJsonData())
            {
                return await ParsedJsonDataRequest(context);
            }

            return await ParsedFormDataRequest(context);
        }

        private async Task<ParsedSecret> ParsedJsonDataRequest(IOwinContext context)
        {
            var body = await context.Request.ReadBodyAsStringAsync();
            var deserializedBody = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(body);

            if (deserializedBody != null)
            {
                var id = deserializedBody.ContainsKey("client_id") ? deserializedBody["client_id"] : "";
                var secret = deserializedBody.ContainsKey("client_secret") ? deserializedBody["client_secret"] : "";
                if (id.IsPresent() && secret.IsPresent())
                {
                    return MapToParsedSecret(id, secret);
                }
            }

            Logger.Debug("No secret in post body found");
            return null;
        }

        private async Task<ParsedSecret> ParsedFormDataRequest(IOwinContext context)
        {
            var body = await context.ReadRequestFormAsync();

            if (body != null)
            {
                var id = body.Get("client_id");
                var secret = body.Get("client_secret");
                if (id.IsPresent() && secret.IsPresent())
                {
                    return MapToParsedSecret(id, secret);
                }
            }

            Logger.Debug("No secret in post body found");
            return null;
        }

        private ParsedSecret MapToParsedSecret(string id, string secret)
        {
            if (id.Length > _options.InputLengthRestrictions.ClientId ||
                secret.Length > _options.InputLengthRestrictions.ClientSecret)
            {
                Logger.Debug("Client ID or secret exceeds maximum length.");
                return null;
            }

            var parsedSecret = new ParsedSecret
            {
                Id = id,
                Credential = secret,
                Type = Constants.ParsedSecretTypes.SharedSecret
            };

            return parsedSecret;
        }
    }
}
