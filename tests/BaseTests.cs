using System;
using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using ServiceStack.Auth;

namespace ServiceStack.Jwks.Tests {

    public abstract class BaseTests {
        protected JsonHttpClient client;

        protected HttpClient httpClient;

        protected IHost server;
        protected IConfiguration configuration;

        [OneTimeSetUp]
        public void Setup() {
            configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .Build();
            server = CreateTestServer();
        }

        protected abstract IHost CreateTestServer();

        [SetUp]
        public void BeforeTests() {
            httpClient = server.GetTestClient();
            client = new JsonHttpClient("https://server.example.com") {
                HttpClient = httpClient
            };
        }

        [OneTimeTearDown]
        public void TearDown() {
            server?.Dispose();
        }

        protected string CreateJwt(RSAParameters privateKey, string algorithm, string audience = null) {
            var header = JwtAuthProvider.CreateJwtHeader(algorithm);
            var payload = JwtAuthProvider.CreateJwtPayload(new AuthUserSession {
                    UserAuthId = "someuser",
                        DisplayName = "Test",
                        Email = "test@example.com",
                        // JwtAuthProvider.CreateJwt would fail without ProfileUrl when
                        // there is no initialized AppHost
                        ProfileUrl = "http://myprofile"
                }, "https://server.example.com",
                audiences : new [] { audience },
                expireIn : TimeSpan.FromDays(7));

            var rsaSignFunc = JwtAuthProviderReader.RsaSignAlgorithms[algorithm];

            return JwtAuthProvider.CreateJwt(header, payload,
                data => rsaSignFunc(privateKey, data));
        }

    }
}