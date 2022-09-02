using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GraphQL;
using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using NuGet.Packaging;

namespace CVEMapping
{
    internal class GitHubAPI
    {
        string token = "<add your token here. For instructions: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token";

        private GraphQLHttpClient graphQLClient;
        public GitHubAPI()
        {
            graphQLClient = new GraphQLHttpClient("https://api.github.com/graphql", new NewtonsoftJsonSerializer());
            
            graphQLClient.HttpClient.DefaultRequestHeaders.Add("Authorization", "bearer " + token);
        }

        public async Task<string> GetCVELinkAsync(string cveId)
        {
            var getCVEData = new GraphQLRequest
            {
                Query = @"
                        query GetCVEData($cve_Id: String!) { 
                            securityAdvisories(identifier: { type: CVE, value: $cve_Id }, first:100) {
                                nodes {
                                    id,
                                    permalink
                                    identifiers {type, value}
                                    vulnerabilities(first: 100) {
                                            nodes {
                                              package {
                                                name
                                                ecosystem
                                              }
                                              vulnerableVersionRange
                                            }
                                        }
                                    }
                                   }
                               }",
                OperationName = "GetCVEData",
                Variables = new { cve_Id = cveId }
            };

            var graphQLResponse = await graphQLClient.SendQueryAsync<ResponseType>(getCVEData);

            foreach (var advisory in graphQLResponse.Data.securityAdvisories.nodes)
            {
                if (advisory.identifiers.Exists(x => x.value == cveId))
                {
                    return advisory.permalink;
                }
            }
            
            return String.Empty;
        }
    }

    public class ResponseType
    {
        public SecurityAdvisory? securityAdvisories { get; set; }
    }

    public class SecurityAdvisory
    {
        public List<Node>? nodes { get; set; }
    }

    public class Node
    {
        public string? id { get; set; }
        public string? permalink { get; set; }

        public List<Identifier>? identifiers { get; set; }
        public Vulnerabilities vulnerabilities { get; set; }
    }

    public class Vulnerabilities
    {
        public  List<VulnerabilityNode>? nodes { get; set; }
    }

    public class VulnerabilityNode
    {
        public VulnerablePackage package { get; set; }
        public string vulnerableVersionRange { get; set; }  
    }

    public class VulnerablePackage
    {
        public string name { get; set; }
        public string ecosystem { get; set; }
    }

    public class Identifier
    {
        public string? type { get; set; }
        public string? value { get; set; }
    }
}
