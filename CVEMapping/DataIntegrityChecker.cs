using NuGet.Versioning;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CVEMapping
{
    internal static class DataIntegrityChecker
    {
        public static async Task CheckDatabaseAsync(CVEMappingDatabase database)
        {
            var gitHubApi = new GitHubAPI();
            var nugetAPI = new NuGetAPI();

            var cveToActualAdvisoryLink = new Dictionary<string, string>();
            var packageIdToNuGetOrgData = new Dictionary<string, Tuple<bool, IReadOnlyList<NuGetVersion>>>();

            foreach (var cveMappingsList in database.CVEToMappings.Values)
            {
                /*
                 * 1. Check if the data in the file is correct with respect to nuget.org. Package versions exist.
                 * 2. Get the data for the CVE from GitHub. Check if the data is identical to the file
                 */

                // Advisory check
                await CheckAdvisoryUrl(gitHubApi, cveToActualAdvisoryLink, cveMappingsList.First());

                //NuGet.org check 
                foreach (var cveMapping in cveMappingsList)
                {
                    await CheckCVEMappingInNuGetOrg(nugetAPI, packageIdToNuGetOrgData, cveMapping);
                }
            }
        }

        private static async Task CheckCVEMappingInNuGetOrg(
            NuGetAPI nuGetAPI, 
            Dictionary<string, Tuple<bool, IReadOnlyList<NuGetVersion>>> packageIdToNuGetOrgData,
            CVEMappingDatabase.CVEMapping cveMapping)
        {
            var packageId = cveMapping.PackageId.Trim();

            if (string.IsNullOrEmpty(packageId))
            {
                return;
            }

            Tuple<bool, IReadOnlyList<NuGetVersion>> nugetOrgData;
            
            if (!packageIdToNuGetOrgData.ContainsKey(packageId))
            {
                packageIdToNuGetOrgData[packageId] = await nuGetAPI.PackageExistsAsync(packageId);
            }

            nugetOrgData = packageIdToNuGetOrgData[packageId];

            if (!nugetOrgData.Item1)
            {
                Console.WriteLine($"Found mismatch CVE: {cveMapping.CVE}. Package id {packageId} doesn't exist");
                return;
            }

            var versionsList = GetVersionsList(cveMapping.VersionRange);

            foreach (var version in versionsList)
            {
                if (!nugetOrgData.Item2.Contains(version))
                {
                    Console.WriteLine($"Found mismatch for CVE: {cveMapping.CVE}. Package id {packageId} {version} doesn't exist");
                }
            }

            var fixedInVersion = GetVersionsList(cveMapping.FixedInVersion);

            if (fixedInVersion.Any())
            {
                if (!nugetOrgData.Item2.Contains(fixedInVersion.First()))
                {
                    Console.WriteLine($"Found mismatch for CVE: {cveMapping.CVE}. Package id fixed version {packageId} {fixedInVersion.First()} doesn't exist");
                }
            }  
        }

        private static List<NuGetVersion> GetVersionsList(string versionsString)
        {
            versionsString = versionsString
                .Replace('\n', ' ').Replace("<", string.Empty).Replace(">", string.Empty)
                .Replace("=", string.Empty).Replace("[", string.Empty).Replace("]", string.Empty)
                .Replace("(", string.Empty).Replace(")", string.Empty).Replace(",", " ").Trim(' ');
            
            var versions = versionsString.Split(' ');

            var result = new List<NuGetVersion>();

            foreach (var version in versions)
            {
                if (!string.IsNullOrEmpty(version))
                {
                    result.Add(new NuGetVersion(version));
                }
            }

            return result;
        } 

        private static async Task CheckAdvisoryUrl(GitHubAPI gitHubApi, Dictionary<string, string> cveToActualAdvisoryLink, CVEMappingDatabase.CVEMapping cveMapping)
        {
            string actualAdvisoryUrl;

            if (cveToActualAdvisoryLink.ContainsKey(cveMapping.CVE))
            {
                actualAdvisoryUrl = cveToActualAdvisoryLink[cveMapping.CVE];
            }
            else
            {
                actualAdvisoryUrl = await gitHubApi.GetCVELinkAsync(cveMapping.CVE);
                cveToActualAdvisoryLink[cveMapping.CVE] = actualAdvisoryUrl;
            }

            if (actualAdvisoryUrl != cveMapping.GitHubAdvisoryUrl &&
                !(string.IsNullOrWhiteSpace(actualAdvisoryUrl) && string.IsNullOrWhiteSpace(cveMapping.GitHubAdvisoryUrl)))
            {
                Console.WriteLine($"Found mismatch in Advisory URL for CVE: {cveMapping.CVE}. GitHub: {actualAdvisoryUrl}, DB: {cveMapping.GitHubAdvisoryUrl}");
            }
        }
    }
}
