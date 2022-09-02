using CsvHelper;
using CsvHelper.Configuration;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CVEMapping
{
    internal class CVEMappingDatabase
    {
        public class CVEMapping
        {
            public string CVE { get; set; }
            public string GitHubAdvisoryUrl { get; set; }

            public string PackageId { get; set; }

            public string VersionRange { get; set; }

            public string FixedInVersion { get; set; }
        }

        public sealed class CVEMappingMap : ClassMap<CVEMapping>
        {
            public CVEMappingMap()
            {
                Map(m => m.CVE).Name("CVE");
                Map(m => m.GitHubAdvisoryUrl).Name("GitHub Advisory");
                Map(m => m.PackageId).Name("Vulnerable package id");
                Map(m => m.VersionRange).Name("Vulnerable version range");
                Map(m => m.FixedInVersion).Name("Fixed in version");
            }
        }

        public List<CVEMapping> Database { get; set; }

        public Dictionary<string, List<CVEMapping>> CVEToMappings { get; set; }

        public void Load(string filePath)
        {
            using (var reader = new StreamReader(filePath))
            using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
            {

                csv.Context.RegisterClassMap<CVEMappingMap>();
                var records = csv.GetRecords<CVEMapping>();
                Database = records.ToList();
            }

            CVEToMappings = new Dictionary<string, List<CVEMapping>>();
            foreach (var mapping in Database)
            {
                if (CVEToMappings.ContainsKey(mapping.CVE))
                {
                    var entry = CVEToMappings[mapping.CVE];
                    entry.Add(mapping);
                }
                else
                {
                    var entry = new List<CVEMapping>();
                    entry.Add(mapping);
                    CVEToMappings[mapping.CVE] = entry;
                }
            }
        }
    }
}
