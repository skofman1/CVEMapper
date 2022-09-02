**What does the tool do?**

1. The tool parses a csv file for CVE -> impacted package mapping
2. For each CVE, the following is checked:

	a. Queries GitHub Advisories DB to ensure the link to "GitHub Advisory" is correct. Also useful for identifying Advisories that exist, but the link is missing from the CSV.
	
	b. Checks that the package in "Vulnerable package id" column actually exists on nuget.org
	
	c. Checks that all the versions mentioned in "Vulnerable version range", "Fixed in version" exist on nuget.org. This test is very basic, it removes all characters that are not part of the version string, and checks if that exists.


**How to use it?**
1. Open file Program.cs and set the 'databasePath' to the csv file path. 
2. If you are interested in performing validation 2.a., create a GitHub personal token and set it in file GitHubAPI.cs (string token). Instructions on how to create one: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token 
