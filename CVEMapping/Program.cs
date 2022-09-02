using CVEMapping;

string databasePath = @"Add your path here";

var database = new CVEMappingDatabase();
database.Load(databasePath);

await DataIntegrityChecker.CheckDatabaseAsync(database);

Console.WriteLine("done");
