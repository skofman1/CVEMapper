using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;

namespace CVEMapping
{
    internal class NuGetAPI
    {
        private SourceRepository sourceRepository;

        public NuGetAPI()
        {
            var source = new PackageSource("https://api.nuget.org/v3/index.json");
            var providers = Repository.Provider.GetCoreV3();
            sourceRepository = new SourceRepository(source, providers);
        }

        public async Task<Tuple<bool, IReadOnlyList<NuGetVersion>>> PackageExistsAsync(string packageId)
        {
            ILogger logger = NullLogger.Instance;
            CancellationToken cancellationToken = CancellationToken.None;

            SourceCacheContext cache = new SourceCacheContext();

            var resource = await sourceRepository.GetResourceAsync<FindPackageByIdResource>();

            IEnumerable<NuGetVersion> versions = await resource.GetAllVersionsAsync(
                packageId,
                cache,
                logger,
                cancellationToken);

            return new Tuple<bool, IReadOnlyList<NuGetVersion>>(versions.Any(), versions.ToList());
            
        }
    }
}
