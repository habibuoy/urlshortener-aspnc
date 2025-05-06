using UrlShortener.Data;

namespace UrlShortener.BackgroundServices;

public class ExpiredUrlRemoverHostedService : BackgroundService
{
    private readonly TimeSpan checkInterval = TimeSpan.FromSeconds(30);

    private readonly ILogger<ExpiredUrlRemoverHostedService> logger;
    private readonly IServiceProvider services;

    public ExpiredUrlRemoverHostedService(ILogger<ExpiredUrlRemoverHostedService> logger, IServiceProvider services)
    {
        this.logger = logger;
        this.services = services;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("{servicename}: Starting Expired Url Remover Service, checking every {interval} seconds.", nameof(ExpiredUrlRemoverHostedService), checkInterval.Seconds);

        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("Running check at {datetime}.", DateTime.Now);

            // create a scope because no scope is created for background service by default.
            using (var scope = services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                int expiredUrlCount = 0;

                foreach (var url in dbContext.Urls)
                {
                    if (stoppingToken.IsCancellationRequested)
                    {
                        logger.LogInformation("Service is stopping at {dt} because of the token", DateTime.Now);
                        return;
                    }

                    if (url.ExpiredAt == null) continue;

                    if (DateTime.Now > url.ExpiredAt)
                    {
                        logger.LogInformation("Url id {id} is expired at {expiredDt}", url.Id, url.ExpiredAt);
                        dbContext.Remove(url);
                        expiredUrlCount++;
                    }
                }

                await dbContext.SaveChangesAsync(stoppingToken);
                logger.LogInformation("Finished running check. Removed {count} expired urls.", expiredUrlCount);
            }

            logger.LogInformation("Waiting for {waitTime} seconds before running the check again.", checkInterval.Seconds);
            await Task.Delay(checkInterval, stoppingToken);
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("{servicename}: Stopping Expired Url Remover Service", nameof(ExpiredUrlRemoverHostedService));

        return base.StopAsync(cancellationToken);
    }
}