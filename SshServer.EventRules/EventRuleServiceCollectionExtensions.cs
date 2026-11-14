using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SshServer.EventRules.Actions;
using SshServer.Interfaces.EventRules;
using SshServer.Interfaces.Events;

namespace SshServer.EventRules;

public static class EventRuleServiceCollectionExtensions
{
    /// <summary>
    /// The event rules plug-in (#68): the event sink and the <c>Pre*</c> hook of the rules on events, the background
    /// worker that runs them, the scheduler of the scheduled rules, the application service of the admin UI and the
    /// built-in actions (email, command, file operations, data retention). Nothing runs until an admin adds a rule; with
    /// no rule an event costs no database read. The Command action is off unless <c>EventRules:AllowCommands</c> is true,
    /// and an Email action is skipped without <c>EventRules:Smtp:Host</c>. Needs an <c>IEventRuleStore</c>
    /// (AddSshServerSettings), the event bus (AddSshServerEvents), the users (<c>ISettingsRepository</c>) and the storage
    /// (<c>IFileSystemFactory</c>, AddSshServerStorage). More action types are singleton <see cref="IEventRuleAction"/>
    /// services, for example the Webhook action of AddWebhooks.
    /// </summary>
    public static IServiceCollection AddEventRules(this IServiceCollection services, IConfiguration configuration)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<EventRuleOptions>().Configure(o => EventRuleOptions.Bind(o, configuration)).ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<EventRuleOptions>, EventRuleOptionsValidator>());

        services.TryAddSingleton<EventRuleCatalog>();
        services.TryAddSingleton<EventRuleQueue>();
        services.TryAddSingleton<EventRuleRunner>();
        services.TryAddSingleton<EventRuleAdministrationService>();
        services.TryAddSingleton<UserFileSystems>();
        services.TryAddSingleton<IEmailSender, SmtpEmailSender>();
        services.TryAddSingleton<ICommandRunner, ProcessCommandRunner>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, EmailAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, CommandAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, MoveAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, CopyAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, DeleteAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, CreateDirectoryAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, ExistsAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, CompressAction>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventRuleAction, RetentionAction>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, EventRuleSink>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventHook, EventRuleHook>());
        services.AddHostedService<EventRuleWorker>();
        services.AddHostedService<EventRuleScheduler>();
        return services;
    }
}
