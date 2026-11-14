#nullable enable
using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces.Events;

namespace SshServerModule.Events
{
    public static class EventServiceCollectionExtensions
    {
        /// <summary>
        /// The event bus (<see cref="IEventBus"/>, <see cref="ChannelEventBus"/>) and the log lines of the auth events
        /// (<see cref="AuthLogSink"/>). Register more consumers as singleton <see cref="IEventSink"/> or
        /// <see cref="IEventHook"/>; the audit log comes with AddSshServerSettings.
        /// </summary>
        public static IServiceCollection AddSshServerEvents(this IServiceCollection services)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<IEventBus, ChannelEventBus>();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IEventSink, AuthLogSink>());
            return services;
        }
    }
}
