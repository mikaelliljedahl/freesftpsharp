#nullable enable
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization;
using SshServer.Interfaces.Security;

namespace SshServerModule.Storage
{
    /// <summary>How the admin UI shows a <see cref="StorageOptionField"/>.</summary>
    public enum StorageOptionKind
    {
        Text,
        Number,
        Boolean,

        /// <summary>One of <see cref="StorageOptionField.Choices"/> (an enum, or a string with <see cref="AllowedValuesAttribute"/>).</summary>
        Choice,
    }

    /// <summary>
    /// One property of the options record of a storage provider (<c>IStorageProvider.OptionsType</c>), read with
    /// reflection, so the admin UI shows the options of every backend without code for each backend. A backend
    /// describes its options with attributes: <see cref="DisplayAttribute"/> (name, description, placeholder, order),
    /// <see cref="SecretAttribute"/>, <see cref="AllowedValuesAttribute"/>, and on the record <see cref="DisplayNameAttribute"/>
    /// and <see cref="DescriptionAttribute"/>. Properties of other types (lists, objects) are not shown and keep their stored value.
    /// </summary>
    public sealed record StorageOptionField(string Name, string Label, string? Description, string? Placeholder, StorageOptionKind Kind,
        bool IsSecret, IReadOnlyList<string> Choices)
    {
        private static readonly ConcurrentDictionary<Type, IReadOnlyList<StorageOptionField>> Cache = new();

        /// <summary>The fields of an options type, in the <see cref="DisplayAttribute.Order"/> and then the declaration order.</summary>
        public static IReadOnlyList<StorageOptionField> Of(Type optionsType) => Cache.GetOrAdd(optionsType, Read);

        /// <summary>The name of an options type for the UI: its <see cref="DisplayNameAttribute"/>, or the type name.</summary>
        public static string DisplayNameOf(Type optionsType, string fallback)
            => optionsType.GetCustomAttribute<DisplayNameAttribute>()?.DisplayName is { Length: > 0 } name ? name : fallback;

        /// <summary>The <see cref="DescriptionAttribute"/> of an options type, or null.</summary>
        public static string? DescriptionOf(Type optionsType) => optionsType.GetCustomAttribute<DescriptionAttribute>()?.Description;

        private static IReadOnlyList<StorageOptionField> Read(Type type)
        {
            var fields = new List<(int Order, int Token, StorageOptionField Field)>();
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                if (property.GetMethod is null || property.GetIndexParameters().Length > 0 || property.GetCustomAttribute<JsonIgnoreAttribute>() != null)
                    continue;
                var kind = KindOf(property, out var choices);
                if (kind is null)
                    continue;
                var display = property.GetCustomAttribute<DisplayAttribute>();
                var isSecret = property.GetCustomAttribute<SecretAttribute>() != null;
                if (isSecret && property.PropertyType != typeof(string))
                    throw new InvalidOperationException($"The secret {type.Name}.{property.Name} must be a string.");
                var field = new StorageOptionField(property.Name, display?.GetName() ?? SplitWords(property.Name), display?.GetDescription(),
                    display?.GetPrompt(), kind.Value, isSecret, choices);
                fields.Add((display?.GetOrder() ?? 10_000, property.MetadataToken, field));
            }
            return fields.OrderBy(f => f.Order).ThenBy(f => f.Token).Select(f => f.Field).ToList();
        }

        private static StorageOptionKind? KindOf(PropertyInfo property, out IReadOnlyList<string> choices)
        {
            choices = [];
            var type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;
            if (type.IsEnum)
            {
                choices = Enum.GetNames(type);
                return StorageOptionKind.Choice;
            }
            if (type == typeof(string))
            {
                if (property.GetCustomAttribute<AllowedValuesAttribute>() is { } allowed)
                {
                    choices = allowed.Values.Select(v => v?.ToString() ?? string.Empty).ToList();
                    return StorageOptionKind.Choice;
                }
                return StorageOptionKind.Text;
            }
            if (type == typeof(bool))
                return StorageOptionKind.Boolean;
            if (type == typeof(int) || type == typeof(long) || type == typeof(short) || type == typeof(uint) || type == typeof(ulong) || type == typeof(ushort))
                return StorageOptionKind.Number;
            return null;
        }

        /// <summary>"RootDirectory" gives "Root directory".</summary>
        private static string SplitWords(string name)
        {
            var words = new System.Text.StringBuilder();
            foreach (var c in name)
            {
                if (words.Length > 0 && char.IsUpper(c))
                    words.Append(' ').Append(char.ToLowerInvariant(c));
                else
                    words.Append(c);
            }
            return words.ToString();
        }
    }
}
