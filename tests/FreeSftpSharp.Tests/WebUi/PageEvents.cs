using AngleSharp.Dom;
using Bunit;
using Bunit.Rendering;
using Microsoft.AspNetCore.Components;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// Triggers an event on an element that is found again for each event. A page can render again between the moment
/// a test finds an element and the moment it triggers the event (a save that reloads the form, for example). The
/// event handler id of the found element is then stale and bUnit throws <see cref="UnknownEventHandlerIdException"/>.
/// These helpers find the element again and retry, so the event always reaches the current render tree.
/// The assertions of the tests are not changed.
/// </summary>
internal static class PageEvents
{
    private const int Attempts = 100;

    public static void Change<TComponent, TValue>(this IRenderedComponent<TComponent> cut, string selector, TValue value)
        where TComponent : IComponent =>
        Trigger(() => cut.Find(selector), element => element.Change(value));

    public static void Input<TComponent, TValue>(this IRenderedComponent<TComponent> cut, string selector, TValue value)
        where TComponent : IComponent =>
        Trigger(() => cut.Find(selector), element => element.Input(value));

    public static void Click<TComponent>(this IRenderedComponent<TComponent> cut, string selector)
        where TComponent : IComponent =>
        Trigger(() => cut.Find(selector), element => element.Click());

    public static void Submit<TComponent>(this IRenderedComponent<TComponent> cut, string selector)
        where TComponent : IComponent =>
        Trigger(() => cut.Find(selector), element => element.Submit());

    /// <summary>Clicks the element at <paramref name="index"/> of all elements that match the selector.</summary>
    public static void Click<TComponent>(this IRenderedComponent<TComponent> cut, string selector, int index)
        where TComponent : IComponent =>
        Trigger(() => cut.FindAll(selector)[index], element => element.Click());

    /// <summary>Finds an element with <paramref name="find"/> and runs <paramref name="act"/> on it, again if the element is stale.</summary>
    public static void Trigger(Func<IElement> find, Action<IElement> act)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                act(find());
                return;
            }
            catch (UnknownEventHandlerIdException) when (attempt < Attempts)
            {
                Thread.Sleep(10);
            }
        }
    }
}
