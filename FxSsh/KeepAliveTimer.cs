using System;
using System.Collections.Generic;
using System.Text;
using System.Timers;

namespace FxSsh
{
    public class KeepAliveTimer : IDisposable
    {
        private readonly Timer _timer;
        private DateTime _startTime;
        private TimeSpan? _runTime;

        
        public Action Action { get; set; }
        public bool Running { get; private set; }

        public KeepAliveTimer(double intervalmilliseconds, Action action)
        {
            
            Action = action;
            _timer = new Timer(intervalmilliseconds );
            _timer.Elapsed += TimerExpired;
            _timer.Start();
        }

        public void Dispose()
        {
            _timer.Stop();
            _timer.Dispose();
        }

        private void TimerExpired(object sender, EventArgs e)
        {
            lock (_timer)
            {
                Running = false;
                _timer.Stop();
                _runTime = DateTime.UtcNow.Subtract(_startTime);
                Action();
                _startTime = DateTime.UtcNow;
                _timer.Start();
                Running = true;
            }
        }

        public void Nudge()
        {
            lock (_timer)
            {
                if (!Running)
                {
                    _startTime = DateTime.UtcNow;
                    _runTime = null;
                    _timer.Start();
                    Running = true;
                }
                else
                {
                    //Reset the timer
                    _timer.Stop();
                    _timer.Start();
                }
            }
        }

        public TimeSpan GetTimeSpan()
        {
            return _runTime ?? DateTime.UtcNow.Subtract(_startTime);
        }
    }
}
