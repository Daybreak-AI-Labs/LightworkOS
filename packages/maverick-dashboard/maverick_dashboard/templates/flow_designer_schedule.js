// Pure schedule parsing and presentation for the workflow designer.
var FDSchedule = (function () {
  'use strict';
  var WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  var HOURS = [1, 2, 3, 4, 6, 8, 12];

  function clockWords(h, m) {
    var hour = Number(h), mm = ('0' + m).slice(-2);
    return (hour % 12 || 12) + (mm === '00' ? '' : ':' + mm) + (hour < 12 ? ' am' : ' pm');
  }
  function ordinalWords(n) {
    n = Number(n);
    var t = ['th', 'st', 'nd', 'rd'], v = n % 100;
    return n + (t[(v - 20) % 10] || t[v] || t[0]);
  }
  function scheduleHours(hour) {
    if (hour === '*') return 1;
    var match = /^\*\/(\d+)$/.exec(hour);
    return match && HOURS.indexOf(Number(match[1])) >= 0 ? Number(match[1]) : null;
  }
  function words(cron) {
    var f = String(cron || '').trim().split(/\s+/);
    if (f.length !== 5) return 'a custom timetable';
    var mi = f[0], hr = f[1], dom = f[2], mon = f[3], dow = f[4];
    var every = scheduleHours(hr);
    if (/^\d+$/.test(mi) && every && dom === '*' && mon === '*' && dow === '*') return (every === 1 ? 'every hour' : 'every ' + every + ' hours') + ' at ' + Number(mi) + (Number(mi) === 1 ? ' minute past' : ' minutes past');
    if (!/^\d+$/.test(mi) || !/^\d+$/.test(hr) || mon !== '*') return 'a custom timetable';
    var at = ' at ' + clockWords(hr, mi);
    if (dom === '*' && dow === '*') return 'every day' + at;
    if (dom === '*' && dow === '1-5') return 'weekdays' + at;
    if (dom === '*' && /^[0-7](,[0-7])*$/.test(dow)) return 'every ' + dow.split(',').map(function (d) { return WEEKDAYS[Number(d) % 7]; }).join(', ') + at;
    if (/^\d+$/.test(dom) && dow === '*') return 'monthly on the ' + ordinalWords(dom) + at;
    return 'a custom timetable';
  }
  function parse(cron) {
    var f = String(cron || '').trim().split(/\s+/);
    if (!cron || !String(cron).trim()) return { freq: '' };
    if (f.length !== 5) return { freq: 'custom' };
    var mi = f[0], hr = f[1], dom = f[2], mon = f[3], dow = f[4];
    if (mon !== '*' || !/^\d+$/.test(mi) || Number(mi) > 59) return { freq: 'custom' };
    var every = scheduleHours(hr);
    if (every && dom === '*' && dow === '*') return { freq: 'hourly', minute: mi, every: every };
    if (!/^\d+$/.test(hr) || Number(hr) > 23) return { freq: 'custom' };
    var time = ('0' + hr).slice(-2) + ':' + ('0' + mi).slice(-2);
    if (dom === '*' && dow === '*') return { freq: 'daily', time: time };
    if (dom === '*' && dow === '1-5') return { freq: 'weekdays', time: time };
    if (dom === '*' && /^[0-7](,[0-7])*$/.test(dow)) return { freq: 'weekly', time: time, days: dow.split(',').map(function (d) { return String(Number(d) % 7); }) };
    if (/^\d+$/.test(dom) && Number(dom) >= 1 && Number(dom) <= 31 && dow === '*') return { freq: 'monthly', time: time, dom: dom };
    return { freq: 'custom' };
  }
  function build(options) {
    var freq = options.freq || '';
    var time = String(options.time || '09:00').split(':');
    var hr = String(Number(time[0]) || 0), mi = String(Number(time[1]) || 0);
    if (freq === '') return '';
    if (freq === 'custom') return String(options.cron || '').trim();
    if (freq === 'hourly') {
      var every = Number(options.every) || 1;
      return String(Number(options.minute) || 0) + ' ' + (every === 1 ? '*' : '*/' + every) + ' * * *';
    }
    if (freq === 'daily') return mi + ' ' + hr + ' * * *';
    if (freq === 'weekdays') return mi + ' ' + hr + ' * * 1-5';
    if (freq === 'weekly') {
      var days = options.days || [];
      return mi + ' ' + hr + ' * * ' + (days.length ? days.join(',') : '1');
    }
    if (freq === 'monthly') return mi + ' ' + hr + ' ' + (options.dom || '1') + ' * *';
    return '';
  }
  return { parse: parse, build: build, words: words };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDSchedule;
