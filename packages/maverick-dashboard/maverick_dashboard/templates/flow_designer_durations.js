// Duration labels and choices for the workflow designer; no DOM dependencies.
var FDDurations = (function () {
  'use strict';
  var DURATIONS = [{ v: '60', t: '1 minute' }, { v: '300', t: '5 minutes' }, { v: '900', t: '15 minutes' },
    { v: '1800', t: '30 minutes' }, { v: '3600', t: '1 hour' }, { v: '14400', t: '4 hours' },
    { v: '86400', t: '1 day' }, { v: '259200', t: '3 days' }, { v: '604800', t: '1 week' }];

  function durationText(sec) {
    sec = Number(sec) || 0;
    if (sec % 86400 === 0) return (sec / 86400) + (sec === 86400 ? ' day' : ' days');
    if (sec % 3600 === 0) return (sec / 3600) + (sec === 3600 ? ' hour' : ' hours');
    if (sec % 60 === 0) return (sec / 60) + (sec === 60 ? ' minute' : ' minutes');
    return sec + (sec === 1 ? ' second' : ' seconds');
  }
  function durationOptions(value, none) {
    var opts = [{ v: '0', t: none }].concat(DURATIONS);
    var cur = String(Math.round(Number(value) || 0));
    if (!opts.some(function (o) { return o.v === cur; })) opts.push({ v: cur, t: durationText(Number(cur)) });
    return opts;
  }
  function retryWaitOptions(value) {
    var options = [{ v: '0', t: 'No wait' }, { v: '10', t: '10 seconds' }, { v: '30', t: '30 seconds' }];
    var saved = Number(value) || 0;
    if (!options.some(function (option) { return Number(option.v) === saved; })) {
      options.push({ v: String(saved), t: saved > 30
        ? 'Saved request: ' + durationText(saved) + ' (first wait: 30 seconds)'
        : 'Saved request: ' + durationText(saved) });
    }
    return options;
  }
  return { durationText: durationText, durationOptions: durationOptions, retryWaitOptions: retryWaitOptions };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDDurations;
