// Transport helpers for workflow requests and their mutation receipts.
var FDTransport = (function () {
  'use strict';

  function fetchJson(fetcher, url, options) {
    return fetcher(url, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options || {}));
  }

  function unconfirmedMutation(action) {
    return action + ' could not be confirmed. ' + (action === 'Run'
      ? 'Check recent runs before retrying.' : 'Reload the flow before retrying.');
  }

  async function readMutationResult(response, action, options) {
    var result;
    try { result = options.recipeInputs && typeof response.text === 'function'
      ? await options.recipeInputs.responseJson(response) : await response.json(); }
    catch (e) { throw new Error(unconfirmedMutation(action)); }
    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      throw new Error(unconfirmedMutation(action));
    }
    if (!response.ok) throw new Error(options.failText(response, action));
    return result;
  }

  function validPublication(result) {
    return typeof result.published === 'boolean' && (result.published
      ? Number.isInteger(result.published_version) && result.published_version > 0 &&
        typeof result.published_revision === 'string' && !!result.published_revision.trim()
      : result.published_version === null && result.published_revision === '');
  }

  return { fetchJson: fetchJson, unconfirmedMutation: unconfirmedMutation,
    readMutationResult: readMutationResult, validPublication: validPublication };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = FDTransport;
