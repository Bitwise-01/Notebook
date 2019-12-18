/*
 * Only for debugging. Prevents session from expiring.
 */

'use strict';

const DEBUG = false;
const autoRefreshDelay = 50 * 1000; // 50 seconds

$(document).ready(() => {
    if (DEBUG) {
        setInterval(sessionCheck, autoRefreshDelay);
    }
});
