const crypto = require('crypto');

// CWE-328: Using MD5
function hashData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// CWE-79: XSS via innerHTML
function renderUser(user) {
    document.getElementById('user').innerHTML = user.name;
}

// CWE-95: eval usage
function parseConfig(str) {
    return eval('(' + str + ')');
}
