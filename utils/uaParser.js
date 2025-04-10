const parser = require('ua-parser-js');

const parseUserAgent = (ua) => {
    const parsed = parser(ua || '');
    return `${parsed.browser.name} on ${parsed.os.name}`;
};

module.exports = parseUserAgent;