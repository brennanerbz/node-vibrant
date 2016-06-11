(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var punycode = require('punycode');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
    delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],

    // RFC 2396: characters not allowed for various reasons.
    unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
    autoEscape = ['\''].concat(unwise),
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
    nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([a-z0-9A-Z_-]{0,63})(.*)$/,
    // protocols that can allow "unsafe" and "unwise" chars.
    unsafeProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that never have a hostname.
    hostlessProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that always contain a // bit.
    slashedProtocol = {
      'http': true,
      'https': true,
      'ftp': true,
      'gopher': true,
      'file': true,
      'http:': true,
      'https:': true,
      'ftp:': true,
      'gopher:': true,
      'file:': true
    },
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && isObject(url) && url instanceof Url) return url;

  var u = new Url;
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
  if (!isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
  }

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1)
      hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' &&
        this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a puny coded representation of "domain".
      // It only converts the part of the domain name that
      // has non ASCII characters. I.e. it dosent matter if
      // you call it with a domain that already is in ASCII.
      var domainArray = this.hostname.split('.');
      var newOut = [];
      for (var i = 0; i < domainArray.length; ++i) {
        var s = domainArray[i];
        newOut.push(s.match(/[^A-Za-z0-9_-]/) ?
            'xn--' + punycode.encode(s) : s);
      }
      this.hostname = newOut.join('.');
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }


  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] &&
      this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function() {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ?
        this.hostname :
        '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query &&
      isObject(this.query) &&
      Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || (query && ('?' + query)) || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes ||
      (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function(match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function(relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function(relative) {
  if (isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  Object.keys(this).forEach(function(k) {
    result[k] = this[k];
  }, this);

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    Object.keys(relative).forEach(function(k) {
      if (k !== 'protocol')
        result[k] = relative[k];
    });

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] &&
        result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      Object.keys(relative).forEach(function(k) {
        result[k] = relative[k];
      });
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift()));
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
      isRelAbs = (
          relative.host ||
          relative.pathname && relative.pathname.charAt(0) === '/'
      ),
      mustEndAbs = (isRelAbs || isSourceAbs ||
                    (result.host && relative.pathname)),
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;
      else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;
        else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = (relative.host || relative.host === '') ?
                  relative.host : result.host;
    result.hostname = (relative.hostname || relative.hostname === '') ?
                      relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especialy happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ?
                       result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!isNull(result.pathname) || !isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') +
                    (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (
      (result.host || relative.host) && (last === '.' || last === '..') ||
      last === '');

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last == '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' &&
      (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' ||
      (srcPath[0] && srcPath[0].charAt(0) === '/');

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' :
                                    srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especialy happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ?
                     result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || (result.host && srcPath.length);

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!isNull(result.pathname) || !isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') +
                  (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function() {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

function isString(arg) {
  return typeof arg === "string";
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isNull(arg) {
  return arg === null;
}
function isNullOrUndefined(arg) {
  return  arg == null;
}

},{"punycode":2,"querystring":6}],2:[function(require,module,exports){
(function (global){
/*! https://mths.be/punycode v1.3.2 by @mathias */
;(function(root) {

	/** Detect free variables */
	var freeExports = typeof exports == 'object' && exports &&
		!exports.nodeType && exports;
	var freeModule = typeof module == 'object' && module &&
		!module.nodeType && module;
	var freeGlobal = typeof global == 'object' && global;
	if (
		freeGlobal.global === freeGlobal ||
		freeGlobal.window === freeGlobal ||
		freeGlobal.self === freeGlobal
	) {
		root = freeGlobal;
	}

	/**
	 * The `punycode` object.
	 * @name punycode
	 * @type Object
	 */
	var punycode,

	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	tMin = 1,
	tMax = 26,
	skew = 38,
	damp = 700,
	initialBias = 72,
	initialN = 128, // 0x80
	delimiter = '-', // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	regexNonASCII = /[^\x20-\x7E]/, // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g, // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},

	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	floor = Math.floor,
	stringFromCharCode = String.fromCharCode,

	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
	 * A generic error utility function.
	 * @private
	 * @param {String} type The error type.
	 * @returns {Error} Throws a `RangeError` with the applicable error message.
	 */
	function error(type) {
		throw RangeError(errors[type]);
	}

	/**
	 * A generic `Array#map` utility function.
	 * @private
	 * @param {Array} array The array to iterate over.
	 * @param {Function} callback The function that gets called for every array
	 * item.
	 * @returns {Array} A new array of values returned by the callback function.
	 */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
	 * A simple `Array#map`-like wrapper to work with domain name strings or email
	 * addresses.
	 * @private
	 * @param {String} domain The domain name or email address.
	 * @param {Function} callback The function that gets called for every
	 * character.
	 * @returns {Array} A new string of characters returned by the callback
	 * function.
	 */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
	 * Creates an array containing the numeric code points of each Unicode
	 * character in the string. While JavaScript uses UCS-2 internally,
	 * this function will convert a pair of surrogate halves (each of which
	 * UCS-2 exposes as separate characters) into a single code point,
	 * matching UTF-16.
	 * @see `punycode.ucs2.encode`
	 * @see <https://mathiasbynens.be/notes/javascript-encoding>
	 * @memberOf punycode.ucs2
	 * @name decode
	 * @param {String} string The Unicode input string (UCS-2).
	 * @returns {Array} The new array of code points.
	 */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
	 * Creates a string based on an array of numeric code points.
	 * @see `punycode.ucs2.decode`
	 * @memberOf punycode.ucs2
	 * @name encode
	 * @param {Array} codePoints The array of numeric code points.
	 * @returns {String} The new Unicode string (UCS-2).
	 */
	function ucs2encode(array) {
		return map(array, function(value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
	 * Converts a basic code point into a digit/integer.
	 * @see `digitToBasic()`
	 * @private
	 * @param {Number} codePoint The basic numeric code point value.
	 * @returns {Number} The numeric value of a basic code point (for use in
	 * representing integers) in the range `0` to `base - 1`, or `base` if
	 * the code point does not represent a value.
	 */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
	 * Converts a digit/integer into a basic code point.
	 * @see `basicToDigit()`
	 * @private
	 * @param {Number} digit The numeric value of a basic code point.
	 * @returns {Number} The basic code point whose value (when used for
	 * representing integers) is `digit`, which needs to be in the range
	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
	 * used; else, the lowercase form is used. The behavior is undefined
	 * if `flag` is non-zero and `digit` has no uppercase form.
	 */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
	 * Bias adaptation function as per section 3.4 of RFC 3492.
	 * http://tools.ietf.org/html/rfc3492#section-3.4
	 * @private
	 */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The Punycode string of ASCII-only symbols.
	 * @returns {String} The resulting string of Unicode symbols.
	 */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,
		    /** Cached calculation results */
		    baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;

			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);

		}

		return ucs2encode(output);
	}

	/**
	 * Converts a string of Unicode symbols (e.g. a domain name label) to a
	 * Punycode string of ASCII-only symbols.
	 * @memberOf punycode
	 * @param {String} input The string of Unicode symbols.
	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
	 */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],
		    /** `inputLength` will hold the number of code points in `input`. */
		    inputLength,
		    /** Cached calculation results */
		    handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base; /* no condition */; k += base) {
						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(
							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
						);
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;

		}
		return output.join('');
	}

	/**
	 * Converts a Punycode string representing a domain name or an email address
	 * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
	 * it doesn't matter if you call it on a string that has already been
	 * converted to Unicode.
	 * @memberOf punycode
	 * @param {String} input The Punycoded domain name or email address to
	 * convert to Unicode.
	 * @returns {String} The Unicode representation of the given Punycode
	 * string.
	 */
	function toUnicode(input) {
		return mapDomain(input, function(string) {
			return regexPunycode.test(string)
				? decode(string.slice(4).toLowerCase())
				: string;
		});
	}

	/**
	 * Converts a Unicode string representing a domain name or an email address to
	 * Punycode. Only the non-ASCII parts of the domain name will be converted,
	 * i.e. it doesn't matter if you call it with a domain that's already in
	 * ASCII.
	 * @memberOf punycode
	 * @param {String} input The domain name or email address to convert, as a
	 * Unicode string.
	 * @returns {String} The Punycode representation of the given domain name or
	 * email address.
	 */
	function toASCII(input) {
		return mapDomain(input, function(string) {
			return regexNonASCII.test(string)
				? 'xn--' + encode(string)
				: string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
		 * A string representing the current Punycode.js version number.
		 * @memberOf punycode
		 * @type String
		 */
		'version': '1.3.2',
		/**
		 * An object of methods to convert from JavaScript's internal character
		 * representation (UCS-2) to Unicode code points, and back.
		 * @see <https://mathiasbynens.be/notes/javascript-encoding>
		 * @memberOf punycode
		 * @type Object
		 */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define('punycode', function() {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) { // in Node.js or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else { // in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else { // in Rhino or a web browser
		root.punycode = punycode;
	}

}(this));

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],3:[function(require,module,exports){
/*
 * quantize.js Copyright 2008 Nick Rabinowitz
 * Ported to node.js by Olivier Lesnicki
 * Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
 */

// fill out a couple protovis dependencies
/*
 * Block below copied from Protovis: http://mbostock.github.com/protovis/
 * Copyright 2010 Stanford Visualization Group
 * Licensed under the BSD License: http://www.opensource.org/licenses/bsd-license.php
 */
if (!pv) {
    var pv = {
        map: function(array, f) {
            var o = {};
            return f ? array.map(function(d, i) {
                o.index = i;
                return f.call(o, d);
            }) : array.slice();
        },
        naturalOrder: function(a, b) {
            return (a < b) ? -1 : ((a > b) ? 1 : 0);
        },
        sum: function(array, f) {
            var o = {};
            return array.reduce(f ? function(p, d, i) {
                o.index = i;
                return p + f.call(o, d);
            } : function(p, d) {
                return p + d;
            }, 0);
        },
        max: function(array, f) {
            return Math.max.apply(null, f ? pv.map(array, f) : array);
        }
    }
}

/**
 * Basic Javascript port of the MMCQ (modified median cut quantization)
 * algorithm from the Leptonica library (http://www.leptonica.com/).
 * Returns a color map you can use to map original pixels to the reduced
 * palette. Still a work in progress.
 * 
 * @author Nick Rabinowitz
 * @example
 
// array of pixels as [R,G,B] arrays
var myPixels = [[190,197,190], [202,204,200], [207,214,210], [211,214,211], [205,207,207]
                // etc
                ];
var maxColors = 4;
 
var cmap = MMCQ.quantize(myPixels, maxColors);
var newPalette = cmap.palette();
var newPixels = myPixels.map(function(p) { 
    return cmap.map(p); 
});
 
 */
var MMCQ = (function() {
    // private constants
    var sigbits = 5,
        rshift = 8 - sigbits,
        maxIterations = 1000,
        fractByPopulations = 0.75;

    // get reduced-space color index for a pixel

    function getColorIndex(r, g, b) {
        return (r << (2 * sigbits)) + (g << sigbits) + b;
    }

    // Simple priority queue

    function PQueue(comparator) {
        var contents = [],
            sorted = false;

        function sort() {
            contents.sort(comparator);
            sorted = true;
        }

        return {
            push: function(o) {
                contents.push(o);
                sorted = false;
            },
            peek: function(index) {
                if (!sorted) sort();
                if (index === undefined) index = contents.length - 1;
                return contents[index];
            },
            pop: function() {
                if (!sorted) sort();
                return contents.pop();
            },
            size: function() {
                return contents.length;
            },
            map: function(f) {
                return contents.map(f);
            },
            debug: function() {
                if (!sorted) sort();
                return contents;
            }
        };
    }

    // 3d color space box

    function VBox(r1, r2, g1, g2, b1, b2, histo) {
        var vbox = this;
        vbox.r1 = r1;
        vbox.r2 = r2;
        vbox.g1 = g1;
        vbox.g2 = g2;
        vbox.b1 = b1;
        vbox.b2 = b2;
        vbox.histo = histo;
    }
    VBox.prototype = {
        volume: function(force) {
            var vbox = this;
            if (!vbox._volume || force) {
                vbox._volume = ((vbox.r2 - vbox.r1 + 1) * (vbox.g2 - vbox.g1 + 1) * (vbox.b2 - vbox.b1 + 1));
            }
            return vbox._volume;
        },
        count: function(force) {
            var vbox = this,
                histo = vbox.histo;
            if (!vbox._count_set || force) {
                var npix = 0,
                    i, j, k, index;
                for (i = vbox.r1; i <= vbox.r2; i++) {
                    for (j = vbox.g1; j <= vbox.g2; j++) {
                        for (k = vbox.b1; k <= vbox.b2; k++) {
                            index = getColorIndex(i, j, k);
                            npix += (histo[index] || 0);
                        }
                    }
                }
                vbox._count = npix;
                vbox._count_set = true;
            }
            return vbox._count;
        },
        copy: function() {
            var vbox = this;
            return new VBox(vbox.r1, vbox.r2, vbox.g1, vbox.g2, vbox.b1, vbox.b2, vbox.histo);
        },
        avg: function(force) {
            var vbox = this,
                histo = vbox.histo;
            if (!vbox._avg || force) {
                var ntot = 0,
                    mult = 1 << (8 - sigbits),
                    rsum = 0,
                    gsum = 0,
                    bsum = 0,
                    hval,
                    i, j, k, histoindex;
                for (i = vbox.r1; i <= vbox.r2; i++) {
                    for (j = vbox.g1; j <= vbox.g2; j++) {
                        for (k = vbox.b1; k <= vbox.b2; k++) {
                            histoindex = getColorIndex(i, j, k);
                            hval = histo[histoindex] || 0;
                            ntot += hval;
                            rsum += (hval * (i + 0.5) * mult);
                            gsum += (hval * (j + 0.5) * mult);
                            bsum += (hval * (k + 0.5) * mult);
                        }
                    }
                }
                if (ntot) {
                    vbox._avg = [~~(rsum / ntot), ~~ (gsum / ntot), ~~ (bsum / ntot)];
                } else {
                    //console.log('empty box');
                    vbox._avg = [~~(mult * (vbox.r1 + vbox.r2 + 1) / 2), ~~ (mult * (vbox.g1 + vbox.g2 + 1) / 2), ~~ (mult * (vbox.b1 + vbox.b2 + 1) / 2)];
                }
            }
            return vbox._avg;
        },
        contains: function(pixel) {
            var vbox = this,
                rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            return (rval >= vbox.r1 && rval <= vbox.r2 &&
                gval >= vbox.g1 && gval <= vbox.g2 &&
                bval >= vbox.b1 && bval <= vbox.b2);
        }
    };

    // Color map

    function CMap() {
        this.vboxes = new PQueue(function(a, b) {
            return pv.naturalOrder(
                a.vbox.count() * a.vbox.volume(),
                b.vbox.count() * b.vbox.volume()
            )
        });;
    }
    CMap.prototype = {
        push: function(vbox) {
            this.vboxes.push({
                vbox: vbox,
                color: vbox.avg()
            });
        },
        palette: function() {
            return this.vboxes.map(function(vb) {
                return vb.color
            });
        },
        size: function() {
            return this.vboxes.size();
        },
        map: function(color) {
            var vboxes = this.vboxes;
            for (var i = 0; i < vboxes.size(); i++) {
                if (vboxes.peek(i).vbox.contains(color)) {
                    return vboxes.peek(i).color;
                }
            }
            return this.nearest(color);
        },
        nearest: function(color) {
            var vboxes = this.vboxes,
                d1, d2, pColor;
            for (var i = 0; i < vboxes.size(); i++) {
                d2 = Math.sqrt(
                    Math.pow(color[0] - vboxes.peek(i).color[0], 2) +
                    Math.pow(color[1] - vboxes.peek(i).color[1], 2) +
                    Math.pow(color[2] - vboxes.peek(i).color[2], 2)
                );
                if (d2 < d1 || d1 === undefined) {
                    d1 = d2;
                    pColor = vboxes.peek(i).color;
                }
            }
            return pColor;
        },
        forcebw: function() {
            // XXX: won't  work yet
            var vboxes = this.vboxes;
            vboxes.sort(function(a, b) {
                return pv.naturalOrder(pv.sum(a.color), pv.sum(b.color))
            });

            // force darkest color to black if everything < 5
            var lowest = vboxes[0].color;
            if (lowest[0] < 5 && lowest[1] < 5 && lowest[2] < 5)
                vboxes[0].color = [0, 0, 0];

            // force lightest color to white if everything > 251
            var idx = vboxes.length - 1,
                highest = vboxes[idx].color;
            if (highest[0] > 251 && highest[1] > 251 && highest[2] > 251)
                vboxes[idx].color = [255, 255, 255];
        }
    };

    // histo (1-d array, giving the number of pixels in
    // each quantized region of color space), or null on error

    function getHisto(pixels) {
        var histosize = 1 << (3 * sigbits),
            histo = new Array(histosize),
            index, rval, gval, bval;
        pixels.forEach(function(pixel) {
            rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            index = getColorIndex(rval, gval, bval);
            histo[index] = (histo[index] || 0) + 1;
        });
        return histo;
    }

    function vboxFromPixels(pixels, histo) {
        var rmin = 1000000,
            rmax = 0,
            gmin = 1000000,
            gmax = 0,
            bmin = 1000000,
            bmax = 0,
            rval, gval, bval;
        // find min/max
        pixels.forEach(function(pixel) {
            rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            if (rval < rmin) rmin = rval;
            else if (rval > rmax) rmax = rval;
            if (gval < gmin) gmin = gval;
            else if (gval > gmax) gmax = gval;
            if (bval < bmin) bmin = bval;
            else if (bval > bmax) bmax = bval;
        });
        return new VBox(rmin, rmax, gmin, gmax, bmin, bmax, histo);
    }

    function medianCutApply(histo, vbox) {
        if (!vbox.count()) return;

        var rw = vbox.r2 - vbox.r1 + 1,
            gw = vbox.g2 - vbox.g1 + 1,
            bw = vbox.b2 - vbox.b1 + 1,
            maxw = pv.max([rw, gw, bw]);
        // only one pixel, no split
        if (vbox.count() == 1) {
            return [vbox.copy()]
        }
        /* Find the partial sum arrays along the selected axis. */
        var total = 0,
            partialsum = [],
            lookaheadsum = [],
            i, j, k, sum, index;
        if (maxw == rw) {
            for (i = vbox.r1; i <= vbox.r2; i++) {
                sum = 0;
                for (j = vbox.g1; j <= vbox.g2; j++) {
                    for (k = vbox.b1; k <= vbox.b2; k++) {
                        index = getColorIndex(i, j, k);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        } else if (maxw == gw) {
            for (i = vbox.g1; i <= vbox.g2; i++) {
                sum = 0;
                for (j = vbox.r1; j <= vbox.r2; j++) {
                    for (k = vbox.b1; k <= vbox.b2; k++) {
                        index = getColorIndex(j, i, k);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        } else { /* maxw == bw */
            for (i = vbox.b1; i <= vbox.b2; i++) {
                sum = 0;
                for (j = vbox.r1; j <= vbox.r2; j++) {
                    for (k = vbox.g1; k <= vbox.g2; k++) {
                        index = getColorIndex(j, k, i);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        }
        partialsum.forEach(function(d, i) {
            lookaheadsum[i] = total - d
        });

        function doCut(color) {
            var dim1 = color + '1',
                dim2 = color + '2',
                left, right, vbox1, vbox2, d2, count2 = 0;
            for (i = vbox[dim1]; i <= vbox[dim2]; i++) {
                if (partialsum[i] > total / 2) {
                    vbox1 = vbox.copy();
                    vbox2 = vbox.copy();
                    left = i - vbox[dim1];
                    right = vbox[dim2] - i;
                    if (left <= right)
                        d2 = Math.min(vbox[dim2] - 1, ~~ (i + right / 2));
                    else d2 = Math.max(vbox[dim1], ~~ (i - 1 - left / 2));
                    // avoid 0-count boxes
                    while (!partialsum[d2]) d2++;
                    count2 = lookaheadsum[d2];
                    while (!count2 && partialsum[d2 - 1]) count2 = lookaheadsum[--d2];
                    // set dimensions
                    vbox1[dim2] = d2;
                    vbox2[dim1] = vbox1[dim2] + 1;
                    // console.log('vbox counts:', vbox.count(), vbox1.count(), vbox2.count());
                    return [vbox1, vbox2];
                }
            }

        }
        // determine the cut planes
        return maxw == rw ? doCut('r') :
            maxw == gw ? doCut('g') :
            doCut('b');
    }

    function quantize(pixels, maxcolors) {
        // short-circuit
        if (!pixels.length || maxcolors < 2 || maxcolors > 256) {
            // console.log('wrong number of maxcolors');
            return false;
        }

        // XXX: check color content and convert to grayscale if insufficient

        var histo = getHisto(pixels),
            histosize = 1 << (3 * sigbits);

        // check that we aren't below maxcolors already
        var nColors = 0;
        histo.forEach(function() {
            nColors++
        });
        if (nColors <= maxcolors) {
            // XXX: generate the new colors from the histo and return
        }

        // get the beginning vbox from the colors
        var vbox = vboxFromPixels(pixels, histo),
            pq = new PQueue(function(a, b) {
                return pv.naturalOrder(a.count(), b.count())
            });
        pq.push(vbox);

        // inner function to do the iteration

        function iter(lh, target) {
            var ncolors = 1,
                niters = 0,
                vbox;
            while (niters < maxIterations) {
                vbox = lh.pop();
                if (!vbox.count()) { /* just put it back */
                    lh.push(vbox);
                    niters++;
                    continue;
                }
                // do the cut
                var vboxes = medianCutApply(histo, vbox),
                    vbox1 = vboxes[0],
                    vbox2 = vboxes[1];

                if (!vbox1) {
                    // console.log("vbox1 not defined; shouldn't happen!");
                    return;
                }
                lh.push(vbox1);
                if (vbox2) { /* vbox2 can be null */
                    lh.push(vbox2);
                    ncolors++;
                }
                if (ncolors >= target) return;
                if (niters++ > maxIterations) {
                    // console.log("infinite loop; perhaps too few pixels!");
                    return;
                }
            }
        }

        // first set of colors, sorted by population
        iter(pq, fractByPopulations * maxcolors);
        // console.log(pq.size(), pq.debug().length, pq.debug().slice());

        // Re-sort by the product of pixel occupancy times the size in color space.
        var pq2 = new PQueue(function(a, b) {
            return pv.naturalOrder(a.count() * a.volume(), b.count() * b.volume())
        });
        while (pq.size()) {
            pq2.push(pq.pop());
        }

        // next set - generate the median cuts using the (npix * vol) sorting.
        iter(pq2, maxcolors - pq2.size());

        // calculate the actual colors
        var cmap = new CMap();
        while (pq2.size()) {
            cmap.push(pq2.pop());
        }

        return cmap;
    }

    return {
        quantize: quantize
    }
})();

module.exports = MMCQ.quantize

},{}],4:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function(qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr, vstr, k, v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var stringifyPrimitive = function(v) {
  switch (typeof v) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function(obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if (typeof obj === 'object') {
    return map(objectKeys(obj), function(k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function(v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);

  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq +
         encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map (xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],6:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":4,"./encode":5}],7:[function(require,module,exports){
var Vibrant;

Vibrant = require('./vibrant');

Vibrant.DefaultOpts.Image = require('./image/browser');

module.exports = Vibrant;


},{"./image/browser":13,"./vibrant":22}],8:[function(require,module,exports){
var Vibrant;

window.Vibrant = Vibrant = require('./browser');


},{"./browser":7}],9:[function(require,module,exports){
module.exports = function(r, g, b, a) {
  return a >= 125 && !(r > 250 && g > 250 && b > 250);
};


},{}],10:[function(require,module,exports){
module.exports.Default = require('./default');


},{"./default":9}],11:[function(require,module,exports){
var DefaultGenerator, DefaultOpts, Generator, Swatch, util,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty,
  slice = [].slice;

Swatch = require('../swatch');

util = require('../util');

Generator = require('./index');

DefaultOpts = {
  targetDarkLuma: 0.26,
  maxDarkLuma: 0.45,
  minLightLuma: 0.55,
  targetLightLuma: 0.74,
  minNormalLuma: 0.3,
  targetNormalLuma: 0.5,
  maxNormalLuma: 0.7,
  targetMutesSaturation: 0.3,
  maxMutesSaturation: 0.4,
  targetVibrantSaturation: 1.0,
  minVibrantSaturation: 0.35,
  weightSaturation: 3,
  weightLuma: 6,
  weightPopulation: 1
};

module.exports = DefaultGenerator = (function(superClass) {
  extend(DefaultGenerator, superClass);

  function DefaultGenerator(opts) {
    this.opts = util.defaults(opts, DefaultOpts);
    this.VibrantSwatch = null;
    this.LightVibrantSwatch = null;
    this.DarkVibrantSwatch = null;
    this.MutedSwatch = null;
    this.LightMutedSwatch = null;
    this.DarkMutedSwatch = null;
  }

  DefaultGenerator.prototype.generate = function(swatches) {
    this.swatches = swatches;
    this.maxPopulation = this.findMaxPopulation();
    this.generateVarationColors();
    return this.generateEmptySwatches();
  };

  DefaultGenerator.prototype.getVibrantSwatch = function() {
    return this.VibrantSwatch;
  };

  DefaultGenerator.prototype.getLightVibrantSwatch = function() {
    return this.LightVibrantSwatch;
  };

  DefaultGenerator.prototype.getDarkVibrantSwatch = function() {
    return this.DarkVibrantSwatch;
  };

  DefaultGenerator.prototype.getMutedSwatch = function() {
    return this.MutedSwatch;
  };

  DefaultGenerator.prototype.getLightMutedSwatch = function() {
    return this.LightMutedSwatch;
  };

  DefaultGenerator.prototype.getDarkMutedSwatch = function() {
    return this.DarkMutedSwatch;
  };

  DefaultGenerator.prototype.generateVarationColors = function() {
    this.VibrantSwatch = this.findColorVariation(this.opts.targetNormalLuma, this.opts.minNormalLuma, this.opts.maxNormalLuma, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.LightVibrantSwatch = this.findColorVariation(this.opts.targetLightLuma, this.opts.minLightLuma, 1, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.DarkVibrantSwatch = this.findColorVariation(this.opts.targetDarkLuma, 0, this.opts.maxDarkLuma, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.MutedSwatch = this.findColorVariation(this.opts.targetNormalLuma, this.opts.minNormalLuma, this.opts.maxNormalLuma, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
    this.LightMutedSwatch = this.findColorVariation(this.opts.targetLightLuma, this.opts.minLightLuma, 1, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
    return this.DarkMutedSwatch = this.findColorVariation(this.opts.targetDarkLuma, 0, this.opts.maxDarkLuma, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
  };

  DefaultGenerator.prototype.generateEmptySwatches = function() {
    var hsl;
    if (this.VibrantSwatch === null) {
      if (this.DarkVibrantSwatch !== null) {
        hsl = this.DarkVibrantSwatch.getHsl();
        hsl[2] = this.opts.targetNormalLuma;
        this.VibrantSwatch = new Swatch(util.hslToRgb(hsl[0], hsl[1], hsl[2]), 0);
      }
    }
    if (this.DarkVibrantSwatch === null) {
      if (this.VibrantSwatch !== null) {
        hsl = this.VibrantSwatch.getHsl();
        hsl[2] = this.opts.targetDarkLuma;
        return this.DarkVibrantSwatch = new Swatch(util.hslToRgb(hsl[0], hsl[1], hsl[2]), 0);
      }
    }
  };

  DefaultGenerator.prototype.findMaxPopulation = function() {
    var j, len, population, ref, swatch;
    population = 0;
    ref = this.swatches;
    for (j = 0, len = ref.length; j < len; j++) {
      swatch = ref[j];
      population = Math.max(population, swatch.getPopulation());
    }
    return population;
  };

  DefaultGenerator.prototype.findColorVariation = function(targetLuma, minLuma, maxLuma, targetSaturation, minSaturation, maxSaturation) {
    var j, len, luma, max, maxValue, ref, sat, swatch, value;
    max = null;
    maxValue = 0;
    ref = this.swatches;
    for (j = 0, len = ref.length; j < len; j++) {
      swatch = ref[j];
      sat = swatch.getHsl()[1];
      luma = swatch.getHsl()[2];
      if (sat >= minSaturation && sat <= maxSaturation && luma >= minLuma && luma <= maxLuma && !this.isAlreadySelected(swatch)) {
        value = this.createComparisonValue(sat, targetSaturation, luma, targetLuma, swatch.getPopulation(), this.maxPopulation);
        if (max === null || value > maxValue) {
          max = swatch;
          maxValue = value;
        }
      }
    }
    return max;
  };

  DefaultGenerator.prototype.createComparisonValue = function(saturation, targetSaturation, luma, targetLuma, population, maxPopulation) {
    return this.weightedMean(this.invertDiff(saturation, targetSaturation), this.opts.weightSaturation, this.invertDiff(luma, targetLuma), this.opts.weightLuma, population / maxPopulation, this.opts.weightPopulation);
  };

  DefaultGenerator.prototype.invertDiff = function(value, targetValue) {
    return 1 - Math.abs(value - targetValue);
  };

  DefaultGenerator.prototype.weightedMean = function() {
    var i, sum, sumWeight, value, values, weight;
    values = 1 <= arguments.length ? slice.call(arguments, 0) : [];
    sum = 0;
    sumWeight = 0;
    i = 0;
    while (i < values.length) {
      value = values[i];
      weight = values[i + 1];
      sum += value * weight;
      sumWeight += weight;
      i += 2;
    }
    return sum / sumWeight;
  };

  DefaultGenerator.prototype.isAlreadySelected = function(swatch) {
    return this.VibrantSwatch === swatch || this.DarkVibrantSwatch === swatch || this.LightVibrantSwatch === swatch || this.MutedSwatch === swatch || this.DarkMutedSwatch === swatch || this.LightMutedSwatch === swatch;
  };

  return DefaultGenerator;

})(Generator);


},{"../swatch":20,"../util":21,"./index":12}],12:[function(require,module,exports){
var Generator;

module.exports = Generator = (function() {
  function Generator() {}

  Generator.prototype.generate = function(swatches) {};

  Generator.prototype.getVibrantSwatch = function() {};

  Generator.prototype.getLightVibrantSwatch = function() {};

  Generator.prototype.getDarkVibrantSwatch = function() {};

  Generator.prototype.getMutedSwatch = function() {};

  Generator.prototype.getLightMutedSwatch = function() {};

  Generator.prototype.getDarkMutedSwatch = function() {};

  return Generator;

})();

module.exports.Default = require('./default');


},{"./default":11}],13:[function(require,module,exports){
var BrowserImage, Image, Url, isRelativeUrl, isSameOrigin,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

Image = require('./index');

Url = require('url');

isRelativeUrl = function(url) {
  var u;
  u = Url.parse(url);
  return u.protocol === null && u.host === null && u.port === null;
};

isSameOrigin = function(a, b) {
  var ua, ub;
  ua = Url.parse(a);
  ub = Url.parse(b);
  return ua.protocol === ub.protocol && ua.hostname === ub.hostname && ua.port === ub.port;
};

module.exports = BrowserImage = (function(superClass) {
  extend(BrowserImage, superClass);

  function BrowserImage(path, cb) {
    if (typeof path === 'object' && path instanceof HTMLImageElement) {
      this.img = path;
      path = this.img.src;
    } else {
      this.img = document.createElement('img');
      this.img.src = path;
    }
    this.img.onload = (function(_this) {
      return function() {
        _this._initCanvas();
        return typeof cb === "function" ? cb(null, _this) : void 0;
      };
    })(this);
    if (this.img.complete) {
      this.img.onload();
    }
    this.img.onerror = (function(_this) {
      return function(e) {
        var err;
        err = new Error("Fail to load image: " + path);
        err.raw = e;
        return typeof cb === "function" ? cb(err) : void 0;
      };
    })(this);
  }

  BrowserImage.prototype._initCanvas = function() {
    this.canvas = document.createElement('canvas');
    this.context = this.canvas.getContext('2d');
    document.body.appendChild(this.canvas);
    this.width = this.canvas.width = this.img.width;
    this.height = this.canvas.height = this.img.height;
    return this.context.drawImage(this.img, 0, 0, this.width, this.height);
  };

  BrowserImage.prototype.clear = function() {
    return this.context.clearRect(0, 0, this.width, this.height);
  };

  BrowserImage.prototype.getWidth = function() {
    return this.width;
  };

  BrowserImage.prototype.getHeight = function() {
    return this.height;
  };

  BrowserImage.prototype.resize = function(w, h, r) {
    this.width = this.canvas.width = w;
    this.height = this.canvas.height = h;
    this.context.scale(r, r);
    return this.context.drawImage(this.img, 0, 0);
  };

  BrowserImage.prototype.update = function(imageData) {
    return this.context.putImageData(imageData, 0, 0);
  };

  BrowserImage.prototype.getPixelCount = function() {
    return this.width * this.height;
  };

  BrowserImage.prototype.getImageData = function() {
    return this.context.getImageData(0, 0, this.width, this.height);
  };

  BrowserImage.prototype.removeCanvas = function() {
    return this.canvas.parentNode.removeChild(this.canvas);
  };

  return BrowserImage;

})(Image);


},{"./index":14,"url":1}],14:[function(require,module,exports){
var Image;

module.exports = Image = (function() {
  function Image() {}

  Image.prototype.clear = function() {};

  Image.prototype.update = function(imageData) {};

  Image.prototype.getWidth = function() {};

  Image.prototype.getHeight = function() {};

  Image.prototype.scaleDown = function(opts) {
    var height, maxSide, ratio, width;
    width = this.getWidth();
    height = this.getHeight();
    ratio = 1;
    if (opts.maxDimension != null) {
      maxSide = Math.max(width, height);
      if (maxSide > opts.maxDimension) {
        ratio = opts.maxDimension / maxSide;
      }
    } else {
      ratio = 1 / opts.quality;
    }
    if (ratio < 1) {
      return this.resize(width * ratio, height * ratio, ratio);
    }
  };

  Image.prototype.resize = function(w, h, r) {};

  Image.prototype.getPixelCount = function() {};

  Image.prototype.getImageData = function() {};

  Image.prototype.removeCanvas = function() {};

  return Image;

})();


},{}],15:[function(require,module,exports){
var MMCQ, PQueue, RSHIFT, SIGBITS, Swatch, VBox, getColorIndex, ref, util;

ref = util = require('../../util'), getColorIndex = ref.getColorIndex, SIGBITS = ref.SIGBITS, RSHIFT = ref.RSHIFT;

Swatch = require('../../swatch');

VBox = require('./vbox');

PQueue = require('./pqueue');

module.exports = MMCQ = (function() {
  MMCQ.DefaultOpts = {
    maxIterations: 1000,
    fractByPopulations: 0.75
  };

  function MMCQ(opts) {
    this.opts = util.defaults(opts, this.constructor.DefaultOpts);
  }

  MMCQ.prototype.quantize = function(pixels, opts) {
    var color, colorCount, hist, pq, pq2, shouldIgnore, swatches, v, vbox;
    if (pixels.length === 0 || opts.colorCount < 2 || opts.colorCount > 256) {
      throw new Error("Wrong MMCQ parameters");
    }
    shouldIgnore = function() {
      return false;
    };
    if (Array.isArray(opts.filters) && opts.filters.length > 0) {
      shouldIgnore = function(r, g, b, a) {
        var f, i, len, ref1;
        ref1 = opts.filters;
        for (i = 0, len = ref1.length; i < len; i++) {
          f = ref1[i];
          if (!f(r, g, b, a)) {
            return true;
          }
        }
        return false;
      };
    }
    vbox = VBox.build(pixels, shouldIgnore);
    hist = vbox.hist;
    colorCount = Object.keys(hist).length;
    pq = new PQueue(function(a, b) {
      return a.count() - b.count();
    });
    pq.push(vbox);
    this._splitBoxes(pq, this.opts.fractByPopulations * opts.colorCount);
    pq2 = new PQueue(function(a, b) {
      return a.count() * a.volume() - b.count() * b.volume();
    });
    pq2.contents = pq.contents;
    this._splitBoxes(pq2, opts.colorCount - pq2.size());
    swatches = [];
    this.vboxes = [];
    while (pq2.size()) {
      v = pq2.pop();
      color = v.avg();
      if (!(typeof shouldIgnore === "function" ? shouldIgnore(color[0], color[1], color[2], 255) : void 0)) {
        this.vboxes.push(v);
        swatches.push(new Swatch(color, v.count()));
      }
    }
    return swatches;
  };

  MMCQ.prototype._splitBoxes = function(pq, target) {
    var colorCount, iteration, maxIterations, ref1, vbox, vbox1, vbox2;
    colorCount = 1;
    iteration = 0;
    maxIterations = this.opts.maxIterations;
    while (iteration < maxIterations) {
      iteration++;
      vbox = pq.pop();
      if (!vbox.count()) {
        continue;
      }
      ref1 = vbox.split(), vbox1 = ref1[0], vbox2 = ref1[1];
      pq.push(vbox1);
      if (vbox2) {
        pq.push(vbox2);
        colorCount++;
      }
      if (colorCount >= target || iteration > maxIterations) {
        return;
      }
    }
  };

  return MMCQ;

})();


},{"../../swatch":20,"../../util":21,"./pqueue":16,"./vbox":17}],16:[function(require,module,exports){
var PQueue;

module.exports = PQueue = (function() {
  function PQueue(comparator) {
    this.comparator = comparator;
    this.contents = [];
    this.sorted = false;
  }

  PQueue.prototype._sort = function() {
    this.contents.sort(this.comparator);
    return this.sorted = true;
  };

  PQueue.prototype.push = function(o) {
    this.contents.push(o);
    return this.sorted = false;
  };

  PQueue.prototype.peek = function(index) {
    if (!this.sorted) {
      this._sort();
    }
    if (index == null) {
      index = this.contents.length - 1;
    }
    return this.contents[index];
  };

  PQueue.prototype.pop = function() {
    if (!this.sorted) {
      this._sort();
    }
    return this.contents.pop();
  };

  PQueue.prototype.size = function() {
    return this.contents.length;
  };

  PQueue.prototype.map = function(f) {
    if (!this.sorted) {
      this._sort();
    }
    return this.contents.map(f);
  };

  return PQueue;

})();


},{}],17:[function(require,module,exports){
var RSHIFT, SIGBITS, VBox, getColorIndex, ref, util;

ref = util = require('../../util'), getColorIndex = ref.getColorIndex, SIGBITS = ref.SIGBITS, RSHIFT = ref.RSHIFT;

module.exports = VBox = (function() {
  VBox.build = function(pixels, shouldIgnore) {
    var a, b, bmax, bmin, g, gmax, gmin, hist, hn, i, index, n, offset, r, rmax, rmin;
    hn = 1 << (3 * SIGBITS);
    hist = new Uint32Array(hn);
    rmax = gmax = bmax = 0;
    rmin = gmin = bmin = Number.MAX_VALUE;
    n = pixels.length / 4;
    i = 0;
    while (i < n) {
      offset = i * 4;
      i++;
      r = pixels[offset + 0];
      g = pixels[offset + 1];
      b = pixels[offset + 2];
      a = pixels[offset + 3];
      if (shouldIgnore(r, g, b, a)) {
        continue;
      }
      r = r >> RSHIFT;
      g = g >> RSHIFT;
      b = b >> RSHIFT;
      index = getColorIndex(r, g, b);
      hist[index] += 1;
      if (r > rmax) {
        rmax = r;
      }
      if (r < rmin) {
        rmin = r;
      }
      if (g > gmax) {
        gmax = g;
      }
      if (g < gmin) {
        gmin = g;
      }
      if (b > bmax) {
        bmax = b;
      }
      if (b < bmin) {
        bmin = b;
      }
    }
    return new VBox(rmin, rmax, gmin, gmax, bmin, bmax, hist);
  };

  function VBox(r1, r2, g1, g2, b1, b2, hist1) {
    this.r1 = r1;
    this.r2 = r2;
    this.g1 = g1;
    this.g2 = g2;
    this.b1 = b1;
    this.b2 = b2;
    this.hist = hist1;
  }

  VBox.prototype.invalidate = function() {
    delete this._count;
    delete this._avg;
    return delete this._volume;
  };

  VBox.prototype.volume = function() {
    if (this._volume == null) {
      this._volume = (this.r2 - this.r1 + 1) * (this.g2 - this.g1 + 1) * (this.b2 - this.b1 + 1);
    }
    return this._volume;
  };

  VBox.prototype.count = function() {
    var c, hist;
    if (this._count == null) {
      hist = this.hist;
      c = 0;
      
      for (var r = this.r1; r <= this.r2; r++) {
        for (var g = this.g1; g <= this.g2; g++) {
          for (var b = this.b1; b <= this.b2; b++) {
            var index = getColorIndex(r, g, b);
            c += hist[index];
          }
        }
      }
      ;
      this._count = c;
    }
    return this._count;
  };

  VBox.prototype.clone = function() {
    return new VBox(this.r1, this.r2, this.g1, this.g2, this.b1, this.b2, this.hist);
  };

  VBox.prototype.avg = function() {
    var bsum, gsum, hist, mult, ntot, rsum;
    if (this._avg == null) {
      hist = this.hist;
      ntot = 0;
      mult = 1 << (8 - SIGBITS);
      rsum = gsum = bsum = 0;
      
      for (var r = this.r1; r <= this.r2; r++) {
        for (var g = this.g1; g <= this.g2; g++) {
          for (var b = this.b1; b <= this.b2; b++) {
            var index = getColorIndex(r, g, b);
            var h = hist[index];
            ntot += h;
            rsum += (h * (r + 0.5) * mult);
            gsum += (h * (g + 0.5) * mult);
            bsum += (h * (b + 0.5) * mult);
          }
        }
      }
      ;
      if (ntot) {
        this._avg = [~~(rsum / ntot), ~~(gsum / ntot), ~~(bsum / ntot)];
      } else {
        this._avg = [~~(mult * (this.r1 + this.r2 + 1) / 2), ~~(mult * (this.g1 + this.g2 + 1) / 2), ~~(mult * (this.b1 + this.b2 + 1) / 2)];
      }
    }
    return this._avg;
  };

  VBox.prototype.split = function() {
    var accSum, bw, d, doCut, gw, hist, i, j, maxd, maxw, ref1, reverseSum, rw, splitPoint, sum, total, vbox;
    hist = this.hist;
    if (!this.count()) {
      return null;
    }
    if (this.count() === 1) {
      return [this.clone()];
    }
    rw = this.r2 - this.r1 + 1;
    gw = this.g2 - this.g1 + 1;
    bw = this.b2 - this.b1 + 1;
    maxw = Math.max(rw, gw, bw);
    accSum = null;
    sum = total = 0;
    maxd = null;
    switch (maxw) {
      case rw:
        maxd = 'r';
        accSum = new Uint32Array(this.r2 + 1);
        
        for (var r = this.r1; r <= this.r2; r++) {
          sum = 0
          for (var g = this.g1; g <= this.g2; g++) {
            for (var b = this.b1; b <= this.b2; b++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[r] = total;
        }
        ;
        break;
      case gw:
        maxd = 'g';
        accSum = new Uint32Array(this.g2 + 1);
        
        for (var g = this.g1; g <= this.g2; g++) {
          sum = 0
          for (var r = this.r1; r <= this.r2; r++) {
            for (var b = this.b1; b <= this.b2; b++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[g] = total;
        }
        ;
        break;
      case bw:
        maxd = 'b';
        accSum = new Uint32Array(this.b2 + 1);
        
        for (var b = this.b1; b <= this.b2; b++) {
          sum = 0
          for (var r = this.r1; r <= this.r2; r++) {
            for (var g = this.g1; g <= this.g2; g++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[b] = total;
        }
        ;
    }
    splitPoint = -1;
    reverseSum = new Uint32Array(accSum.length);
    for (i = j = 0, ref1 = accSum.length - 1; 0 <= ref1 ? j <= ref1 : j >= ref1; i = 0 <= ref1 ? ++j : --j) {
      d = accSum[i];
      if (splitPoint < 0 && d > total / 2) {
        splitPoint = i;
      }
      reverseSum[i] = total - d;
    }
    vbox = this;
    doCut = function(d) {
      var c2, d1, d2, dim1, dim2, left, right, vbox1, vbox2;
      dim1 = d + "1";
      dim2 = d + "2";
      d1 = vbox[dim1];
      d2 = vbox[dim2];
      vbox1 = vbox.clone();
      vbox2 = vbox.clone();
      left = splitPoint - d1;
      right = d2 - splitPoint;
      if (left <= right) {
        d2 = Math.min(d2 - 1, ~~(splitPoint + right / 2));
        d2 = Math.max(0, d2);
      } else {
        d2 = Math.max(d1, ~~(splitPoint - 1 - left / 2));
        d2 = Math.min(vbox[dim2], d2);
      }
      while (!accSum[d2]) {
        d2++;
      }
      c2 = reverseSum[d2];
      while (!c2 && accSum[d2 - 1]) {
        c2 = reverseSum[--d2];
      }
      vbox1[dim2] = d2;
      vbox2[dim1] = d2 + 1;
      return [vbox1, vbox2];
    };
    return doCut(maxd);
  };

  VBox.prototype.contains = function(p) {
    var b, g, r;
    r = p[0] >> RSHIFT;
    g = p[1] >> RSHIFT;
    b = p[2] >> RSHIFT;
    return r >= this.r1 && r <= this.r2 && g >= this.g1 && g <= this.g2 && b >= this.b1 && b <= this.b2;
  };

  return VBox;

})();


},{"../../util":21}],18:[function(require,module,exports){
var Quantizer;

module.exports = Quantizer = (function() {
  function Quantizer() {}

  Quantizer.prototype.initialize = function(pixels, opts) {};

  Quantizer.prototype.getQuantizedColors = function() {};

  return Quantizer;

})();

module.exports.MMCQ = require('./mmcq');


},{"./mmcq":19}],19:[function(require,module,exports){
var MMCQ, MMCQImpl, Quantizer, Swatch,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

Swatch = require('../swatch');

Quantizer = require('./index');

MMCQImpl = require('./impl/mmcq');

module.exports = MMCQ = (function(superClass) {
  extend(MMCQ, superClass);

  function MMCQ() {
    return MMCQ.__super__.constructor.apply(this, arguments);
  }

  MMCQ.prototype.initialize = function(pixels, opts) {
    var mmcq;
    this.opts = opts;
    mmcq = new MMCQImpl();
    return this.swatches = mmcq.quantize(pixels, this.opts);
  };

  MMCQ.prototype.getQuantizedColors = function() {
    return this.swatches;
  };

  return MMCQ;

})(Quantizer);


},{"../swatch":20,"./impl/mmcq":15,"./index":18}],20:[function(require,module,exports){
var Swatch, util;

util = require('./util');


/*
  From Vibrant.js by Jari Zwarts
  Ported to node.js by AKFish

  Swatch class
 */

module.exports = Swatch = (function() {
  Swatch.prototype.hsl = void 0;

  Swatch.prototype.rgb = void 0;

  Swatch.prototype.population = 1;

  Swatch.prototype.yiq = 0;

  function Swatch(rgb, population) {
    this.rgb = rgb;
    this.population = population;
  }

  Swatch.prototype.getHsl = function() {
    if (!this.hsl) {
      return this.hsl = util.rgbToHsl(this.rgb[0], this.rgb[1], this.rgb[2]);
    } else {
      return this.hsl;
    }
  };

  Swatch.prototype.getPopulation = function() {
    return this.population;
  };

  Swatch.prototype.getRgb = function() {
    return this.rgb;
  };

  Swatch.prototype.getHex = function() {
    return util.rgbToHex(this.rgb[0], this.rgb[1], this.rgb[2]);
  };

  Swatch.prototype.getTitleTextColor = function() {
    this._ensureTextColors();
    if (this.yiq < 200) {
      return "#fff";
    } else {
      return "#000";
    }
  };

  Swatch.prototype.getBodyTextColor = function() {
    this._ensureTextColors();
    if (this.yiq < 150) {
      return "#fff";
    } else {
      return "#000";
    }
  };

  Swatch.prototype._ensureTextColors = function() {
    if (!this.yiq) {
      return this.yiq = (this.rgb[0] * 299 + this.rgb[1] * 587 + this.rgb[2] * 114) / 1000;
    }
  };

  return Swatch;

})();


},{"./util":21}],21:[function(require,module,exports){
var DELTAE94, RSHIFT, SIGBITS;

DELTAE94 = {
  NA: 0,
  PERFECT: 1,
  CLOSE: 2,
  GOOD: 10,
  SIMILAR: 50
};

SIGBITS = 5;

RSHIFT = 8 - SIGBITS;

module.exports = {
  clone: function(o) {
    var _o, key, value;
    if (typeof o === 'object') {
      if (Array.isArray(o)) {
        return o.map((function(_this) {
          return function(v) {
            return _this.clone(v);
          };
        })(this));
      } else {
        _o = {};
        for (key in o) {
          value = o[key];
          _o[key] = this.clone(value);
        }
        return _o;
      }
    }
    return o;
  },
  defaults: function() {
    var _o, i, key, len, o, value;
    o = {};
    for (i = 0, len = arguments.length; i < len; i++) {
      _o = arguments[i];
      for (key in _o) {
        value = _o[key];
        if (o[key] == null) {
          o[key] = this.clone(value);
        }
      }
    }
    return o;
  },
  hexToRgb: function(hex) {
    var m;
    m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (m != null) {
      return [m[1], m[2], m[3]].map(function(s) {
        return parseInt(s, 16);
      });
    }
    return null;
  },
  rgbToHex: function(r, g, b) {
    return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1, 7);
  },
  rgbToHsl: function(r, g, b) {
    var d, h, l, max, min, s;
    r /= 255;
    g /= 255;
    b /= 255;
    max = Math.max(r, g, b);
    min = Math.min(r, g, b);
    h = void 0;
    s = void 0;
    l = (max + min) / 2;
    if (max === min) {
      h = s = 0;
    } else {
      d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      switch (max) {
        case r:
          h = (g - b) / d + (g < b ? 6 : 0);
          break;
        case g:
          h = (b - r) / d + 2;
          break;
        case b:
          h = (r - g) / d + 4;
      }
      h /= 6;
    }
    return [h, s, l];
  },
  hslToRgb: function(h, s, l) {
    var b, g, hue2rgb, p, q, r;
    r = void 0;
    g = void 0;
    b = void 0;
    hue2rgb = function(p, q, t) {
      if (t < 0) {
        t += 1;
      }
      if (t > 1) {
        t -= 1;
      }
      if (t < 1 / 6) {
        return p + (q - p) * 6 * t;
      }
      if (t < 1 / 2) {
        return q;
      }
      if (t < 2 / 3) {
        return p + (q - p) * (2 / 3 - t) * 6;
      }
      return p;
    };
    if (s === 0) {
      r = g = b = l;
    } else {
      q = l < 0.5 ? l * (1 + s) : l + s - (l * s);
      p = 2 * l - q;
      r = hue2rgb(p, q, h + 1 / 3);
      g = hue2rgb(p, q, h);
      b = hue2rgb(p, q, h - (1 / 3));
    }
    return [r * 255, g * 255, b * 255];
  },
  rgbToXyz: function(r, g, b) {
    var x, y, z;
    r /= 255;
    g /= 255;
    b /= 255;
    r = r > 0.04045 ? Math.pow((r + 0.005) / 1.055, 2.4) : r / 12.92;
    g = g > 0.04045 ? Math.pow((g + 0.005) / 1.055, 2.4) : g / 12.92;
    b = b > 0.04045 ? Math.pow((b + 0.005) / 1.055, 2.4) : b / 12.92;
    r *= 100;
    g *= 100;
    b *= 100;
    x = r * 0.4124 + g * 0.3576 + b * 0.1805;
    y = r * 0.2126 + g * 0.7152 + b * 0.0722;
    z = r * 0.0193 + g * 0.1192 + b * 0.9505;
    return [x, y, z];
  },
  xyzToCIELab: function(x, y, z) {
    var L, REF_X, REF_Y, REF_Z, a, b;
    REF_X = 95.047;
    REF_Y = 100;
    REF_Z = 108.883;
    x /= REF_X;
    y /= REF_Y;
    z /= REF_Z;
    x = x > 0.008856 ? Math.pow(x, 1 / 3) : 7.787 * x + 16 / 116;
    y = y > 0.008856 ? Math.pow(y, 1 / 3) : 7.787 * y + 16 / 116;
    z = z > 0.008856 ? Math.pow(z, 1 / 3) : 7.787 * z + 16 / 116;
    L = 116 * y - 16;
    a = 500 * (x - y);
    b = 200 * (y - z);
    return [L, a, b];
  },
  rgbToCIELab: function(r, g, b) {
    var ref, x, y, z;
    ref = this.rgbToXyz(r, g, b), x = ref[0], y = ref[1], z = ref[2];
    return this.xyzToCIELab(x, y, z);
  },
  deltaE94: function(lab1, lab2) {
    var L1, L2, WEIGHT_C, WEIGHT_H, WEIGHT_L, a1, a2, b1, b2, dL, da, db, xC1, xC2, xDC, xDE, xDH, xDL, xSC, xSH;
    WEIGHT_L = 1;
    WEIGHT_C = 1;
    WEIGHT_H = 1;
    L1 = lab1[0], a1 = lab1[1], b1 = lab1[2];
    L2 = lab2[0], a2 = lab2[1], b2 = lab2[2];
    dL = L1 - L2;
    da = a1 - a2;
    db = b1 - b2;
    xC1 = Math.sqrt(a1 * a1 + b1 * b1);
    xC2 = Math.sqrt(a2 * a2 + b2 * b2);
    xDL = L2 - L1;
    xDC = xC2 - xC1;
    xDE = Math.sqrt(dL * dL + da * da + db * db);
    if (Math.sqrt(xDE) > Math.sqrt(Math.abs(xDL)) + Math.sqrt(Math.abs(xDC))) {
      xDH = Math.sqrt(xDE * xDE - xDL * xDL - xDC * xDC);
    } else {
      xDH = 0;
    }
    xSC = 1 + 0.045 * xC1;
    xSH = 1 + 0.015 * xC1;
    xDL /= WEIGHT_L;
    xDC /= WEIGHT_C * xSC;
    xDH /= WEIGHT_H * xSH;
    return Math.sqrt(xDL * xDL + xDC * xDC + xDH * xDH);
  },
  rgbDiff: function(rgb1, rgb2) {
    var lab1, lab2;
    lab1 = this.rgbToCIELab.apply(this, rgb1);
    lab2 = this.rgbToCIELab.apply(this, rgb2);
    return this.deltaE94(lab1, lab2);
  },
  hexDiff: function(hex1, hex2) {
    var rgb1, rgb2;
    rgb1 = this.hexToRgb(hex1);
    rgb2 = this.hexToRgb(hex2);
    return this.rgbDiff(rgb1, rgb2);
  },
  DELTAE94_DIFF_STATUS: DELTAE94,
  getColorDiffStatus: function(d) {
    if (d < DELTAE94.NA) {
      return "N/A";
    }
    if (d <= DELTAE94.PERFECT) {
      return "Perfect";
    }
    if (d <= DELTAE94.CLOSE) {
      return "Close";
    }
    if (d <= DELTAE94.GOOD) {
      return "Good";
    }
    if (d < DELTAE94.SIMILAR) {
      return "Similar";
    }
    return "Wrong";
  },
  SIGBITS: SIGBITS,
  RSHIFT: RSHIFT,
  getColorIndex: function(r, g, b) {
    return (r << (2 * SIGBITS)) + (g << SIGBITS) + b;
  }
};


},{}],22:[function(require,module,exports){

/*
  From Vibrant.js by Jari Zwarts
  Ported to node.js by AKFish

  Color algorithm class that finds variations on colors in an image.

  Credits
  --------
  Lokesh Dhakar (http://www.lokeshdhakar.com) - Created ColorThief
  Google - Palette support library in Android
 */
var Builder, DefaultGenerator, Filter, Swatch, Vibrant, util,
  bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

Swatch = require('./swatch');

util = require('./util');

DefaultGenerator = require('./generator').Default;

Filter = require('./filter');

module.exports = Vibrant = (function() {
  Vibrant.DefaultOpts = {
    colorCount: 64,
    quality: 5,
    generator: new DefaultGenerator(),
    Image: null,
    Quantizer: require('./quantizer').MMCQ,
    filters: []
  };

  Vibrant.from = function(src) {
    return new Builder(src);
  };

  Vibrant.prototype.quantize = require('quantize');

  Vibrant.prototype._swatches = [];

  function Vibrant(sourceImage, opts) {
    this.sourceImage = sourceImage;
    if (opts == null) {
      opts = {};
    }
    this.swatches = bind(this.swatches, this);
    this.opts = util.defaults(opts, this.constructor.DefaultOpts);
    this.generator = this.opts.generator;
  }

  Vibrant.prototype.getPalette = function(cb) {
    var image;
    return image = new this.opts.Image(this.sourceImage, (function(_this) {
      return function(err, image) {
        var error, error1;
        if (err != null) {
          return cb(err);
        }
        try {
          _this._process(image, _this.opts);
          return cb(null, _this.swatches());
        } catch (error1) {
          error = error1;
          return cb(error);
        }
      };
    })(this));
  };

  Vibrant.prototype.getSwatches = function(cb) {
    return this.getPalette(cb);
  };

  Vibrant.prototype._process = function(image, opts) {
    var imageData, quantizer, swatches;
    image.scaleDown(this.opts);
    imageData = image.getImageData();
    quantizer = new this.opts.Quantizer();
    quantizer.initialize(imageData.data, this.opts);
    swatches = quantizer.getQuantizedColors();
    this.generator.generate(swatches);
    return image.removeCanvas();
  };

  Vibrant.prototype.swatches = function() {
    return {
      Vibrant: this.generator.getVibrantSwatch(),
      Muted: this.generator.getMutedSwatch(),
      DarkVibrant: this.generator.getDarkVibrantSwatch(),
      DarkMuted: this.generator.getDarkMutedSwatch(),
      LightVibrant: this.generator.getLightVibrantSwatch(),
      LightMuted: this.generator.getLightMutedSwatch()
    };
  };

  return Vibrant;

})();

module.exports.Builder = Builder = (function() {
  function Builder(src1, opts1) {
    this.src = src1;
    this.opts = opts1 != null ? opts1 : {};
    this.opts.filters = util.clone(Vibrant.DefaultOpts.filters);
  }

  Builder.prototype.maxColorCount = function(n) {
    this.opts.colorCount = n;
    return this;
  };

  Builder.prototype.maxDimension = function(d) {
    this.opts.maxDimension = d;
    return this;
  };

  Builder.prototype.addFilter = function(f) {
    if (typeof f === 'function') {
      this.opts.filters.push(f);
    }
    return this;
  };

  Builder.prototype.removeFilter = function(f) {
    var i;
    if ((i = this.opts.filters.indexOf(f)) > 0) {
      this.opts.filters.splice(i);
    }
    return this;
  };

  Builder.prototype.clearFilters = function() {
    this.opts.filters = [];
    return this;
  };

  Builder.prototype.quality = function(q) {
    this.opts.quality = q;
    return this;
  };

  Builder.prototype.useImage = function(image) {
    this.opts.Image = image;
    return this;
  };

  Builder.prototype.useGenerator = function(generator) {
    this.opts.generator = generator;
    return this;
  };

  Builder.prototype.useQuantizer = function(quantizer) {
    this.opts.Quantizer = quantizer;
    return this;
  };

  Builder.prototype.build = function() {
    if (this.v == null) {
      this.v = new Vibrant(this.src, this.opts);
    }
    return this.v;
  };

  Builder.prototype.getSwatches = function(cb) {
    return this.build().getPalette(cb);
  };

  Builder.prototype.getPalette = function(cb) {
    return this.build().getPalette(cb);
  };

  Builder.prototype.from = function(src) {
    return new Vibrant(src, this.opts);
  };

  return Builder;

})();

module.exports.Util = util;

module.exports.Swatch = Swatch;

module.exports.Quantizer = require('./quantizer/');

module.exports.Generator = require('./generator/');

module.exports.Filter = require('./filter/');


},{"./filter":10,"./filter/":10,"./generator":12,"./generator/":12,"./quantizer":18,"./quantizer/":18,"./swatch":20,"./util":21,"quantize":3}]},{},[8])
//# sourceMappingURL=data:application/json;charset:utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvdXJsL3VybC5qcyIsIm5vZGVfbW9kdWxlcy9wdW55Y29kZS9wdW55Y29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWFudGl6ZS9xdWFudGl6ZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvZGVjb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9lbmNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2luZGV4LmpzIiwiL1VzZXJzL2JyZW5uYW5lcmJlem5pay9EZXNrdG9wL0BicmVubmFuLW5vZGUtdmlicmFudC9zcmMvYnJvd3Nlci5jb2ZmZWUiLCIvVXNlcnMvYnJlbm5hbmVyYmV6bmlrL0Rlc2t0b3AvQGJyZW5uYW4tbm9kZS12aWJyYW50L3NyYy9idW5kbGUuY29mZmVlIiwiL1VzZXJzL2JyZW5uYW5lcmJlem5pay9EZXNrdG9wL0BicmVubmFuLW5vZGUtdmlicmFudC9zcmMvZmlsdGVyL2RlZmF1bHQuY29mZmVlIiwiL1VzZXJzL2JyZW5uYW5lcmJlem5pay9EZXNrdG9wL0BicmVubmFuLW5vZGUtdmlicmFudC9zcmMvZmlsdGVyL2luZGV4LmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL2dlbmVyYXRvci9kZWZhdWx0LmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL2dlbmVyYXRvci9pbmRleC5jb2ZmZWUiLCIvVXNlcnMvYnJlbm5hbmVyYmV6bmlrL0Rlc2t0b3AvQGJyZW5uYW4tbm9kZS12aWJyYW50L3NyYy9pbWFnZS9icm93c2VyLmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL2ltYWdlL2luZGV4LmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL3F1YW50aXplci9pbXBsL21tY3EuY29mZmVlIiwiL1VzZXJzL2JyZW5uYW5lcmJlem5pay9EZXNrdG9wL0BicmVubmFuLW5vZGUtdmlicmFudC9zcmMvcXVhbnRpemVyL2ltcGwvcHF1ZXVlLmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL3F1YW50aXplci9pbXBsL3Zib3guY29mZmVlIiwiL1VzZXJzL2JyZW5uYW5lcmJlem5pay9EZXNrdG9wL0BicmVubmFuLW5vZGUtdmlicmFudC9zcmMvcXVhbnRpemVyL2luZGV4LmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL3F1YW50aXplci9tbWNxLmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL3N3YXRjaC5jb2ZmZWUiLCIvVXNlcnMvYnJlbm5hbmVyYmV6bmlrL0Rlc2t0b3AvQGJyZW5uYW4tbm9kZS12aWJyYW50L3NyYy91dGlsLmNvZmZlZSIsIi9Vc2Vycy9icmVubmFuZXJiZXpuaWsvRGVza3RvcC9AYnJlbm5hbi1ub2RlLXZpYnJhbnQvc3JjL3ZpYnJhbnQuY29mZmVlIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBO0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUNuc0JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ2xoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMxZUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDcEZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFD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QUN0QixNQUFNLENBQUMsT0FBTyxDQUFDLE1BQWYsR0FBd0I7O0FBQ3hCLE1BQU0sQ0FBQyxPQUFPLENBQUMsU0FBZixHQUEyQixPQUFBLENBQVEsY0FBUjs7QUFDM0IsTUFBTSxDQUFDLE9BQU8sQ0FBQyxTQUFmLEdBQTJCLE9BQUEsQ0FBUSxjQUFSOztBQUMzQixNQUFNLENBQUMsT0FBTyxDQUFDLE1BQWYsR0FBd0IsT0FBQSxDQUFRLFdBQVIiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbiBlKHQsbixyKXtmdW5jdGlvbiBzKG8sdSl7aWYoIW5bb10pe2lmKCF0W29dKXt2YXIgYT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2lmKCF1JiZhKXJldHVybiBhKG8sITApO2lmKGkpcmV0dXJuIGkobywhMCk7dmFyIGY9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitvK1wiJ1wiKTt0aHJvdyBmLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsZn12YXIgbD1uW29dPXtleHBvcnRzOnt9fTt0W29dWzBdLmNhbGwobC5leHBvcnRzLGZ1bmN0aW9uKGUpe3ZhciBuPXRbb11bMV1bZV07cmV0dXJuIHMobj9uOmUpfSxsLGwuZXhwb3J0cyxlLHQsbixyKX1yZXR1cm4gbltvXS5leHBvcnRzfXZhciBpPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7Zm9yKHZhciBvPTA7bzxyLmxlbmd0aDtvKyspcyhyW29dKTtyZXR1cm4gc30pIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbnZhciBwdW55Y29kZSA9IHJlcXVpcmUoJ3B1bnljb2RlJyk7XG5cbmV4cG9ydHMucGFyc2UgPSB1cmxQYXJzZTtcbmV4cG9ydHMucmVzb2x2ZSA9IHVybFJlc29sdmU7XG5leHBvcnRzLnJlc29sdmVPYmplY3QgPSB1cmxSZXNvbHZlT2JqZWN0O1xuZXhwb3J0cy5mb3JtYXQgPSB1cmxGb3JtYXQ7XG5cbmV4cG9ydHMuVXJsID0gVXJsO1xuXG5mdW5jdGlvbiBVcmwoKSB7XG4gIHRoaXMucHJvdG9jb2wgPSBudWxsO1xuICB0aGlzLnNsYXNoZXMgPSBudWxsO1xuICB0aGlzLmF1dGggPSBudWxsO1xuICB0aGlzLmhvc3QgPSBudWxsO1xuICB0aGlzLnBvcnQgPSBudWxsO1xuICB0aGlzLmhvc3RuYW1lID0gbnVsbDtcbiAgdGhpcy5oYXNoID0gbnVsbDtcbiAgdGhpcy5zZWFyY2ggPSBudWxsO1xuICB0aGlzLnF1ZXJ5ID0gbnVsbDtcbiAgdGhpcy5wYXRobmFtZSA9IG51bGw7XG4gIHRoaXMucGF0aCA9IG51bGw7XG4gIHRoaXMuaHJlZiA9IG51bGw7XG59XG5cbi8vIFJlZmVyZW5jZTogUkZDIDM5ODYsIFJGQyAxODA4LCBSRkMgMjM5NlxuXG4vLyBkZWZpbmUgdGhlc2UgaGVyZSBzbyBhdCBsZWFzdCB0aGV5IG9ubHkgaGF2ZSB0byBiZVxuLy8gY29tcGlsZWQgb25jZSBvbiB0aGUgZmlyc3QgbW9kdWxlIGxvYWQuXG52YXIgcHJvdG9jb2xQYXR0ZXJuID0gL14oW2EtejAtOS4rLV0rOikvaSxcbiAgICBwb3J0UGF0dGVybiA9IC86WzAtOV0qJC8sXG5cbiAgICAvLyBSRkMgMjM5NjogY2hhcmFjdGVycyByZXNlcnZlZCBmb3IgZGVsaW1pdGluZyBVUkxzLlxuICAgIC8vIFdlIGFjdHVhbGx5IGp1c3QgYXV0by1lc2NhcGUgdGhlc2UuXG4gICAgZGVsaW1zID0gWyc8JywgJz4nLCAnXCInLCAnYCcsICcgJywgJ1xccicsICdcXG4nLCAnXFx0J10sXG5cbiAgICAvLyBSRkMgMjM5NjogY2hhcmFjdGVycyBub3QgYWxsb3dlZCBmb3IgdmFyaW91cyByZWFzb25zLlxuICAgIHVud2lzZSA9IFsneycsICd9JywgJ3wnLCAnXFxcXCcsICdeJywgJ2AnXS5jb25jYXQoZGVsaW1zKSxcblxuICAgIC8vIEFsbG93ZWQgYnkgUkZDcywgYnV0IGNhdXNlIG9mIFhTUyBhdHRhY2tzLiAgQWx3YXlzIGVzY2FwZSB0aGVzZS5cbiAgICBhdXRvRXNjYXBlID0gWydcXCcnXS5jb25jYXQodW53aXNlKSxcbiAgICAvLyBDaGFyYWN0ZXJzIHRoYXQgYXJlIG5ldmVyIGV2ZXIgYWxsb3dlZCBpbiBhIGhvc3RuYW1lLlxuICAgIC8vIE5vdGUgdGhhdCBhbnkgaW52YWxpZCBjaGFycyBhcmUgYWxzbyBoYW5kbGVkLCBidXQgdGhlc2VcbiAgICAvLyBhcmUgdGhlIG9uZXMgdGhhdCBhcmUgKmV4cGVjdGVkKiB0byBiZSBzZWVuLCBzbyB3ZSBmYXN0LXBhdGhcbiAgICAvLyB0aGVtLlxuICAgIG5vbkhvc3RDaGFycyA9IFsnJScsICcvJywgJz8nLCAnOycsICcjJ10uY29uY2F0KGF1dG9Fc2NhcGUpLFxuICAgIGhvc3RFbmRpbmdDaGFycyA9IFsnLycsICc/JywgJyMnXSxcbiAgICBob3N0bmFtZU1heExlbiA9IDI1NSxcbiAgICBob3N0bmFtZVBhcnRQYXR0ZXJuID0gL15bYS16MC05QS1aXy1dezAsNjN9JC8sXG4gICAgaG9zdG5hbWVQYXJ0U3RhcnQgPSAvXihbYS16MC05QS1aXy1dezAsNjN9KSguKikkLyxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBjYW4gYWxsb3cgXCJ1bnNhZmVcIiBhbmQgXCJ1bndpc2VcIiBjaGFycy5cbiAgICB1bnNhZmVQcm90b2NvbCA9IHtcbiAgICAgICdqYXZhc2NyaXB0JzogdHJ1ZSxcbiAgICAgICdqYXZhc2NyaXB0Oic6IHRydWVcbiAgICB9LFxuICAgIC8vIHByb3RvY29scyB0aGF0IG5ldmVyIGhhdmUgYSBob3N0bmFtZS5cbiAgICBob3N0bGVzc1Byb3RvY29sID0ge1xuICAgICAgJ2phdmFzY3JpcHQnOiB0cnVlLFxuICAgICAgJ2phdmFzY3JpcHQ6JzogdHJ1ZVxuICAgIH0sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgYWx3YXlzIGNvbnRhaW4gYSAvLyBiaXQuXG4gICAgc2xhc2hlZFByb3RvY29sID0ge1xuICAgICAgJ2h0dHAnOiB0cnVlLFxuICAgICAgJ2h0dHBzJzogdHJ1ZSxcbiAgICAgICdmdHAnOiB0cnVlLFxuICAgICAgJ2dvcGhlcic6IHRydWUsXG4gICAgICAnZmlsZSc6IHRydWUsXG4gICAgICAnaHR0cDonOiB0cnVlLFxuICAgICAgJ2h0dHBzOic6IHRydWUsXG4gICAgICAnZnRwOic6IHRydWUsXG4gICAgICAnZ29waGVyOic6IHRydWUsXG4gICAgICAnZmlsZTonOiB0cnVlXG4gICAgfSxcbiAgICBxdWVyeXN0cmluZyA9IHJlcXVpcmUoJ3F1ZXJ5c3RyaW5nJyk7XG5cbmZ1bmN0aW9uIHVybFBhcnNlKHVybCwgcGFyc2VRdWVyeVN0cmluZywgc2xhc2hlc0Rlbm90ZUhvc3QpIHtcbiAgaWYgKHVybCAmJiBpc09iamVjdCh1cmwpICYmIHVybCBpbnN0YW5jZW9mIFVybCkgcmV0dXJuIHVybDtcblxuICB2YXIgdSA9IG5ldyBVcmw7XG4gIHUucGFyc2UodXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCk7XG4gIHJldHVybiB1O1xufVxuXG5VcmwucHJvdG90eXBlLnBhcnNlID0gZnVuY3Rpb24odXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCkge1xuICBpZiAoIWlzU3RyaW5nKHVybCkpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiUGFyYW1ldGVyICd1cmwnIG11c3QgYmUgYSBzdHJpbmcsIG5vdCBcIiArIHR5cGVvZiB1cmwpO1xuICB9XG5cbiAgdmFyIHJlc3QgPSB1cmw7XG5cbiAgLy8gdHJpbSBiZWZvcmUgcHJvY2VlZGluZy5cbiAgLy8gVGhpcyBpcyB0byBzdXBwb3J0IHBhcnNlIHN0dWZmIGxpa2UgXCIgIGh0dHA6Ly9mb28uY29tICBcXG5cIlxuICByZXN0ID0gcmVzdC50cmltKCk7XG5cbiAgdmFyIHByb3RvID0gcHJvdG9jb2xQYXR0ZXJuLmV4ZWMocmVzdCk7XG4gIGlmIChwcm90bykge1xuICAgIHByb3RvID0gcHJvdG9bMF07XG4gICAgdmFyIGxvd2VyUHJvdG8gPSBwcm90by50b0xvd2VyQ2FzZSgpO1xuICAgIHRoaXMucHJvdG9jb2wgPSBsb3dlclByb3RvO1xuICAgIHJlc3QgPSByZXN0LnN1YnN0cihwcm90by5sZW5ndGgpO1xuICB9XG5cbiAgLy8gZmlndXJlIG91dCBpZiBpdCdzIGdvdCBhIGhvc3RcbiAgLy8gdXNlckBzZXJ2ZXIgaXMgKmFsd2F5cyogaW50ZXJwcmV0ZWQgYXMgYSBob3N0bmFtZSwgYW5kIHVybFxuICAvLyByZXNvbHV0aW9uIHdpbGwgdHJlYXQgLy9mb28vYmFyIGFzIGhvc3Q9Zm9vLHBhdGg9YmFyIGJlY2F1c2UgdGhhdCdzXG4gIC8vIGhvdyB0aGUgYnJvd3NlciByZXNvbHZlcyByZWxhdGl2ZSBVUkxzLlxuICBpZiAoc2xhc2hlc0Rlbm90ZUhvc3QgfHwgcHJvdG8gfHwgcmVzdC5tYXRjaCgvXlxcL1xcL1teQFxcL10rQFteQFxcL10rLykpIHtcbiAgICB2YXIgc2xhc2hlcyA9IHJlc3Quc3Vic3RyKDAsIDIpID09PSAnLy8nO1xuICAgIGlmIChzbGFzaGVzICYmICEocHJvdG8gJiYgaG9zdGxlc3NQcm90b2NvbFtwcm90b10pKSB7XG4gICAgICByZXN0ID0gcmVzdC5zdWJzdHIoMik7XG4gICAgICB0aGlzLnNsYXNoZXMgPSB0cnVlO1xuICAgIH1cbiAgfVxuXG4gIGlmICghaG9zdGxlc3NQcm90b2NvbFtwcm90b10gJiZcbiAgICAgIChzbGFzaGVzIHx8IChwcm90byAmJiAhc2xhc2hlZFByb3RvY29sW3Byb3RvXSkpKSB7XG5cbiAgICAvLyB0aGVyZSdzIGEgaG9zdG5hbWUuXG4gICAgLy8gdGhlIGZpcnN0IGluc3RhbmNlIG9mIC8sID8sIDssIG9yICMgZW5kcyB0aGUgaG9zdC5cbiAgICAvL1xuICAgIC8vIElmIHRoZXJlIGlzIGFuIEAgaW4gdGhlIGhvc3RuYW1lLCB0aGVuIG5vbi1ob3N0IGNoYXJzICphcmUqIGFsbG93ZWRcbiAgICAvLyB0byB0aGUgbGVmdCBvZiB0aGUgbGFzdCBAIHNpZ24sIHVubGVzcyBzb21lIGhvc3QtZW5kaW5nIGNoYXJhY3RlclxuICAgIC8vIGNvbWVzICpiZWZvcmUqIHRoZSBALXNpZ24uXG4gICAgLy8gVVJMcyBhcmUgb2Jub3hpb3VzLlxuICAgIC8vXG4gICAgLy8gZXg6XG4gICAgLy8gaHR0cDovL2FAYkBjLyA9PiB1c2VyOmFAYiBob3N0OmNcbiAgICAvLyBodHRwOi8vYUBiP0BjID0+IHVzZXI6YSBob3N0OmMgcGF0aDovP0BjXG5cbiAgICAvLyB2MC4xMiBUT0RPKGlzYWFjcyk6IFRoaXMgaXMgbm90IHF1aXRlIGhvdyBDaHJvbWUgZG9lcyB0aGluZ3MuXG4gICAgLy8gUmV2aWV3IG91ciB0ZXN0IGNhc2UgYWdhaW5zdCBicm93c2VycyBtb3JlIGNvbXByZWhlbnNpdmVseS5cblxuICAgIC8vIGZpbmQgdGhlIGZpcnN0IGluc3RhbmNlIG9mIGFueSBob3N0RW5kaW5nQ2hhcnNcbiAgICB2YXIgaG9zdEVuZCA9IC0xO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaG9zdEVuZGluZ0NoYXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgaGVjID0gcmVzdC5pbmRleE9mKGhvc3RFbmRpbmdDaGFyc1tpXSk7XG4gICAgICBpZiAoaGVjICE9PSAtMSAmJiAoaG9zdEVuZCA9PT0gLTEgfHwgaGVjIDwgaG9zdEVuZCkpXG4gICAgICAgIGhvc3RFbmQgPSBoZWM7XG4gICAgfVxuXG4gICAgLy8gYXQgdGhpcyBwb2ludCwgZWl0aGVyIHdlIGhhdmUgYW4gZXhwbGljaXQgcG9pbnQgd2hlcmUgdGhlXG4gICAgLy8gYXV0aCBwb3J0aW9uIGNhbm5vdCBnbyBwYXN0LCBvciB0aGUgbGFzdCBAIGNoYXIgaXMgdGhlIGRlY2lkZXIuXG4gICAgdmFyIGF1dGgsIGF0U2lnbjtcbiAgICBpZiAoaG9zdEVuZCA9PT0gLTEpIHtcbiAgICAgIC8vIGF0U2lnbiBjYW4gYmUgYW55d2hlcmUuXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIGF0U2lnbiBtdXN0IGJlIGluIGF1dGggcG9ydGlvbi5cbiAgICAgIC8vIGh0dHA6Ly9hQGIvY0BkID0+IGhvc3Q6YiBhdXRoOmEgcGF0aDovY0BkXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJywgaG9zdEVuZCk7XG4gICAgfVxuXG4gICAgLy8gTm93IHdlIGhhdmUgYSBwb3J0aW9uIHdoaWNoIGlzIGRlZmluaXRlbHkgdGhlIGF1dGguXG4gICAgLy8gUHVsbCB0aGF0IG9mZi5cbiAgICBpZiAoYXRTaWduICE9PSAtMSkge1xuICAgICAgYXV0aCA9IHJlc3Quc2xpY2UoMCwgYXRTaWduKTtcbiAgICAgIHJlc3QgPSByZXN0LnNsaWNlKGF0U2lnbiArIDEpO1xuICAgICAgdGhpcy5hdXRoID0gZGVjb2RlVVJJQ29tcG9uZW50KGF1dGgpO1xuICAgIH1cblxuICAgIC8vIHRoZSBob3N0IGlzIHRoZSByZW1haW5pbmcgdG8gdGhlIGxlZnQgb2YgdGhlIGZpcnN0IG5vbi1ob3N0IGNoYXJcbiAgICBob3N0RW5kID0gLTE7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBub25Ib3N0Q2hhcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoZWMgPSByZXN0LmluZGV4T2Yobm9uSG9zdENoYXJzW2ldKTtcbiAgICAgIGlmIChoZWMgIT09IC0xICYmIChob3N0RW5kID09PSAtMSB8fCBoZWMgPCBob3N0RW5kKSlcbiAgICAgICAgaG9zdEVuZCA9IGhlYztcbiAgICB9XG4gICAgLy8gaWYgd2Ugc3RpbGwgaGF2ZSBub3QgaGl0IGl0LCB0aGVuIHRoZSBlbnRpcmUgdGhpbmcgaXMgYSBob3N0LlxuICAgIGlmIChob3N0RW5kID09PSAtMSlcbiAgICAgIGhvc3RFbmQgPSByZXN0Lmxlbmd0aDtcblxuICAgIHRoaXMuaG9zdCA9IHJlc3Quc2xpY2UoMCwgaG9zdEVuZCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoaG9zdEVuZCk7XG5cbiAgICAvLyBwdWxsIG91dCBwb3J0LlxuICAgIHRoaXMucGFyc2VIb3N0KCk7XG5cbiAgICAvLyB3ZSd2ZSBpbmRpY2F0ZWQgdGhhdCB0aGVyZSBpcyBhIGhvc3RuYW1lLFxuICAgIC8vIHNvIGV2ZW4gaWYgaXQncyBlbXB0eSwgaXQgaGFzIHRvIGJlIHByZXNlbnQuXG4gICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUgfHwgJyc7XG5cbiAgICAvLyBpZiBob3N0bmFtZSBiZWdpbnMgd2l0aCBbIGFuZCBlbmRzIHdpdGggXVxuICAgIC8vIGFzc3VtZSB0aGF0IGl0J3MgYW4gSVB2NiBhZGRyZXNzLlxuICAgIHZhciBpcHY2SG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lWzBdID09PSAnWycgJiZcbiAgICAgICAgdGhpcy5ob3N0bmFtZVt0aGlzLmhvc3RuYW1lLmxlbmd0aCAtIDFdID09PSAnXSc7XG5cbiAgICAvLyB2YWxpZGF0ZSBhIGxpdHRsZS5cbiAgICBpZiAoIWlwdjZIb3N0bmFtZSkge1xuICAgICAgdmFyIGhvc3RwYXJ0cyA9IHRoaXMuaG9zdG5hbWUuc3BsaXQoL1xcLi8pO1xuICAgICAgZm9yICh2YXIgaSA9IDAsIGwgPSBob3N0cGFydHMubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgICAgIHZhciBwYXJ0ID0gaG9zdHBhcnRzW2ldO1xuICAgICAgICBpZiAoIXBhcnQpIGNvbnRpbnVlO1xuICAgICAgICBpZiAoIXBhcnQubWF0Y2goaG9zdG5hbWVQYXJ0UGF0dGVybikpIHtcbiAgICAgICAgICB2YXIgbmV3cGFydCA9ICcnO1xuICAgICAgICAgIGZvciAodmFyIGogPSAwLCBrID0gcGFydC5sZW5ndGg7IGogPCBrOyBqKyspIHtcbiAgICAgICAgICAgIGlmIChwYXJ0LmNoYXJDb2RlQXQoaikgPiAxMjcpIHtcbiAgICAgICAgICAgICAgLy8gd2UgcmVwbGFjZSBub24tQVNDSUkgY2hhciB3aXRoIGEgdGVtcG9yYXJ5IHBsYWNlaG9sZGVyXG4gICAgICAgICAgICAgIC8vIHdlIG5lZWQgdGhpcyB0byBtYWtlIHN1cmUgc2l6ZSBvZiBob3N0bmFtZSBpcyBub3RcbiAgICAgICAgICAgICAgLy8gYnJva2VuIGJ5IHJlcGxhY2luZyBub24tQVNDSUkgYnkgbm90aGluZ1xuICAgICAgICAgICAgICBuZXdwYXJ0ICs9ICd4JztcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIG5ld3BhcnQgKz0gcGFydFtqXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gd2UgdGVzdCBhZ2FpbiB3aXRoIEFTQ0lJIGNoYXIgb25seVxuICAgICAgICAgIGlmICghbmV3cGFydC5tYXRjaChob3N0bmFtZVBhcnRQYXR0ZXJuKSkge1xuICAgICAgICAgICAgdmFyIHZhbGlkUGFydHMgPSBob3N0cGFydHMuc2xpY2UoMCwgaSk7XG4gICAgICAgICAgICB2YXIgbm90SG9zdCA9IGhvc3RwYXJ0cy5zbGljZShpICsgMSk7XG4gICAgICAgICAgICB2YXIgYml0ID0gcGFydC5tYXRjaChob3N0bmFtZVBhcnRTdGFydCk7XG4gICAgICAgICAgICBpZiAoYml0KSB7XG4gICAgICAgICAgICAgIHZhbGlkUGFydHMucHVzaChiaXRbMV0pO1xuICAgICAgICAgICAgICBub3RIb3N0LnVuc2hpZnQoYml0WzJdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChub3RIb3N0Lmxlbmd0aCkge1xuICAgICAgICAgICAgICByZXN0ID0gJy8nICsgbm90SG9zdC5qb2luKCcuJykgKyByZXN0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhpcy5ob3N0bmFtZSA9IHZhbGlkUGFydHMuam9pbignLicpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuaG9zdG5hbWUubGVuZ3RoID4gaG9zdG5hbWVNYXhMZW4pIHtcbiAgICAgIHRoaXMuaG9zdG5hbWUgPSAnJztcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gaG9zdG5hbWVzIGFyZSBhbHdheXMgbG93ZXIgY2FzZS5cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgfVxuXG4gICAgaWYgKCFpcHY2SG9zdG5hbWUpIHtcbiAgICAgIC8vIElETkEgU3VwcG9ydDogUmV0dXJucyBhIHB1bnkgY29kZWQgcmVwcmVzZW50YXRpb24gb2YgXCJkb21haW5cIi5cbiAgICAgIC8vIEl0IG9ubHkgY29udmVydHMgdGhlIHBhcnQgb2YgdGhlIGRvbWFpbiBuYW1lIHRoYXRcbiAgICAgIC8vIGhhcyBub24gQVNDSUkgY2hhcmFjdGVycy4gSS5lLiBpdCBkb3NlbnQgbWF0dGVyIGlmXG4gICAgICAvLyB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQgYWxyZWFkeSBpcyBpbiBBU0NJSS5cbiAgICAgIHZhciBkb21haW5BcnJheSA9IHRoaXMuaG9zdG5hbWUuc3BsaXQoJy4nKTtcbiAgICAgIHZhciBuZXdPdXQgPSBbXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZG9tYWluQXJyYXkubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgdmFyIHMgPSBkb21haW5BcnJheVtpXTtcbiAgICAgICAgbmV3T3V0LnB1c2gocy5tYXRjaCgvW15BLVphLXowLTlfLV0vKSA/XG4gICAgICAgICAgICAneG4tLScgKyBwdW55Y29kZS5lbmNvZGUocykgOiBzKTtcbiAgICAgIH1cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSBuZXdPdXQuam9pbignLicpO1xuICAgIH1cblxuICAgIHZhciBwID0gdGhpcy5wb3J0ID8gJzonICsgdGhpcy5wb3J0IDogJyc7XG4gICAgdmFyIGggPSB0aGlzLmhvc3RuYW1lIHx8ICcnO1xuICAgIHRoaXMuaG9zdCA9IGggKyBwO1xuICAgIHRoaXMuaHJlZiArPSB0aGlzLmhvc3Q7XG5cbiAgICAvLyBzdHJpcCBbIGFuZCBdIGZyb20gdGhlIGhvc3RuYW1lXG4gICAgLy8gdGhlIGhvc3QgZmllbGQgc3RpbGwgcmV0YWlucyB0aGVtLCB0aG91Z2hcbiAgICBpZiAoaXB2Nkhvc3RuYW1lKSB7XG4gICAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZS5zdWJzdHIoMSwgdGhpcy5ob3N0bmFtZS5sZW5ndGggLSAyKTtcbiAgICAgIGlmIChyZXN0WzBdICE9PSAnLycpIHtcbiAgICAgICAgcmVzdCA9ICcvJyArIHJlc3Q7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLy8gbm93IHJlc3QgaXMgc2V0IHRvIHRoZSBwb3N0LWhvc3Qgc3R1ZmYuXG4gIC8vIGNob3Agb2ZmIGFueSBkZWxpbSBjaGFycy5cbiAgaWYgKCF1bnNhZmVQcm90b2NvbFtsb3dlclByb3RvXSkge1xuXG4gICAgLy8gRmlyc3QsIG1ha2UgMTAwJSBzdXJlIHRoYXQgYW55IFwiYXV0b0VzY2FwZVwiIGNoYXJzIGdldFxuICAgIC8vIGVzY2FwZWQsIGV2ZW4gaWYgZW5jb2RlVVJJQ29tcG9uZW50IGRvZXNuJ3QgdGhpbmsgdGhleVxuICAgIC8vIG5lZWQgdG8gYmUuXG4gICAgZm9yICh2YXIgaSA9IDAsIGwgPSBhdXRvRXNjYXBlLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgICAgdmFyIGFlID0gYXV0b0VzY2FwZVtpXTtcbiAgICAgIHZhciBlc2MgPSBlbmNvZGVVUklDb21wb25lbnQoYWUpO1xuICAgICAgaWYgKGVzYyA9PT0gYWUpIHtcbiAgICAgICAgZXNjID0gZXNjYXBlKGFlKTtcbiAgICAgIH1cbiAgICAgIHJlc3QgPSByZXN0LnNwbGl0KGFlKS5qb2luKGVzYyk7XG4gICAgfVxuICB9XG5cblxuICAvLyBjaG9wIG9mZiBmcm9tIHRoZSB0YWlsIGZpcnN0LlxuICB2YXIgaGFzaCA9IHJlc3QuaW5kZXhPZignIycpO1xuICBpZiAoaGFzaCAhPT0gLTEpIHtcbiAgICAvLyBnb3QgYSBmcmFnbWVudCBzdHJpbmcuXG4gICAgdGhpcy5oYXNoID0gcmVzdC5zdWJzdHIoaGFzaCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoMCwgaGFzaCk7XG4gIH1cbiAgdmFyIHFtID0gcmVzdC5pbmRleE9mKCc/Jyk7XG4gIGlmIChxbSAhPT0gLTEpIHtcbiAgICB0aGlzLnNlYXJjaCA9IHJlc3Quc3Vic3RyKHFtKTtcbiAgICB0aGlzLnF1ZXJ5ID0gcmVzdC5zdWJzdHIocW0gKyAxKTtcbiAgICBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgICAgdGhpcy5xdWVyeSA9IHF1ZXJ5c3RyaW5nLnBhcnNlKHRoaXMucXVlcnkpO1xuICAgIH1cbiAgICByZXN0ID0gcmVzdC5zbGljZSgwLCBxbSk7XG4gIH0gZWxzZSBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgIC8vIG5vIHF1ZXJ5IHN0cmluZywgYnV0IHBhcnNlUXVlcnlTdHJpbmcgc3RpbGwgcmVxdWVzdGVkXG4gICAgdGhpcy5zZWFyY2ggPSAnJztcbiAgICB0aGlzLnF1ZXJ5ID0ge307XG4gIH1cbiAgaWYgKHJlc3QpIHRoaXMucGF0aG5hbWUgPSByZXN0O1xuICBpZiAoc2xhc2hlZFByb3RvY29sW2xvd2VyUHJvdG9dICYmXG4gICAgICB0aGlzLmhvc3RuYW1lICYmICF0aGlzLnBhdGhuYW1lKSB7XG4gICAgdGhpcy5wYXRobmFtZSA9ICcvJztcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgaWYgKHRoaXMucGF0aG5hbWUgfHwgdGhpcy5zZWFyY2gpIHtcbiAgICB2YXIgcCA9IHRoaXMucGF0aG5hbWUgfHwgJyc7XG4gICAgdmFyIHMgPSB0aGlzLnNlYXJjaCB8fCAnJztcbiAgICB0aGlzLnBhdGggPSBwICsgcztcbiAgfVxuXG4gIC8vIGZpbmFsbHksIHJlY29uc3RydWN0IHRoZSBocmVmIGJhc2VkIG9uIHdoYXQgaGFzIGJlZW4gdmFsaWRhdGVkLlxuICB0aGlzLmhyZWYgPSB0aGlzLmZvcm1hdCgpO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8vIGZvcm1hdCBhIHBhcnNlZCBvYmplY3QgaW50byBhIHVybCBzdHJpbmdcbmZ1bmN0aW9uIHVybEZvcm1hdChvYmopIHtcbiAgLy8gZW5zdXJlIGl0J3MgYW4gb2JqZWN0LCBhbmQgbm90IGEgc3RyaW5nIHVybC5cbiAgLy8gSWYgaXQncyBhbiBvYmosIHRoaXMgaXMgYSBuby1vcC5cbiAgLy8gdGhpcyB3YXksIHlvdSBjYW4gY2FsbCB1cmxfZm9ybWF0KCkgb24gc3RyaW5nc1xuICAvLyB0byBjbGVhbiB1cCBwb3RlbnRpYWxseSB3b25reSB1cmxzLlxuICBpZiAoaXNTdHJpbmcob2JqKSkgb2JqID0gdXJsUGFyc2Uob2JqKTtcbiAgaWYgKCEob2JqIGluc3RhbmNlb2YgVXJsKSkgcmV0dXJuIFVybC5wcm90b3R5cGUuZm9ybWF0LmNhbGwob2JqKTtcbiAgcmV0dXJuIG9iai5mb3JtYXQoKTtcbn1cblxuVXJsLnByb3RvdHlwZS5mb3JtYXQgPSBmdW5jdGlvbigpIHtcbiAgdmFyIGF1dGggPSB0aGlzLmF1dGggfHwgJyc7XG4gIGlmIChhdXRoKSB7XG4gICAgYXV0aCA9IGVuY29kZVVSSUNvbXBvbmVudChhdXRoKTtcbiAgICBhdXRoID0gYXV0aC5yZXBsYWNlKC8lM0EvaSwgJzonKTtcbiAgICBhdXRoICs9ICdAJztcbiAgfVxuXG4gIHZhciBwcm90b2NvbCA9IHRoaXMucHJvdG9jb2wgfHwgJycsXG4gICAgICBwYXRobmFtZSA9IHRoaXMucGF0aG5hbWUgfHwgJycsXG4gICAgICBoYXNoID0gdGhpcy5oYXNoIHx8ICcnLFxuICAgICAgaG9zdCA9IGZhbHNlLFxuICAgICAgcXVlcnkgPSAnJztcblxuICBpZiAodGhpcy5ob3N0KSB7XG4gICAgaG9zdCA9IGF1dGggKyB0aGlzLmhvc3Q7XG4gIH0gZWxzZSBpZiAodGhpcy5ob3N0bmFtZSkge1xuICAgIGhvc3QgPSBhdXRoICsgKHRoaXMuaG9zdG5hbWUuaW5kZXhPZignOicpID09PSAtMSA/XG4gICAgICAgIHRoaXMuaG9zdG5hbWUgOlxuICAgICAgICAnWycgKyB0aGlzLmhvc3RuYW1lICsgJ10nKTtcbiAgICBpZiAodGhpcy5wb3J0KSB7XG4gICAgICBob3N0ICs9ICc6JyArIHRoaXMucG9ydDtcbiAgICB9XG4gIH1cblxuICBpZiAodGhpcy5xdWVyeSAmJlxuICAgICAgaXNPYmplY3QodGhpcy5xdWVyeSkgJiZcbiAgICAgIE9iamVjdC5rZXlzKHRoaXMucXVlcnkpLmxlbmd0aCkge1xuICAgIHF1ZXJ5ID0gcXVlcnlzdHJpbmcuc3RyaW5naWZ5KHRoaXMucXVlcnkpO1xuICB9XG5cbiAgdmFyIHNlYXJjaCA9IHRoaXMuc2VhcmNoIHx8IChxdWVyeSAmJiAoJz8nICsgcXVlcnkpKSB8fCAnJztcblxuICBpZiAocHJvdG9jb2wgJiYgcHJvdG9jb2wuc3Vic3RyKC0xKSAhPT0gJzonKSBwcm90b2NvbCArPSAnOic7XG5cbiAgLy8gb25seSB0aGUgc2xhc2hlZFByb3RvY29scyBnZXQgdGhlIC8vLiAgTm90IG1haWx0bzosIHhtcHA6LCBldGMuXG4gIC8vIHVubGVzcyB0aGV5IGhhZCB0aGVtIHRvIGJlZ2luIHdpdGguXG4gIGlmICh0aGlzLnNsYXNoZXMgfHxcbiAgICAgICghcHJvdG9jb2wgfHwgc2xhc2hlZFByb3RvY29sW3Byb3RvY29sXSkgJiYgaG9zdCAhPT0gZmFsc2UpIHtcbiAgICBob3N0ID0gJy8vJyArIChob3N0IHx8ICcnKTtcbiAgICBpZiAocGF0aG5hbWUgJiYgcGF0aG5hbWUuY2hhckF0KDApICE9PSAnLycpIHBhdGhuYW1lID0gJy8nICsgcGF0aG5hbWU7XG4gIH0gZWxzZSBpZiAoIWhvc3QpIHtcbiAgICBob3N0ID0gJyc7XG4gIH1cblxuICBpZiAoaGFzaCAmJiBoYXNoLmNoYXJBdCgwKSAhPT0gJyMnKSBoYXNoID0gJyMnICsgaGFzaDtcbiAgaWYgKHNlYXJjaCAmJiBzZWFyY2guY2hhckF0KDApICE9PSAnPycpIHNlYXJjaCA9ICc/JyArIHNlYXJjaDtcblxuICBwYXRobmFtZSA9IHBhdGhuYW1lLnJlcGxhY2UoL1s/I10vZywgZnVuY3Rpb24obWF0Y2gpIHtcbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KG1hdGNoKTtcbiAgfSk7XG4gIHNlYXJjaCA9IHNlYXJjaC5yZXBsYWNlKCcjJywgJyUyMycpO1xuXG4gIHJldHVybiBwcm90b2NvbCArIGhvc3QgKyBwYXRobmFtZSArIHNlYXJjaCArIGhhc2g7XG59O1xuXG5mdW5jdGlvbiB1cmxSZXNvbHZlKHNvdXJjZSwgcmVsYXRpdmUpIHtcbiAgcmV0dXJuIHVybFBhcnNlKHNvdXJjZSwgZmFsc2UsIHRydWUpLnJlc29sdmUocmVsYXRpdmUpO1xufVxuXG5VcmwucHJvdG90eXBlLnJlc29sdmUgPSBmdW5jdGlvbihyZWxhdGl2ZSkge1xuICByZXR1cm4gdGhpcy5yZXNvbHZlT2JqZWN0KHVybFBhcnNlKHJlbGF0aXZlLCBmYWxzZSwgdHJ1ZSkpLmZvcm1hdCgpO1xufTtcblxuZnVuY3Rpb24gdXJsUmVzb2x2ZU9iamVjdChzb3VyY2UsIHJlbGF0aXZlKSB7XG4gIGlmICghc291cmNlKSByZXR1cm4gcmVsYXRpdmU7XG4gIHJldHVybiB1cmxQYXJzZShzb3VyY2UsIGZhbHNlLCB0cnVlKS5yZXNvbHZlT2JqZWN0KHJlbGF0aXZlKTtcbn1cblxuVXJsLnByb3RvdHlwZS5yZXNvbHZlT2JqZWN0ID0gZnVuY3Rpb24ocmVsYXRpdmUpIHtcbiAgaWYgKGlzU3RyaW5nKHJlbGF0aXZlKSkge1xuICAgIHZhciByZWwgPSBuZXcgVXJsKCk7XG4gICAgcmVsLnBhcnNlKHJlbGF0aXZlLCBmYWxzZSwgdHJ1ZSk7XG4gICAgcmVsYXRpdmUgPSByZWw7XG4gIH1cblxuICB2YXIgcmVzdWx0ID0gbmV3IFVybCgpO1xuICBPYmplY3Qua2V5cyh0aGlzKS5mb3JFYWNoKGZ1bmN0aW9uKGspIHtcbiAgICByZXN1bHRba10gPSB0aGlzW2tdO1xuICB9LCB0aGlzKTtcblxuICAvLyBoYXNoIGlzIGFsd2F5cyBvdmVycmlkZGVuLCBubyBtYXR0ZXIgd2hhdC5cbiAgLy8gZXZlbiBocmVmPVwiXCIgd2lsbCByZW1vdmUgaXQuXG4gIHJlc3VsdC5oYXNoID0gcmVsYXRpdmUuaGFzaDtcblxuICAvLyBpZiB0aGUgcmVsYXRpdmUgdXJsIGlzIGVtcHR5LCB0aGVuIHRoZXJlJ3Mgbm90aGluZyBsZWZ0IHRvIGRvIGhlcmUuXG4gIGlmIChyZWxhdGl2ZS5ocmVmID09PSAnJykge1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBocmVmcyBsaWtlIC8vZm9vL2JhciBhbHdheXMgY3V0IHRvIHRoZSBwcm90b2NvbC5cbiAgaWYgKHJlbGF0aXZlLnNsYXNoZXMgJiYgIXJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgLy8gdGFrZSBldmVyeXRoaW5nIGV4Y2VwdCB0aGUgcHJvdG9jb2wgZnJvbSByZWxhdGl2ZVxuICAgIE9iamVjdC5rZXlzKHJlbGF0aXZlKS5mb3JFYWNoKGZ1bmN0aW9uKGspIHtcbiAgICAgIGlmIChrICE9PSAncHJvdG9jb2wnKVxuICAgICAgICByZXN1bHRba10gPSByZWxhdGl2ZVtrXTtcbiAgICB9KTtcblxuICAgIC8vdXJsUGFyc2UgYXBwZW5kcyB0cmFpbGluZyAvIHRvIHVybHMgbGlrZSBodHRwOi8vd3d3LmV4YW1wbGUuY29tXG4gICAgaWYgKHNsYXNoZWRQcm90b2NvbFtyZXN1bHQucHJvdG9jb2xdICYmXG4gICAgICAgIHJlc3VsdC5ob3N0bmFtZSAmJiAhcmVzdWx0LnBhdGhuYW1lKSB7XG4gICAgICByZXN1bHQucGF0aCA9IHJlc3VsdC5wYXRobmFtZSA9ICcvJztcbiAgICB9XG5cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgaWYgKHJlbGF0aXZlLnByb3RvY29sICYmIHJlbGF0aXZlLnByb3RvY29sICE9PSByZXN1bHQucHJvdG9jb2wpIHtcbiAgICAvLyBpZiBpdCdzIGEga25vd24gdXJsIHByb3RvY29sLCB0aGVuIGNoYW5naW5nXG4gICAgLy8gdGhlIHByb3RvY29sIGRvZXMgd2VpcmQgdGhpbmdzXG4gICAgLy8gZmlyc3QsIGlmIGl0J3Mgbm90IGZpbGU6LCB0aGVuIHdlIE1VU1QgaGF2ZSBhIGhvc3QsXG4gICAgLy8gYW5kIGlmIHRoZXJlIHdhcyBhIHBhdGhcbiAgICAvLyB0byBiZWdpbiB3aXRoLCB0aGVuIHdlIE1VU1QgaGF2ZSBhIHBhdGguXG4gICAgLy8gaWYgaXQgaXMgZmlsZTosIHRoZW4gdGhlIGhvc3QgaXMgZHJvcHBlZCxcbiAgICAvLyBiZWNhdXNlIHRoYXQncyBrbm93biB0byBiZSBob3N0bGVzcy5cbiAgICAvLyBhbnl0aGluZyBlbHNlIGlzIGFzc3VtZWQgdG8gYmUgYWJzb2x1dGUuXG4gICAgaWYgKCFzbGFzaGVkUHJvdG9jb2xbcmVsYXRpdmUucHJvdG9jb2xdKSB7XG4gICAgICBPYmplY3Qua2V5cyhyZWxhdGl2ZSkuZm9yRWFjaChmdW5jdGlvbihrKSB7XG4gICAgICAgIHJlc3VsdFtrXSA9IHJlbGF0aXZlW2tdO1xuICAgICAgfSk7XG4gICAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuXG4gICAgcmVzdWx0LnByb3RvY29sID0gcmVsYXRpdmUucHJvdG9jb2w7XG4gICAgaWYgKCFyZWxhdGl2ZS5ob3N0ICYmICFob3N0bGVzc1Byb3RvY29sW3JlbGF0aXZlLnByb3RvY29sXSkge1xuICAgICAgdmFyIHJlbFBhdGggPSAocmVsYXRpdmUucGF0aG5hbWUgfHwgJycpLnNwbGl0KCcvJyk7XG4gICAgICB3aGlsZSAocmVsUGF0aC5sZW5ndGggJiYgIShyZWxhdGl2ZS5ob3N0ID0gcmVsUGF0aC5zaGlmdCgpKSk7XG4gICAgICBpZiAoIXJlbGF0aXZlLmhvc3QpIHJlbGF0aXZlLmhvc3QgPSAnJztcbiAgICAgIGlmICghcmVsYXRpdmUuaG9zdG5hbWUpIHJlbGF0aXZlLmhvc3RuYW1lID0gJyc7XG4gICAgICBpZiAocmVsUGF0aFswXSAhPT0gJycpIHJlbFBhdGgudW5zaGlmdCgnJyk7XG4gICAgICBpZiAocmVsUGF0aC5sZW5ndGggPCAyKSByZWxQYXRoLnVuc2hpZnQoJycpO1xuICAgICAgcmVzdWx0LnBhdGhuYW1lID0gcmVsUGF0aC5qb2luKCcvJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdC5wYXRobmFtZSA9IHJlbGF0aXZlLnBhdGhuYW1lO1xuICAgIH1cbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIHJlc3VsdC5ob3N0ID0gcmVsYXRpdmUuaG9zdCB8fCAnJztcbiAgICByZXN1bHQuYXV0aCA9IHJlbGF0aXZlLmF1dGg7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdDtcbiAgICByZXN1bHQucG9ydCA9IHJlbGF0aXZlLnBvcnQ7XG4gICAgLy8gdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAocmVzdWx0LnBhdGhuYW1lIHx8IHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHZhciBwID0gcmVzdWx0LnBhdGhuYW1lIHx8ICcnO1xuICAgICAgdmFyIHMgPSByZXN1bHQuc2VhcmNoIHx8ICcnO1xuICAgICAgcmVzdWx0LnBhdGggPSBwICsgcztcbiAgICB9XG4gICAgcmVzdWx0LnNsYXNoZXMgPSByZXN1bHQuc2xhc2hlcyB8fCByZWxhdGl2ZS5zbGFzaGVzO1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB2YXIgaXNTb3VyY2VBYnMgPSAocmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5jaGFyQXQoMCkgPT09ICcvJyksXG4gICAgICBpc1JlbEFicyA9IChcbiAgICAgICAgICByZWxhdGl2ZS5ob3N0IHx8XG4gICAgICAgICAgcmVsYXRpdmUucGF0aG5hbWUgJiYgcmVsYXRpdmUucGF0aG5hbWUuY2hhckF0KDApID09PSAnLydcbiAgICAgICksXG4gICAgICBtdXN0RW5kQWJzID0gKGlzUmVsQWJzIHx8IGlzU291cmNlQWJzIHx8XG4gICAgICAgICAgICAgICAgICAgIChyZXN1bHQuaG9zdCAmJiByZWxhdGl2ZS5wYXRobmFtZSkpLFxuICAgICAgcmVtb3ZlQWxsRG90cyA9IG11c3RFbmRBYnMsXG4gICAgICBzcmNQYXRoID0gcmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5zcGxpdCgnLycpIHx8IFtdLFxuICAgICAgcmVsUGF0aCA9IHJlbGF0aXZlLnBhdGhuYW1lICYmIHJlbGF0aXZlLnBhdGhuYW1lLnNwbGl0KCcvJykgfHwgW10sXG4gICAgICBwc3ljaG90aWMgPSByZXN1bHQucHJvdG9jb2wgJiYgIXNsYXNoZWRQcm90b2NvbFtyZXN1bHQucHJvdG9jb2xdO1xuXG4gIC8vIGlmIHRoZSB1cmwgaXMgYSBub24tc2xhc2hlZCB1cmwsIHRoZW4gcmVsYXRpdmVcbiAgLy8gbGlua3MgbGlrZSAuLi8uLiBzaG91bGQgYmUgYWJsZVxuICAvLyB0byBjcmF3bCB1cCB0byB0aGUgaG9zdG5hbWUsIGFzIHdlbGwuICBUaGlzIGlzIHN0cmFuZ2UuXG4gIC8vIHJlc3VsdC5wcm90b2NvbCBoYXMgYWxyZWFkeSBiZWVuIHNldCBieSBub3cuXG4gIC8vIExhdGVyIG9uLCBwdXQgdGhlIGZpcnN0IHBhdGggcGFydCBpbnRvIHRoZSBob3N0IGZpZWxkLlxuICBpZiAocHN5Y2hvdGljKSB7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gJyc7XG4gICAgcmVzdWx0LnBvcnQgPSBudWxsO1xuICAgIGlmIChyZXN1bHQuaG9zdCkge1xuICAgICAgaWYgKHNyY1BhdGhbMF0gPT09ICcnKSBzcmNQYXRoWzBdID0gcmVzdWx0Lmhvc3Q7XG4gICAgICBlbHNlIHNyY1BhdGgudW5zaGlmdChyZXN1bHQuaG9zdCk7XG4gICAgfVxuICAgIHJlc3VsdC5ob3N0ID0gJyc7XG4gICAgaWYgKHJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgICByZWxhdGl2ZS5ob3N0bmFtZSA9IG51bGw7XG4gICAgICByZWxhdGl2ZS5wb3J0ID0gbnVsbDtcbiAgICAgIGlmIChyZWxhdGl2ZS5ob3N0KSB7XG4gICAgICAgIGlmIChyZWxQYXRoWzBdID09PSAnJykgcmVsUGF0aFswXSA9IHJlbGF0aXZlLmhvc3Q7XG4gICAgICAgIGVsc2UgcmVsUGF0aC51bnNoaWZ0KHJlbGF0aXZlLmhvc3QpO1xuICAgICAgfVxuICAgICAgcmVsYXRpdmUuaG9zdCA9IG51bGw7XG4gICAgfVxuICAgIG11c3RFbmRBYnMgPSBtdXN0RW5kQWJzICYmIChyZWxQYXRoWzBdID09PSAnJyB8fCBzcmNQYXRoWzBdID09PSAnJyk7XG4gIH1cblxuICBpZiAoaXNSZWxBYnMpIHtcbiAgICAvLyBpdCdzIGFic29sdXRlLlxuICAgIHJlc3VsdC5ob3N0ID0gKHJlbGF0aXZlLmhvc3QgfHwgcmVsYXRpdmUuaG9zdCA9PT0gJycpID9cbiAgICAgICAgICAgICAgICAgIHJlbGF0aXZlLmhvc3QgOiByZXN1bHQuaG9zdDtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSAocmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdG5hbWUgPT09ICcnKSA/XG4gICAgICAgICAgICAgICAgICAgICAgcmVsYXRpdmUuaG9zdG5hbWUgOiByZXN1bHQuaG9zdG5hbWU7XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICBzcmNQYXRoID0gcmVsUGF0aDtcbiAgICAvLyBmYWxsIHRocm91Z2ggdG8gdGhlIGRvdC1oYW5kbGluZyBiZWxvdy5cbiAgfSBlbHNlIGlmIChyZWxQYXRoLmxlbmd0aCkge1xuICAgIC8vIGl0J3MgcmVsYXRpdmVcbiAgICAvLyB0aHJvdyBhd2F5IHRoZSBleGlzdGluZyBmaWxlLCBhbmQgdGFrZSB0aGUgbmV3IHBhdGggaW5zdGVhZC5cbiAgICBpZiAoIXNyY1BhdGgpIHNyY1BhdGggPSBbXTtcbiAgICBzcmNQYXRoLnBvcCgpO1xuICAgIHNyY1BhdGggPSBzcmNQYXRoLmNvbmNhdChyZWxQYXRoKTtcbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICB9IGVsc2UgaWYgKCFpc051bGxPclVuZGVmaW5lZChyZWxhdGl2ZS5zZWFyY2gpKSB7XG4gICAgLy8ganVzdCBwdWxsIG91dCB0aGUgc2VhcmNoLlxuICAgIC8vIGxpa2UgaHJlZj0nP2ZvbycuXG4gICAgLy8gUHV0IHRoaXMgYWZ0ZXIgdGhlIG90aGVyIHR3byBjYXNlcyBiZWNhdXNlIGl0IHNpbXBsaWZpZXMgdGhlIGJvb2xlYW5zXG4gICAgaWYgKHBzeWNob3RpYykge1xuICAgICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVzdWx0Lmhvc3QgPSBzcmNQYXRoLnNoaWZ0KCk7XG4gICAgICAvL29jY2F0aW9uYWx5IHRoZSBhdXRoIGNhbiBnZXQgc3R1Y2sgb25seSBpbiBob3N0XG4gICAgICAvL3RoaXMgZXNwZWNpYWx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgICAgLy91cmwucmVzb2x2ZU9iamVjdCgnbWFpbHRvOmxvY2FsMUBkb21haW4xJywgJ2xvY2FsMkBkb21haW4yJylcbiAgICAgIHZhciBhdXRoSW5Ib3N0ID0gcmVzdWx0Lmhvc3QgJiYgcmVzdWx0Lmhvc3QuaW5kZXhPZignQCcpID4gMCA/XG4gICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICAgIGlmIChhdXRoSW5Ib3N0KSB7XG4gICAgICAgIHJlc3VsdC5hdXRoID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKCFpc051bGwocmVzdWx0LnBhdGhuYW1lKSB8fCAhaXNOdWxsKHJlc3VsdC5zZWFyY2gpKSB7XG4gICAgICByZXN1bHQucGF0aCA9IChyZXN1bHQucGF0aG5hbWUgPyByZXN1bHQucGF0aG5hbWUgOiAnJykgK1xuICAgICAgICAgICAgICAgICAgICAocmVzdWx0LnNlYXJjaCA/IHJlc3VsdC5zZWFyY2ggOiAnJyk7XG4gICAgfVxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBpZiAoIXNyY1BhdGgubGVuZ3RoKSB7XG4gICAgLy8gbm8gcGF0aCBhdCBhbGwuICBlYXN5LlxuICAgIC8vIHdlJ3ZlIGFscmVhZHkgaGFuZGxlZCB0aGUgb3RoZXIgc3R1ZmYgYWJvdmUuXG4gICAgcmVzdWx0LnBhdGhuYW1lID0gbnVsbDtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gJy8nICsgcmVzdWx0LnNlYXJjaDtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0LnBhdGggPSBudWxsO1xuICAgIH1cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gaWYgYSB1cmwgRU5EcyBpbiAuIG9yIC4uLCB0aGVuIGl0IG11c3QgZ2V0IGEgdHJhaWxpbmcgc2xhc2guXG4gIC8vIGhvd2V2ZXIsIGlmIGl0IGVuZHMgaW4gYW55dGhpbmcgZWxzZSBub24tc2xhc2h5LFxuICAvLyB0aGVuIGl0IG11c3QgTk9UIGdldCBhIHRyYWlsaW5nIHNsYXNoLlxuICB2YXIgbGFzdCA9IHNyY1BhdGguc2xpY2UoLTEpWzBdO1xuICB2YXIgaGFzVHJhaWxpbmdTbGFzaCA9IChcbiAgICAgIChyZXN1bHQuaG9zdCB8fCByZWxhdGl2ZS5ob3N0KSAmJiAobGFzdCA9PT0gJy4nIHx8IGxhc3QgPT09ICcuLicpIHx8XG4gICAgICBsYXN0ID09PSAnJyk7XG5cbiAgLy8gc3RyaXAgc2luZ2xlIGRvdHMsIHJlc29sdmUgZG91YmxlIGRvdHMgdG8gcGFyZW50IGRpclxuICAvLyBpZiB0aGUgcGF0aCB0cmllcyB0byBnbyBhYm92ZSB0aGUgcm9vdCwgYHVwYCBlbmRzIHVwID4gMFxuICB2YXIgdXAgPSAwO1xuICBmb3IgKHZhciBpID0gc3JjUGF0aC5sZW5ndGg7IGkgPj0gMDsgaS0tKSB7XG4gICAgbGFzdCA9IHNyY1BhdGhbaV07XG4gICAgaWYgKGxhc3QgPT0gJy4nKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICB9IGVsc2UgaWYgKGxhc3QgPT09ICcuLicpIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXArKztcbiAgICB9IGVsc2UgaWYgKHVwKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICAgIHVwLS07XG4gICAgfVxuICB9XG5cbiAgLy8gaWYgdGhlIHBhdGggaXMgYWxsb3dlZCB0byBnbyBhYm92ZSB0aGUgcm9vdCwgcmVzdG9yZSBsZWFkaW5nIC4uc1xuICBpZiAoIW11c3RFbmRBYnMgJiYgIXJlbW92ZUFsbERvdHMpIHtcbiAgICBmb3IgKDsgdXAtLTsgdXApIHtcbiAgICAgIHNyY1BhdGgudW5zaGlmdCgnLi4nKTtcbiAgICB9XG4gIH1cblxuICBpZiAobXVzdEVuZEFicyAmJiBzcmNQYXRoWzBdICE9PSAnJyAmJlxuICAgICAgKCFzcmNQYXRoWzBdIHx8IHNyY1BhdGhbMF0uY2hhckF0KDApICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmIChoYXNUcmFpbGluZ1NsYXNoICYmIChzcmNQYXRoLmpvaW4oJy8nKS5zdWJzdHIoLTEpICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC5wdXNoKCcnKTtcbiAgfVxuXG4gIHZhciBpc0Fic29sdXRlID0gc3JjUGF0aFswXSA9PT0gJycgfHxcbiAgICAgIChzcmNQYXRoWzBdICYmIHNyY1BhdGhbMF0uY2hhckF0KDApID09PSAnLycpO1xuXG4gIC8vIHB1dCB0aGUgaG9zdCBiYWNrXG4gIGlmIChwc3ljaG90aWMpIHtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSByZXN1bHQuaG9zdCA9IGlzQWJzb2x1dGUgPyAnJyA6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcmNQYXRoLmxlbmd0aCA/IHNyY1BhdGguc2hpZnQoKSA6ICcnO1xuICAgIC8vb2NjYXRpb25hbHkgdGhlIGF1dGggY2FuIGdldCBzdHVjayBvbmx5IGluIGhvc3RcbiAgICAvL3RoaXMgZXNwZWNpYWx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgIC8vdXJsLnJlc29sdmVPYmplY3QoJ21haWx0bzpsb2NhbDFAZG9tYWluMScsICdsb2NhbDJAZG9tYWluMicpXG4gICAgdmFyIGF1dGhJbkhvc3QgPSByZXN1bHQuaG9zdCAmJiByZXN1bHQuaG9zdC5pbmRleE9mKCdAJykgPiAwID9cbiAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICBpZiAoYXV0aEluSG9zdCkge1xuICAgICAgcmVzdWx0LmF1dGggPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICB9XG4gIH1cblxuICBtdXN0RW5kQWJzID0gbXVzdEVuZEFicyB8fCAocmVzdWx0Lmhvc3QgJiYgc3JjUGF0aC5sZW5ndGgpO1xuXG4gIGlmIChtdXN0RW5kQWJzICYmICFpc0Fic29sdXRlKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmICghc3JjUGF0aC5sZW5ndGgpIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBudWxsO1xuICAgIHJlc3VsdC5wYXRoID0gbnVsbDtcbiAgfSBlbHNlIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBzcmNQYXRoLmpvaW4oJy8nKTtcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCByZXF1ZXN0Lmh0dHBcbiAgaWYgKCFpc051bGwocmVzdWx0LnBhdGhuYW1lKSB8fCAhaXNOdWxsKHJlc3VsdC5zZWFyY2gpKSB7XG4gICAgcmVzdWx0LnBhdGggPSAocmVzdWx0LnBhdGhuYW1lID8gcmVzdWx0LnBhdGhuYW1lIDogJycpICtcbiAgICAgICAgICAgICAgICAgIChyZXN1bHQuc2VhcmNoID8gcmVzdWx0LnNlYXJjaCA6ICcnKTtcbiAgfVxuICByZXN1bHQuYXV0aCA9IHJlbGF0aXZlLmF1dGggfHwgcmVzdWx0LmF1dGg7XG4gIHJlc3VsdC5zbGFzaGVzID0gcmVzdWx0LnNsYXNoZXMgfHwgcmVsYXRpdmUuc2xhc2hlcztcbiAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gIHJldHVybiByZXN1bHQ7XG59O1xuXG5VcmwucHJvdG90eXBlLnBhcnNlSG9zdCA9IGZ1bmN0aW9uKCkge1xuICB2YXIgaG9zdCA9IHRoaXMuaG9zdDtcbiAgdmFyIHBvcnQgPSBwb3J0UGF0dGVybi5leGVjKGhvc3QpO1xuICBpZiAocG9ydCkge1xuICAgIHBvcnQgPSBwb3J0WzBdO1xuICAgIGlmIChwb3J0ICE9PSAnOicpIHtcbiAgICAgIHRoaXMucG9ydCA9IHBvcnQuc3Vic3RyKDEpO1xuICAgIH1cbiAgICBob3N0ID0gaG9zdC5zdWJzdHIoMCwgaG9zdC5sZW5ndGggLSBwb3J0Lmxlbmd0aCk7XG4gIH1cbiAgaWYgKGhvc3QpIHRoaXMuaG9zdG5hbWUgPSBob3N0O1xufTtcblxuZnVuY3Rpb24gaXNTdHJpbmcoYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSBcInN0cmluZ1wiO1xufVxuXG5mdW5jdGlvbiBpc09iamVjdChhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdvYmplY3QnICYmIGFyZyAhPT0gbnVsbDtcbn1cblxuZnVuY3Rpb24gaXNOdWxsKGFyZykge1xuICByZXR1cm4gYXJnID09PSBudWxsO1xufVxuZnVuY3Rpb24gaXNOdWxsT3JVbmRlZmluZWQoYXJnKSB7XG4gIHJldHVybiAgYXJnID09IG51bGw7XG59XG4iLCIvKiEgaHR0cHM6Ly9tdGhzLmJlL3B1bnljb2RlIHYxLjMuMiBieSBAbWF0aGlhcyAqL1xuOyhmdW5jdGlvbihyb290KSB7XG5cblx0LyoqIERldGVjdCBmcmVlIHZhcmlhYmxlcyAqL1xuXHR2YXIgZnJlZUV4cG9ydHMgPSB0eXBlb2YgZXhwb3J0cyA9PSAnb2JqZWN0JyAmJiBleHBvcnRzICYmXG5cdFx0IWV4cG9ydHMubm9kZVR5cGUgJiYgZXhwb3J0cztcblx0dmFyIGZyZWVNb2R1bGUgPSB0eXBlb2YgbW9kdWxlID09ICdvYmplY3QnICYmIG1vZHVsZSAmJlxuXHRcdCFtb2R1bGUubm9kZVR5cGUgJiYgbW9kdWxlO1xuXHR2YXIgZnJlZUdsb2JhbCA9IHR5cGVvZiBnbG9iYWwgPT0gJ29iamVjdCcgJiYgZ2xvYmFsO1xuXHRpZiAoXG5cdFx0ZnJlZUdsb2JhbC5nbG9iYWwgPT09IGZyZWVHbG9iYWwgfHxcblx0XHRmcmVlR2xvYmFsLndpbmRvdyA9PT0gZnJlZUdsb2JhbCB8fFxuXHRcdGZyZWVHbG9iYWwuc2VsZiA9PT0gZnJlZUdsb2JhbFxuXHQpIHtcblx0XHRyb290ID0gZnJlZUdsb2JhbDtcblx0fVxuXG5cdC8qKlxuXHQgKiBUaGUgYHB1bnljb2RlYCBvYmplY3QuXG5cdCAqIEBuYW1lIHB1bnljb2RlXG5cdCAqIEB0eXBlIE9iamVjdFxuXHQgKi9cblx0dmFyIHB1bnljb2RlLFxuXG5cdC8qKiBIaWdoZXN0IHBvc2l0aXZlIHNpZ25lZCAzMi1iaXQgZmxvYXQgdmFsdWUgKi9cblx0bWF4SW50ID0gMjE0NzQ4MzY0NywgLy8gYWthLiAweDdGRkZGRkZGIG9yIDJeMzEtMVxuXG5cdC8qKiBCb290c3RyaW5nIHBhcmFtZXRlcnMgKi9cblx0YmFzZSA9IDM2LFxuXHR0TWluID0gMSxcblx0dE1heCA9IDI2LFxuXHRza2V3ID0gMzgsXG5cdGRhbXAgPSA3MDAsXG5cdGluaXRpYWxCaWFzID0gNzIsXG5cdGluaXRpYWxOID0gMTI4LCAvLyAweDgwXG5cdGRlbGltaXRlciA9ICctJywgLy8gJ1xceDJEJ1xuXG5cdC8qKiBSZWd1bGFyIGV4cHJlc3Npb25zICovXG5cdHJlZ2V4UHVueWNvZGUgPSAvXnhuLS0vLFxuXHRyZWdleE5vbkFTQ0lJID0gL1teXFx4MjAtXFx4N0VdLywgLy8gdW5wcmludGFibGUgQVNDSUkgY2hhcnMgKyBub24tQVNDSUkgY2hhcnNcblx0cmVnZXhTZXBhcmF0b3JzID0gL1tcXHgyRVxcdTMwMDJcXHVGRjBFXFx1RkY2MV0vZywgLy8gUkZDIDM0OTAgc2VwYXJhdG9yc1xuXG5cdC8qKiBFcnJvciBtZXNzYWdlcyAqL1xuXHRlcnJvcnMgPSB7XG5cdFx0J292ZXJmbG93JzogJ092ZXJmbG93OiBpbnB1dCBuZWVkcyB3aWRlciBpbnRlZ2VycyB0byBwcm9jZXNzJyxcblx0XHQnbm90LWJhc2ljJzogJ0lsbGVnYWwgaW5wdXQgPj0gMHg4MCAobm90IGEgYmFzaWMgY29kZSBwb2ludCknLFxuXHRcdCdpbnZhbGlkLWlucHV0JzogJ0ludmFsaWQgaW5wdXQnXG5cdH0sXG5cblx0LyoqIENvbnZlbmllbmNlIHNob3J0Y3V0cyAqL1xuXHRiYXNlTWludXNUTWluID0gYmFzZSAtIHRNaW4sXG5cdGZsb29yID0gTWF0aC5mbG9vcixcblx0c3RyaW5nRnJvbUNoYXJDb2RlID0gU3RyaW5nLmZyb21DaGFyQ29kZSxcblxuXHQvKiogVGVtcG9yYXJ5IHZhcmlhYmxlICovXG5cdGtleTtcblxuXHQvKi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKi9cblxuXHQvKipcblx0ICogQSBnZW5lcmljIGVycm9yIHV0aWxpdHkgZnVuY3Rpb24uXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB0eXBlIFRoZSBlcnJvciB0eXBlLlxuXHQgKiBAcmV0dXJucyB7RXJyb3J9IFRocm93cyBhIGBSYW5nZUVycm9yYCB3aXRoIHRoZSBhcHBsaWNhYmxlIGVycm9yIG1lc3NhZ2UuXG5cdCAqL1xuXHRmdW5jdGlvbiBlcnJvcih0eXBlKSB7XG5cdFx0dGhyb3cgUmFuZ2VFcnJvcihlcnJvcnNbdHlwZV0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIEEgZ2VuZXJpYyBgQXJyYXkjbWFwYCB1dGlsaXR5IGZ1bmN0aW9uLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBhcnJheSBUaGUgYXJyYXkgdG8gaXRlcmF0ZSBvdmVyLlxuXHQgKiBAcGFyYW0ge0Z1bmN0aW9ufSBjYWxsYmFjayBUaGUgZnVuY3Rpb24gdGhhdCBnZXRzIGNhbGxlZCBmb3IgZXZlcnkgYXJyYXlcblx0ICogaXRlbS5cblx0ICogQHJldHVybnMge0FycmF5fSBBIG5ldyBhcnJheSBvZiB2YWx1ZXMgcmV0dXJuZWQgYnkgdGhlIGNhbGxiYWNrIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gbWFwKGFycmF5LCBmbikge1xuXHRcdHZhciBsZW5ndGggPSBhcnJheS5sZW5ndGg7XG5cdFx0dmFyIHJlc3VsdCA9IFtdO1xuXHRcdHdoaWxlIChsZW5ndGgtLSkge1xuXHRcdFx0cmVzdWx0W2xlbmd0aF0gPSBmbihhcnJheVtsZW5ndGhdKTtcblx0XHR9XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fVxuXG5cdC8qKlxuXHQgKiBBIHNpbXBsZSBgQXJyYXkjbWFwYC1saWtlIHdyYXBwZXIgdG8gd29yayB3aXRoIGRvbWFpbiBuYW1lIHN0cmluZ3Mgb3IgZW1haWxcblx0ICogYWRkcmVzc2VzLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gZG9tYWluIFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzLlxuXHQgKiBAcGFyYW0ge0Z1bmN0aW9ufSBjYWxsYmFjayBUaGUgZnVuY3Rpb24gdGhhdCBnZXRzIGNhbGxlZCBmb3IgZXZlcnlcblx0ICogY2hhcmFjdGVyLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IEEgbmV3IHN0cmluZyBvZiBjaGFyYWN0ZXJzIHJldHVybmVkIGJ5IHRoZSBjYWxsYmFja1xuXHQgKiBmdW5jdGlvbi5cblx0ICovXG5cdGZ1bmN0aW9uIG1hcERvbWFpbihzdHJpbmcsIGZuKSB7XG5cdFx0dmFyIHBhcnRzID0gc3RyaW5nLnNwbGl0KCdAJyk7XG5cdFx0dmFyIHJlc3VsdCA9ICcnO1xuXHRcdGlmIChwYXJ0cy5sZW5ndGggPiAxKSB7XG5cdFx0XHQvLyBJbiBlbWFpbCBhZGRyZXNzZXMsIG9ubHkgdGhlIGRvbWFpbiBuYW1lIHNob3VsZCBiZSBwdW55Y29kZWQuIExlYXZlXG5cdFx0XHQvLyB0aGUgbG9jYWwgcGFydCAoaS5lLiBldmVyeXRoaW5nIHVwIHRvIGBAYCkgaW50YWN0LlxuXHRcdFx0cmVzdWx0ID0gcGFydHNbMF0gKyAnQCc7XG5cdFx0XHRzdHJpbmcgPSBwYXJ0c1sxXTtcblx0XHR9XG5cdFx0Ly8gQXZvaWQgYHNwbGl0KHJlZ2V4KWAgZm9yIElFOCBjb21wYXRpYmlsaXR5LiBTZWUgIzE3LlxuXHRcdHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKHJlZ2V4U2VwYXJhdG9ycywgJ1xceDJFJyk7XG5cdFx0dmFyIGxhYmVscyA9IHN0cmluZy5zcGxpdCgnLicpO1xuXHRcdHZhciBlbmNvZGVkID0gbWFwKGxhYmVscywgZm4pLmpvaW4oJy4nKTtcblx0XHRyZXR1cm4gcmVzdWx0ICsgZW5jb2RlZDtcblx0fVxuXG5cdC8qKlxuXHQgKiBDcmVhdGVzIGFuIGFycmF5IGNvbnRhaW5pbmcgdGhlIG51bWVyaWMgY29kZSBwb2ludHMgb2YgZWFjaCBVbmljb2RlXG5cdCAqIGNoYXJhY3RlciBpbiB0aGUgc3RyaW5nLiBXaGlsZSBKYXZhU2NyaXB0IHVzZXMgVUNTLTIgaW50ZXJuYWxseSxcblx0ICogdGhpcyBmdW5jdGlvbiB3aWxsIGNvbnZlcnQgYSBwYWlyIG9mIHN1cnJvZ2F0ZSBoYWx2ZXMgKGVhY2ggb2Ygd2hpY2hcblx0ICogVUNTLTIgZXhwb3NlcyBhcyBzZXBhcmF0ZSBjaGFyYWN0ZXJzKSBpbnRvIGEgc2luZ2xlIGNvZGUgcG9pbnQsXG5cdCAqIG1hdGNoaW5nIFVURi0xNi5cblx0ICogQHNlZSBgcHVueWNvZGUudWNzMi5lbmNvZGVgXG5cdCAqIEBzZWUgPGh0dHBzOi8vbWF0aGlhc2J5bmVucy5iZS9ub3Rlcy9qYXZhc2NyaXB0LWVuY29kaW5nPlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGUudWNzMlxuXHQgKiBAbmFtZSBkZWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0cmluZyBUaGUgVW5pY29kZSBpbnB1dCBzdHJpbmcgKFVDUy0yKS5cblx0ICogQHJldHVybnMge0FycmF5fSBUaGUgbmV3IGFycmF5IG9mIGNvZGUgcG9pbnRzLlxuXHQgKi9cblx0ZnVuY3Rpb24gdWNzMmRlY29kZShzdHJpbmcpIHtcblx0XHR2YXIgb3V0cHV0ID0gW10sXG5cdFx0ICAgIGNvdW50ZXIgPSAwLFxuXHRcdCAgICBsZW5ndGggPSBzdHJpbmcubGVuZ3RoLFxuXHRcdCAgICB2YWx1ZSxcblx0XHQgICAgZXh0cmE7XG5cdFx0d2hpbGUgKGNvdW50ZXIgPCBsZW5ndGgpIHtcblx0XHRcdHZhbHVlID0gc3RyaW5nLmNoYXJDb2RlQXQoY291bnRlcisrKTtcblx0XHRcdGlmICh2YWx1ZSA+PSAweEQ4MDAgJiYgdmFsdWUgPD0gMHhEQkZGICYmIGNvdW50ZXIgPCBsZW5ndGgpIHtcblx0XHRcdFx0Ly8gaGlnaCBzdXJyb2dhdGUsIGFuZCB0aGVyZSBpcyBhIG5leHQgY2hhcmFjdGVyXG5cdFx0XHRcdGV4dHJhID0gc3RyaW5nLmNoYXJDb2RlQXQoY291bnRlcisrKTtcblx0XHRcdFx0aWYgKChleHRyYSAmIDB4RkMwMCkgPT0gMHhEQzAwKSB7IC8vIGxvdyBzdXJyb2dhdGVcblx0XHRcdFx0XHRvdXRwdXQucHVzaCgoKHZhbHVlICYgMHgzRkYpIDw8IDEwKSArIChleHRyYSAmIDB4M0ZGKSArIDB4MTAwMDApO1xuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdC8vIHVubWF0Y2hlZCBzdXJyb2dhdGU7IG9ubHkgYXBwZW5kIHRoaXMgY29kZSB1bml0LCBpbiBjYXNlIHRoZSBuZXh0XG5cdFx0XHRcdFx0Ly8gY29kZSB1bml0IGlzIHRoZSBoaWdoIHN1cnJvZ2F0ZSBvZiBhIHN1cnJvZ2F0ZSBwYWlyXG5cdFx0XHRcdFx0b3V0cHV0LnB1c2godmFsdWUpO1xuXHRcdFx0XHRcdGNvdW50ZXItLTtcblx0XHRcdFx0fVxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0b3V0cHV0LnB1c2godmFsdWUpO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gb3V0cHV0O1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYSBzdHJpbmcgYmFzZWQgb24gYW4gYXJyYXkgb2YgbnVtZXJpYyBjb2RlIHBvaW50cy5cblx0ICogQHNlZSBgcHVueWNvZGUudWNzMi5kZWNvZGVgXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZS51Y3MyXG5cdCAqIEBuYW1lIGVuY29kZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBjb2RlUG9pbnRzIFRoZSBhcnJheSBvZiBudW1lcmljIGNvZGUgcG9pbnRzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgbmV3IFVuaWNvZGUgc3RyaW5nIChVQ1MtMikuXG5cdCAqL1xuXHRmdW5jdGlvbiB1Y3MyZW5jb2RlKGFycmF5KSB7XG5cdFx0cmV0dXJuIG1hcChhcnJheSwgZnVuY3Rpb24odmFsdWUpIHtcblx0XHRcdHZhciBvdXRwdXQgPSAnJztcblx0XHRcdGlmICh2YWx1ZSA+IDB4RkZGRikge1xuXHRcdFx0XHR2YWx1ZSAtPSAweDEwMDAwO1xuXHRcdFx0XHRvdXRwdXQgKz0gc3RyaW5nRnJvbUNoYXJDb2RlKHZhbHVlID4+PiAxMCAmIDB4M0ZGIHwgMHhEODAwKTtcblx0XHRcdFx0dmFsdWUgPSAweERDMDAgfCB2YWx1ZSAmIDB4M0ZGO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0ICs9IHN0cmluZ0Zyb21DaGFyQ29kZSh2YWx1ZSk7XG5cdFx0XHRyZXR1cm4gb3V0cHV0O1xuXHRcdH0pLmpvaW4oJycpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgYmFzaWMgY29kZSBwb2ludCBpbnRvIGEgZGlnaXQvaW50ZWdlci5cblx0ICogQHNlZSBgZGlnaXRUb0Jhc2ljKClgXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjb2RlUG9pbnQgVGhlIGJhc2ljIG51bWVyaWMgY29kZSBwb2ludCB2YWx1ZS5cblx0ICogQHJldHVybnMge051bWJlcn0gVGhlIG51bWVyaWMgdmFsdWUgb2YgYSBiYXNpYyBjb2RlIHBvaW50IChmb3IgdXNlIGluXG5cdCAqIHJlcHJlc2VudGluZyBpbnRlZ2VycykgaW4gdGhlIHJhbmdlIGAwYCB0byBgYmFzZSAtIDFgLCBvciBgYmFzZWAgaWZcblx0ICogdGhlIGNvZGUgcG9pbnQgZG9lcyBub3QgcmVwcmVzZW50IGEgdmFsdWUuXG5cdCAqL1xuXHRmdW5jdGlvbiBiYXNpY1RvRGlnaXQoY29kZVBvaW50KSB7XG5cdFx0aWYgKGNvZGVQb2ludCAtIDQ4IDwgMTApIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSAyMjtcblx0XHR9XG5cdFx0aWYgKGNvZGVQb2ludCAtIDY1IDwgMjYpIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSA2NTtcblx0XHR9XG5cdFx0aWYgKGNvZGVQb2ludCAtIDk3IDwgMjYpIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSA5Nztcblx0XHR9XG5cdFx0cmV0dXJuIGJhc2U7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBkaWdpdC9pbnRlZ2VyIGludG8gYSBiYXNpYyBjb2RlIHBvaW50LlxuXHQgKiBAc2VlIGBiYXNpY1RvRGlnaXQoKWBcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IGRpZ2l0IFRoZSBudW1lcmljIHZhbHVlIG9mIGEgYmFzaWMgY29kZSBwb2ludC5cblx0ICogQHJldHVybnMge051bWJlcn0gVGhlIGJhc2ljIGNvZGUgcG9pbnQgd2hvc2UgdmFsdWUgKHdoZW4gdXNlZCBmb3Jcblx0ICogcmVwcmVzZW50aW5nIGludGVnZXJzKSBpcyBgZGlnaXRgLCB3aGljaCBuZWVkcyB0byBiZSBpbiB0aGUgcmFuZ2Vcblx0ICogYDBgIHRvIGBiYXNlIC0gMWAuIElmIGBmbGFnYCBpcyBub24temVybywgdGhlIHVwcGVyY2FzZSBmb3JtIGlzXG5cdCAqIHVzZWQ7IGVsc2UsIHRoZSBsb3dlcmNhc2UgZm9ybSBpcyB1c2VkLiBUaGUgYmVoYXZpb3IgaXMgdW5kZWZpbmVkXG5cdCAqIGlmIGBmbGFnYCBpcyBub24temVybyBhbmQgYGRpZ2l0YCBoYXMgbm8gdXBwZXJjYXNlIGZvcm0uXG5cdCAqL1xuXHRmdW5jdGlvbiBkaWdpdFRvQmFzaWMoZGlnaXQsIGZsYWcpIHtcblx0XHQvLyAgMC4uMjUgbWFwIHRvIEFTQ0lJIGEuLnogb3IgQS4uWlxuXHRcdC8vIDI2Li4zNSBtYXAgdG8gQVNDSUkgMC4uOVxuXHRcdHJldHVybiBkaWdpdCArIDIyICsgNzUgKiAoZGlnaXQgPCAyNikgLSAoKGZsYWcgIT0gMCkgPDwgNSk7XG5cdH1cblxuXHQvKipcblx0ICogQmlhcyBhZGFwdGF0aW9uIGZ1bmN0aW9uIGFzIHBlciBzZWN0aW9uIDMuNCBvZiBSRkMgMzQ5Mi5cblx0ICogaHR0cDovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjMzQ5MiNzZWN0aW9uLTMuNFxuXHQgKiBAcHJpdmF0ZVxuXHQgKi9cblx0ZnVuY3Rpb24gYWRhcHQoZGVsdGEsIG51bVBvaW50cywgZmlyc3RUaW1lKSB7XG5cdFx0dmFyIGsgPSAwO1xuXHRcdGRlbHRhID0gZmlyc3RUaW1lID8gZmxvb3IoZGVsdGEgLyBkYW1wKSA6IGRlbHRhID4+IDE7XG5cdFx0ZGVsdGEgKz0gZmxvb3IoZGVsdGEgLyBudW1Qb2ludHMpO1xuXHRcdGZvciAoLyogbm8gaW5pdGlhbGl6YXRpb24gKi87IGRlbHRhID4gYmFzZU1pbnVzVE1pbiAqIHRNYXggPj4gMTsgayArPSBiYXNlKSB7XG5cdFx0XHRkZWx0YSA9IGZsb29yKGRlbHRhIC8gYmFzZU1pbnVzVE1pbik7XG5cdFx0fVxuXHRcdHJldHVybiBmbG9vcihrICsgKGJhc2VNaW51c1RNaW4gKyAxKSAqIGRlbHRhIC8gKGRlbHRhICsgc2tldykpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scyB0byBhIHN0cmluZyBvZiBVbmljb2RlXG5cdCAqIHN5bWJvbHMuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSByZXN1bHRpbmcgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scy5cblx0ICovXG5cdGZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuXHRcdC8vIERvbid0IHVzZSBVQ1MtMlxuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgaW5wdXRMZW5ndGggPSBpbnB1dC5sZW5ndGgsXG5cdFx0ICAgIG91dCxcblx0XHQgICAgaSA9IDAsXG5cdFx0ICAgIG4gPSBpbml0aWFsTixcblx0XHQgICAgYmlhcyA9IGluaXRpYWxCaWFzLFxuXHRcdCAgICBiYXNpYyxcblx0XHQgICAgaixcblx0XHQgICAgaW5kZXgsXG5cdFx0ICAgIG9sZGksXG5cdFx0ICAgIHcsXG5cdFx0ICAgIGssXG5cdFx0ICAgIGRpZ2l0LFxuXHRcdCAgICB0LFxuXHRcdCAgICAvKiogQ2FjaGVkIGNhbGN1bGF0aW9uIHJlc3VsdHMgKi9cblx0XHQgICAgYmFzZU1pbnVzVDtcblxuXHRcdC8vIEhhbmRsZSB0aGUgYmFzaWMgY29kZSBwb2ludHM6IGxldCBgYmFzaWNgIGJlIHRoZSBudW1iZXIgb2YgaW5wdXQgY29kZVxuXHRcdC8vIHBvaW50cyBiZWZvcmUgdGhlIGxhc3QgZGVsaW1pdGVyLCBvciBgMGAgaWYgdGhlcmUgaXMgbm9uZSwgdGhlbiBjb3B5XG5cdFx0Ly8gdGhlIGZpcnN0IGJhc2ljIGNvZGUgcG9pbnRzIHRvIHRoZSBvdXRwdXQuXG5cblx0XHRiYXNpYyA9IGlucHV0Lmxhc3RJbmRleE9mKGRlbGltaXRlcik7XG5cdFx0aWYgKGJhc2ljIDwgMCkge1xuXHRcdFx0YmFzaWMgPSAwO1xuXHRcdH1cblxuXHRcdGZvciAoaiA9IDA7IGogPCBiYXNpYzsgKytqKSB7XG5cdFx0XHQvLyBpZiBpdCdzIG5vdCBhIGJhc2ljIGNvZGUgcG9pbnRcblx0XHRcdGlmIChpbnB1dC5jaGFyQ29kZUF0KGopID49IDB4ODApIHtcblx0XHRcdFx0ZXJyb3IoJ25vdC1iYXNpYycpO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0LnB1c2goaW5wdXQuY2hhckNvZGVBdChqKSk7XG5cdFx0fVxuXG5cdFx0Ly8gTWFpbiBkZWNvZGluZyBsb29wOiBzdGFydCBqdXN0IGFmdGVyIHRoZSBsYXN0IGRlbGltaXRlciBpZiBhbnkgYmFzaWMgY29kZVxuXHRcdC8vIHBvaW50cyB3ZXJlIGNvcGllZDsgc3RhcnQgYXQgdGhlIGJlZ2lubmluZyBvdGhlcndpc2UuXG5cblx0XHRmb3IgKGluZGV4ID0gYmFzaWMgPiAwID8gYmFzaWMgKyAxIDogMDsgaW5kZXggPCBpbnB1dExlbmd0aDsgLyogbm8gZmluYWwgZXhwcmVzc2lvbiAqLykge1xuXG5cdFx0XHQvLyBgaW5kZXhgIGlzIHRoZSBpbmRleCBvZiB0aGUgbmV4dCBjaGFyYWN0ZXIgdG8gYmUgY29uc3VtZWQuXG5cdFx0XHQvLyBEZWNvZGUgYSBnZW5lcmFsaXplZCB2YXJpYWJsZS1sZW5ndGggaW50ZWdlciBpbnRvIGBkZWx0YWAsXG5cdFx0XHQvLyB3aGljaCBnZXRzIGFkZGVkIHRvIGBpYC4gVGhlIG92ZXJmbG93IGNoZWNraW5nIGlzIGVhc2llclxuXHRcdFx0Ly8gaWYgd2UgaW5jcmVhc2UgYGlgIGFzIHdlIGdvLCB0aGVuIHN1YnRyYWN0IG9mZiBpdHMgc3RhcnRpbmdcblx0XHRcdC8vIHZhbHVlIGF0IHRoZSBlbmQgdG8gb2J0YWluIGBkZWx0YWAuXG5cdFx0XHRmb3IgKG9sZGkgPSBpLCB3ID0gMSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cblx0XHRcdFx0aWYgKGluZGV4ID49IGlucHV0TGVuZ3RoKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ2ludmFsaWQtaW5wdXQnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGRpZ2l0ID0gYmFzaWNUb0RpZ2l0KGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrKykpO1xuXG5cdFx0XHRcdGlmIChkaWdpdCA+PSBiYXNlIHx8IGRpZ2l0ID4gZmxvb3IoKG1heEludCAtIGkpIC8gdykpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGkgKz0gZGlnaXQgKiB3O1xuXHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblxuXHRcdFx0XHRpZiAoZGlnaXQgPCB0KSB7XG5cdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRiYXNlTWludXNUID0gYmFzZSAtIHQ7XG5cdFx0XHRcdGlmICh3ID4gZmxvb3IobWF4SW50IC8gYmFzZU1pbnVzVCkpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHcgKj0gYmFzZU1pbnVzVDtcblxuXHRcdFx0fVxuXG5cdFx0XHRvdXQgPSBvdXRwdXQubGVuZ3RoICsgMTtcblx0XHRcdGJpYXMgPSBhZGFwdChpIC0gb2xkaSwgb3V0LCBvbGRpID09IDApO1xuXG5cdFx0XHQvLyBgaWAgd2FzIHN1cHBvc2VkIHRvIHdyYXAgYXJvdW5kIGZyb20gYG91dGAgdG8gYDBgLFxuXHRcdFx0Ly8gaW5jcmVtZW50aW5nIGBuYCBlYWNoIHRpbWUsIHNvIHdlJ2xsIGZpeCB0aGF0IG5vdzpcblx0XHRcdGlmIChmbG9vcihpIC8gb3V0KSA+IG1heEludCAtIG4pIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdG4gKz0gZmxvb3IoaSAvIG91dCk7XG5cdFx0XHRpICU9IG91dDtcblxuXHRcdFx0Ly8gSW5zZXJ0IGBuYCBhdCBwb3NpdGlvbiBgaWAgb2YgdGhlIG91dHB1dFxuXHRcdFx0b3V0cHV0LnNwbGljZShpKyssIDAsIG4pO1xuXG5cdFx0fVxuXG5cdFx0cmV0dXJuIHVjczJlbmNvZGUob3V0cHV0KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMgKGUuZy4gYSBkb21haW4gbmFtZSBsYWJlbCkgdG8gYVxuXHQgKiBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgcmVzdWx0aW5nIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBlbmNvZGUoaW5wdXQpIHtcblx0XHR2YXIgbixcblx0XHQgICAgZGVsdGEsXG5cdFx0ICAgIGhhbmRsZWRDUENvdW50LFxuXHRcdCAgICBiYXNpY0xlbmd0aCxcblx0XHQgICAgYmlhcyxcblx0XHQgICAgaixcblx0XHQgICAgbSxcblx0XHQgICAgcSxcblx0XHQgICAgayxcblx0XHQgICAgdCxcblx0XHQgICAgY3VycmVudFZhbHVlLFxuXHRcdCAgICBvdXRwdXQgPSBbXSxcblx0XHQgICAgLyoqIGBpbnB1dExlbmd0aGAgd2lsbCBob2xkIHRoZSBudW1iZXIgb2YgY29kZSBwb2ludHMgaW4gYGlucHV0YC4gKi9cblx0XHQgICAgaW5wdXRMZW5ndGgsXG5cdFx0ICAgIC8qKiBDYWNoZWQgY2FsY3VsYXRpb24gcmVzdWx0cyAqL1xuXHRcdCAgICBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsXG5cdFx0ICAgIGJhc2VNaW51c1QsXG5cdFx0ICAgIHFNaW51c1Q7XG5cblx0XHQvLyBDb252ZXJ0IHRoZSBpbnB1dCBpbiBVQ1MtMiB0byBVbmljb2RlXG5cdFx0aW5wdXQgPSB1Y3MyZGVjb2RlKGlucHV0KTtcblxuXHRcdC8vIENhY2hlIHRoZSBsZW5ndGhcblx0XHRpbnB1dExlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblxuXHRcdC8vIEluaXRpYWxpemUgdGhlIHN0YXRlXG5cdFx0biA9IGluaXRpYWxOO1xuXHRcdGRlbHRhID0gMDtcblx0XHRiaWFzID0gaW5pdGlhbEJpYXM7XG5cblx0XHQvLyBIYW5kbGUgdGhlIGJhc2ljIGNvZGUgcG9pbnRzXG5cdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IDB4ODApIHtcblx0XHRcdFx0b3V0cHV0LnB1c2goc3RyaW5nRnJvbUNoYXJDb2RlKGN1cnJlbnRWYWx1ZSkpO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdGhhbmRsZWRDUENvdW50ID0gYmFzaWNMZW5ndGggPSBvdXRwdXQubGVuZ3RoO1xuXG5cdFx0Ly8gYGhhbmRsZWRDUENvdW50YCBpcyB0aGUgbnVtYmVyIG9mIGNvZGUgcG9pbnRzIHRoYXQgaGF2ZSBiZWVuIGhhbmRsZWQ7XG5cdFx0Ly8gYGJhc2ljTGVuZ3RoYCBpcyB0aGUgbnVtYmVyIG9mIGJhc2ljIGNvZGUgcG9pbnRzLlxuXG5cdFx0Ly8gRmluaXNoIHRoZSBiYXNpYyBzdHJpbmcgLSBpZiBpdCBpcyBub3QgZW1wdHkgLSB3aXRoIGEgZGVsaW1pdGVyXG5cdFx0aWYgKGJhc2ljTGVuZ3RoKSB7XG5cdFx0XHRvdXRwdXQucHVzaChkZWxpbWl0ZXIpO1xuXHRcdH1cblxuXHRcdC8vIE1haW4gZW5jb2RpbmcgbG9vcDpcblx0XHR3aGlsZSAoaGFuZGxlZENQQ291bnQgPCBpbnB1dExlbmd0aCkge1xuXG5cdFx0XHQvLyBBbGwgbm9uLWJhc2ljIGNvZGUgcG9pbnRzIDwgbiBoYXZlIGJlZW4gaGFuZGxlZCBhbHJlYWR5LiBGaW5kIHRoZSBuZXh0XG5cdFx0XHQvLyBsYXJnZXIgb25lOlxuXHRcdFx0Zm9yIChtID0gbWF4SW50LCBqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPj0gbiAmJiBjdXJyZW50VmFsdWUgPCBtKSB7XG5cdFx0XHRcdFx0bSA9IGN1cnJlbnRWYWx1ZTtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQvLyBJbmNyZWFzZSBgZGVsdGFgIGVub3VnaCB0byBhZHZhbmNlIHRoZSBkZWNvZGVyJ3MgPG4saT4gc3RhdGUgdG8gPG0sMD4sXG5cdFx0XHQvLyBidXQgZ3VhcmQgYWdhaW5zdCBvdmVyZmxvd1xuXHRcdFx0aGFuZGxlZENQQ291bnRQbHVzT25lID0gaGFuZGxlZENQQ291bnQgKyAxO1xuXHRcdFx0aWYgKG0gLSBuID4gZmxvb3IoKG1heEludCAtIGRlbHRhKSAvIGhhbmRsZWRDUENvdW50UGx1c09uZSkpIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdGRlbHRhICs9IChtIC0gbikgKiBoYW5kbGVkQ1BDb3VudFBsdXNPbmU7XG5cdFx0XHRuID0gbTtcblxuXHRcdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IG4gJiYgKytkZWx0YSA+IG1heEludCkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA9PSBuKSB7XG5cdFx0XHRcdFx0Ly8gUmVwcmVzZW50IGRlbHRhIGFzIGEgZ2VuZXJhbGl6ZWQgdmFyaWFibGUtbGVuZ3RoIGludGVnZXJcblx0XHRcdFx0XHRmb3IgKHEgPSBkZWx0YSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cdFx0XHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblx0XHRcdFx0XHRcdGlmIChxIDwgdCkge1xuXHRcdFx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRcdHFNaW51c1QgPSBxIC0gdDtcblx0XHRcdFx0XHRcdGJhc2VNaW51c1QgPSBiYXNlIC0gdDtcblx0XHRcdFx0XHRcdG91dHB1dC5wdXNoKFxuXHRcdFx0XHRcdFx0XHRzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHQgKyBxTWludXNUICUgYmFzZU1pbnVzVCwgMCkpXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHRcdFx0cSA9IGZsb29yKHFNaW51c1QgLyBiYXNlTWludXNUKTtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHRvdXRwdXQucHVzaChzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHEsIDApKSk7XG5cdFx0XHRcdFx0YmlhcyA9IGFkYXB0KGRlbHRhLCBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsIGhhbmRsZWRDUENvdW50ID09IGJhc2ljTGVuZ3RoKTtcblx0XHRcdFx0XHRkZWx0YSA9IDA7XG5cdFx0XHRcdFx0KytoYW5kbGVkQ1BDb3VudDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQrK2RlbHRhO1xuXHRcdFx0KytuO1xuXG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBQdW55Y29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzc1xuXHQgKiB0byBVbmljb2RlLiBPbmx5IHRoZSBQdW55Y29kZWQgcGFydHMgb2YgdGhlIGlucHV0IHdpbGwgYmUgY29udmVydGVkLCBpLmUuXG5cdCAqIGl0IGRvZXNuJ3QgbWF0dGVyIGlmIHlvdSBjYWxsIGl0IG9uIGEgc3RyaW5nIHRoYXQgaGFzIGFscmVhZHkgYmVlblxuXHQgKiBjb252ZXJ0ZWQgdG8gVW5pY29kZS5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgUHVueWNvZGVkIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MgdG9cblx0ICogY29udmVydCB0byBVbmljb2RlLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgVW5pY29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gUHVueWNvZGVcblx0ICogc3RyaW5nLlxuXHQgKi9cblx0ZnVuY3Rpb24gdG9Vbmljb2RlKGlucHV0KSB7XG5cdFx0cmV0dXJuIG1hcERvbWFpbihpbnB1dCwgZnVuY3Rpb24oc3RyaW5nKSB7XG5cdFx0XHRyZXR1cm4gcmVnZXhQdW55Y29kZS50ZXN0KHN0cmluZylcblx0XHRcdFx0PyBkZWNvZGUoc3RyaW5nLnNsaWNlKDQpLnRvTG93ZXJDYXNlKCkpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgVW5pY29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzcyB0b1xuXHQgKiBQdW55Y29kZS4gT25seSB0aGUgbm9uLUFTQ0lJIHBhcnRzIG9mIHRoZSBkb21haW4gbmFtZSB3aWxsIGJlIGNvbnZlcnRlZCxcblx0ICogaS5lLiBpdCBkb2Vzbid0IG1hdHRlciBpZiB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQncyBhbHJlYWR5IGluXG5cdCAqIEFTQ0lJLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzIHRvIGNvbnZlcnQsIGFzIGFcblx0ICogVW5pY29kZSBzdHJpbmcuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBQdW55Y29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gZG9tYWluIG5hbWUgb3Jcblx0ICogZW1haWwgYWRkcmVzcy5cblx0ICovXG5cdGZ1bmN0aW9uIHRvQVNDSUkoaW5wdXQpIHtcblx0XHRyZXR1cm4gbWFwRG9tYWluKGlucHV0LCBmdW5jdGlvbihzdHJpbmcpIHtcblx0XHRcdHJldHVybiByZWdleE5vbkFTQ0lJLnRlc3Qoc3RyaW5nKVxuXHRcdFx0XHQ/ICd4bi0tJyArIGVuY29kZShzdHJpbmcpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqIERlZmluZSB0aGUgcHVibGljIEFQSSAqL1xuXHRwdW55Y29kZSA9IHtcblx0XHQvKipcblx0XHQgKiBBIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIGN1cnJlbnQgUHVueWNvZGUuanMgdmVyc2lvbiBudW1iZXIuXG5cdFx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdFx0ICogQHR5cGUgU3RyaW5nXG5cdFx0ICovXG5cdFx0J3ZlcnNpb24nOiAnMS4zLjInLFxuXHRcdC8qKlxuXHRcdCAqIEFuIG9iamVjdCBvZiBtZXRob2RzIHRvIGNvbnZlcnQgZnJvbSBKYXZhU2NyaXB0J3MgaW50ZXJuYWwgY2hhcmFjdGVyXG5cdFx0ICogcmVwcmVzZW50YXRpb24gKFVDUy0yKSB0byBVbmljb2RlIGNvZGUgcG9pbnRzLCBhbmQgYmFjay5cblx0XHQgKiBAc2VlIDxodHRwczovL21hdGhpYXNieW5lbnMuYmUvbm90ZXMvamF2YXNjcmlwdC1lbmNvZGluZz5cblx0XHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0XHQgKiBAdHlwZSBPYmplY3Rcblx0XHQgKi9cblx0XHQndWNzMic6IHtcblx0XHRcdCdkZWNvZGUnOiB1Y3MyZGVjb2RlLFxuXHRcdFx0J2VuY29kZSc6IHVjczJlbmNvZGVcblx0XHR9LFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J2VuY29kZSc6IGVuY29kZSxcblx0XHQndG9BU0NJSSc6IHRvQVNDSUksXG5cdFx0J3RvVW5pY29kZSc6IHRvVW5pY29kZVxuXHR9O1xuXG5cdC8qKiBFeHBvc2UgYHB1bnljb2RlYCAqL1xuXHQvLyBTb21lIEFNRCBidWlsZCBvcHRpbWl6ZXJzLCBsaWtlIHIuanMsIGNoZWNrIGZvciBzcGVjaWZpYyBjb25kaXRpb24gcGF0dGVybnNcblx0Ly8gbGlrZSB0aGUgZm9sbG93aW5nOlxuXHRpZiAoXG5cdFx0dHlwZW9mIGRlZmluZSA9PSAnZnVuY3Rpb24nICYmXG5cdFx0dHlwZW9mIGRlZmluZS5hbWQgPT0gJ29iamVjdCcgJiZcblx0XHRkZWZpbmUuYW1kXG5cdCkge1xuXHRcdGRlZmluZSgncHVueWNvZGUnLCBmdW5jdGlvbigpIHtcblx0XHRcdHJldHVybiBwdW55Y29kZTtcblx0XHR9KTtcblx0fSBlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiBmcmVlTW9kdWxlKSB7XG5cdFx0aWYgKG1vZHVsZS5leHBvcnRzID09IGZyZWVFeHBvcnRzKSB7IC8vIGluIE5vZGUuanMgb3IgUmluZ29KUyB2MC44LjArXG5cdFx0XHRmcmVlTW9kdWxlLmV4cG9ydHMgPSBwdW55Y29kZTtcblx0XHR9IGVsc2UgeyAvLyBpbiBOYXJ3aGFsIG9yIFJpbmdvSlMgdjAuNy4wLVxuXHRcdFx0Zm9yIChrZXkgaW4gcHVueWNvZGUpIHtcblx0XHRcdFx0cHVueWNvZGUuaGFzT3duUHJvcGVydHkoa2V5KSAmJiAoZnJlZUV4cG9ydHNba2V5XSA9IHB1bnljb2RlW2tleV0pO1xuXHRcdFx0fVxuXHRcdH1cblx0fSBlbHNlIHsgLy8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QucHVueWNvZGUgPSBwdW55Y29kZTtcblx0fVxuXG59KHRoaXMpKTtcbiIsIi8qXG4gKiBxdWFudGl6ZS5qcyBDb3B5cmlnaHQgMjAwOCBOaWNrIFJhYmlub3dpdHpcbiAqIFBvcnRlZCB0byBub2RlLmpzIGJ5IE9saXZpZXIgTGVzbmlja2lcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZTogaHR0cDovL3d3dy5vcGVuc291cmNlLm9yZy9saWNlbnNlcy9taXQtbGljZW5zZS5waHBcbiAqL1xuXG4vLyBmaWxsIG91dCBhIGNvdXBsZSBwcm90b3ZpcyBkZXBlbmRlbmNpZXNcbi8qXG4gKiBCbG9jayBiZWxvdyBjb3BpZWQgZnJvbSBQcm90b3ZpczogaHR0cDovL21ib3N0b2NrLmdpdGh1Yi5jb20vcHJvdG92aXMvXG4gKiBDb3B5cmlnaHQgMjAxMCBTdGFuZm9yZCBWaXN1YWxpemF0aW9uIEdyb3VwXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgQlNEIExpY2Vuc2U6IGh0dHA6Ly93d3cub3BlbnNvdXJjZS5vcmcvbGljZW5zZXMvYnNkLWxpY2Vuc2UucGhwXG4gKi9cbmlmICghcHYpIHtcbiAgICB2YXIgcHYgPSB7XG4gICAgICAgIG1hcDogZnVuY3Rpb24oYXJyYXksIGYpIHtcbiAgICAgICAgICAgIHZhciBvID0ge307XG4gICAgICAgICAgICByZXR1cm4gZiA/IGFycmF5Lm1hcChmdW5jdGlvbihkLCBpKSB7XG4gICAgICAgICAgICAgICAgby5pbmRleCA9IGk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGYuY2FsbChvLCBkKTtcbiAgICAgICAgICAgIH0pIDogYXJyYXkuc2xpY2UoKTtcbiAgICAgICAgfSxcbiAgICAgICAgbmF0dXJhbE9yZGVyOiBmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gKGEgPCBiKSA/IC0xIDogKChhID4gYikgPyAxIDogMCk7XG4gICAgICAgIH0sXG4gICAgICAgIHN1bTogZnVuY3Rpb24oYXJyYXksIGYpIHtcbiAgICAgICAgICAgIHZhciBvID0ge307XG4gICAgICAgICAgICByZXR1cm4gYXJyYXkucmVkdWNlKGYgPyBmdW5jdGlvbihwLCBkLCBpKSB7XG4gICAgICAgICAgICAgICAgby5pbmRleCA9IGk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHAgKyBmLmNhbGwobywgZCk7XG4gICAgICAgICAgICB9IDogZnVuY3Rpb24ocCwgZCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBwICsgZDtcbiAgICAgICAgICAgIH0sIDApO1xuICAgICAgICB9LFxuICAgICAgICBtYXg6IGZ1bmN0aW9uKGFycmF5LCBmKSB7XG4gICAgICAgICAgICByZXR1cm4gTWF0aC5tYXguYXBwbHkobnVsbCwgZiA/IHB2Lm1hcChhcnJheSwgZikgOiBhcnJheSk7XG4gICAgICAgIH1cbiAgICB9XG59XG5cbi8qKlxuICogQmFzaWMgSmF2YXNjcmlwdCBwb3J0IG9mIHRoZSBNTUNRIChtb2RpZmllZCBtZWRpYW4gY3V0IHF1YW50aXphdGlvbilcbiAqIGFsZ29yaXRobSBmcm9tIHRoZSBMZXB0b25pY2EgbGlicmFyeSAoaHR0cDovL3d3dy5sZXB0b25pY2EuY29tLykuXG4gKiBSZXR1cm5zIGEgY29sb3IgbWFwIHlvdSBjYW4gdXNlIHRvIG1hcCBvcmlnaW5hbCBwaXhlbHMgdG8gdGhlIHJlZHVjZWRcbiAqIHBhbGV0dGUuIFN0aWxsIGEgd29yayBpbiBwcm9ncmVzcy5cbiAqIFxuICogQGF1dGhvciBOaWNrIFJhYmlub3dpdHpcbiAqIEBleGFtcGxlXG4gXG4vLyBhcnJheSBvZiBwaXhlbHMgYXMgW1IsRyxCXSBhcnJheXNcbnZhciBteVBpeGVscyA9IFtbMTkwLDE5NywxOTBdLCBbMjAyLDIwNCwyMDBdLCBbMjA3LDIxNCwyMTBdLCBbMjExLDIxNCwyMTFdLCBbMjA1LDIwNywyMDddXG4gICAgICAgICAgICAgICAgLy8gZXRjXG4gICAgICAgICAgICAgICAgXTtcbnZhciBtYXhDb2xvcnMgPSA0O1xuIFxudmFyIGNtYXAgPSBNTUNRLnF1YW50aXplKG15UGl4ZWxzLCBtYXhDb2xvcnMpO1xudmFyIG5ld1BhbGV0dGUgPSBjbWFwLnBhbGV0dGUoKTtcbnZhciBuZXdQaXhlbHMgPSBteVBpeGVscy5tYXAoZnVuY3Rpb24ocCkgeyBcbiAgICByZXR1cm4gY21hcC5tYXAocCk7IFxufSk7XG4gXG4gKi9cbnZhciBNTUNRID0gKGZ1bmN0aW9uKCkge1xuICAgIC8vIHByaXZhdGUgY29uc3RhbnRzXG4gICAgdmFyIHNpZ2JpdHMgPSA1LFxuICAgICAgICByc2hpZnQgPSA4IC0gc2lnYml0cyxcbiAgICAgICAgbWF4SXRlcmF0aW9ucyA9IDEwMDAsXG4gICAgICAgIGZyYWN0QnlQb3B1bGF0aW9ucyA9IDAuNzU7XG5cbiAgICAvLyBnZXQgcmVkdWNlZC1zcGFjZSBjb2xvciBpbmRleCBmb3IgYSBwaXhlbFxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3JJbmRleChyLCBnLCBiKSB7XG4gICAgICAgIHJldHVybiAociA8PCAoMiAqIHNpZ2JpdHMpKSArIChnIDw8IHNpZ2JpdHMpICsgYjtcbiAgICB9XG5cbiAgICAvLyBTaW1wbGUgcHJpb3JpdHkgcXVldWVcblxuICAgIGZ1bmN0aW9uIFBRdWV1ZShjb21wYXJhdG9yKSB7XG4gICAgICAgIHZhciBjb250ZW50cyA9IFtdLFxuICAgICAgICAgICAgc29ydGVkID0gZmFsc2U7XG5cbiAgICAgICAgZnVuY3Rpb24gc29ydCgpIHtcbiAgICAgICAgICAgIGNvbnRlbnRzLnNvcnQoY29tcGFyYXRvcik7XG4gICAgICAgICAgICBzb3J0ZWQgPSB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHB1c2g6IGZ1bmN0aW9uKG8pIHtcbiAgICAgICAgICAgICAgICBjb250ZW50cy5wdXNoKG8pO1xuICAgICAgICAgICAgICAgIHNvcnRlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHBlZWs6IGZ1bmN0aW9uKGluZGV4KSB7XG4gICAgICAgICAgICAgICAgaWYgKCFzb3J0ZWQpIHNvcnQoKTtcbiAgICAgICAgICAgICAgICBpZiAoaW5kZXggPT09IHVuZGVmaW5lZCkgaW5kZXggPSBjb250ZW50cy5sZW5ndGggLSAxO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50c1tpbmRleF07XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgcG9wOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNvcnRlZCkgc29ydCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cy5wb3AoKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzaXplOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHMubGVuZ3RoO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIG1hcDogZnVuY3Rpb24oZikge1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cy5tYXAoZik7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZGVidWc6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIGlmICghc29ydGVkKSBzb3J0KCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH1cblxuICAgIC8vIDNkIGNvbG9yIHNwYWNlIGJveFxuXG4gICAgZnVuY3Rpb24gVkJveChyMSwgcjIsIGcxLCBnMiwgYjEsIGIyLCBoaXN0bykge1xuICAgICAgICB2YXIgdmJveCA9IHRoaXM7XG4gICAgICAgIHZib3gucjEgPSByMTtcbiAgICAgICAgdmJveC5yMiA9IHIyO1xuICAgICAgICB2Ym94LmcxID0gZzE7XG4gICAgICAgIHZib3guZzIgPSBnMjtcbiAgICAgICAgdmJveC5iMSA9IGIxO1xuICAgICAgICB2Ym94LmIyID0gYjI7XG4gICAgICAgIHZib3guaGlzdG8gPSBoaXN0bztcbiAgICB9XG4gICAgVkJveC5wcm90b3R5cGUgPSB7XG4gICAgICAgIHZvbHVtZTogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcztcbiAgICAgICAgICAgIGlmICghdmJveC5fdm9sdW1lIHx8IGZvcmNlKSB7XG4gICAgICAgICAgICAgICAgdmJveC5fdm9sdW1lID0gKCh2Ym94LnIyIC0gdmJveC5yMSArIDEpICogKHZib3guZzIgLSB2Ym94LmcxICsgMSkgKiAodmJveC5iMiAtIHZib3guYjEgKyAxKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdmJveC5fdm9sdW1lO1xuICAgICAgICB9LFxuICAgICAgICBjb3VudDogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcyxcbiAgICAgICAgICAgICAgICBoaXN0byA9IHZib3guaGlzdG87XG4gICAgICAgICAgICBpZiAoIXZib3guX2NvdW50X3NldCB8fCBmb3JjZSkge1xuICAgICAgICAgICAgICAgIHZhciBucGl4ID0gMCxcbiAgICAgICAgICAgICAgICAgICAgaSwgaiwgaywgaW5kZXg7XG4gICAgICAgICAgICAgICAgZm9yIChpID0gdmJveC5yMTsgaSA8PSB2Ym94LnIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5nMTsgaiA8PSB2Ym94LmcyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGksIGosIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5waXggKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2Ym94Ll9jb3VudCA9IG5waXg7XG4gICAgICAgICAgICAgICAgdmJveC5fY291bnRfc2V0ID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB2Ym94Ll9jb3VudDtcbiAgICAgICAgfSxcbiAgICAgICAgY29weTogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXM7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFZCb3godmJveC5yMSwgdmJveC5yMiwgdmJveC5nMSwgdmJveC5nMiwgdmJveC5iMSwgdmJveC5iMiwgdmJveC5oaXN0byk7XG4gICAgICAgIH0sXG4gICAgICAgIGF2ZzogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcyxcbiAgICAgICAgICAgICAgICBoaXN0byA9IHZib3guaGlzdG87XG4gICAgICAgICAgICBpZiAoIXZib3guX2F2ZyB8fCBmb3JjZSkge1xuICAgICAgICAgICAgICAgIHZhciBudG90ID0gMCxcbiAgICAgICAgICAgICAgICAgICAgbXVsdCA9IDEgPDwgKDggLSBzaWdiaXRzKSxcbiAgICAgICAgICAgICAgICAgICAgcnN1bSA9IDAsXG4gICAgICAgICAgICAgICAgICAgIGdzdW0gPSAwLFxuICAgICAgICAgICAgICAgICAgICBic3VtID0gMCxcbiAgICAgICAgICAgICAgICAgICAgaHZhbCxcbiAgICAgICAgICAgICAgICAgICAgaSwgaiwgaywgaGlzdG9pbmRleDtcbiAgICAgICAgICAgICAgICBmb3IgKGkgPSB2Ym94LnIxOyBpIDw9IHZib3gucjI7IGkrKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LmcxOyBqIDw9IHZib3guZzI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5iMTsgayA8PSB2Ym94LmIyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoaXN0b2luZGV4ID0gZ2V0Q29sb3JJbmRleChpLCBqLCBrKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBodmFsID0gaGlzdG9baGlzdG9pbmRleF0gfHwgMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBudG90ICs9IGh2YWw7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcnN1bSArPSAoaHZhbCAqIChpICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGdzdW0gKz0gKGh2YWwgKiAoaiArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBic3VtICs9IChodmFsICogKGsgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKG50b3QpIHtcbiAgICAgICAgICAgICAgICAgICAgdmJveC5fYXZnID0gW35+KHJzdW0gLyBudG90KSwgfn4gKGdzdW0gLyBudG90KSwgfn4gKGJzdW0gLyBudG90KV07XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgLy9jb25zb2xlLmxvZygnZW1wdHkgYm94Jyk7XG4gICAgICAgICAgICAgICAgICAgIHZib3guX2F2ZyA9IFt+fihtdWx0ICogKHZib3gucjEgKyB2Ym94LnIyICsgMSkgLyAyKSwgfn4gKG11bHQgKiAodmJveC5nMSArIHZib3guZzIgKyAxKSAvIDIpLCB+fiAobXVsdCAqICh2Ym94LmIxICsgdmJveC5iMiArIDEpIC8gMildO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB2Ym94Ll9hdmc7XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRhaW5zOiBmdW5jdGlvbihwaXhlbCkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzLFxuICAgICAgICAgICAgICAgIHJ2YWwgPSBwaXhlbFswXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBndmFsID0gcGl4ZWxbMV0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgYnZhbCA9IHBpeGVsWzJdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIHJldHVybiAocnZhbCA+PSB2Ym94LnIxICYmIHJ2YWwgPD0gdmJveC5yMiAmJlxuICAgICAgICAgICAgICAgIGd2YWwgPj0gdmJveC5nMSAmJiBndmFsIDw9IHZib3guZzIgJiZcbiAgICAgICAgICAgICAgICBidmFsID49IHZib3guYjEgJiYgYnZhbCA8PSB2Ym94LmIyKTtcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBDb2xvciBtYXBcblxuICAgIGZ1bmN0aW9uIENNYXAoKSB7XG4gICAgICAgIHRoaXMudmJveGVzID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKFxuICAgICAgICAgICAgICAgIGEudmJveC5jb3VudCgpICogYS52Ym94LnZvbHVtZSgpLFxuICAgICAgICAgICAgICAgIGIudmJveC5jb3VudCgpICogYi52Ym94LnZvbHVtZSgpXG4gICAgICAgICAgICApXG4gICAgICAgIH0pOztcbiAgICB9XG4gICAgQ01hcC5wcm90b3R5cGUgPSB7XG4gICAgICAgIHB1c2g6IGZ1bmN0aW9uKHZib3gpIHtcbiAgICAgICAgICAgIHRoaXMudmJveGVzLnB1c2goe1xuICAgICAgICAgICAgICAgIHZib3g6IHZib3gsXG4gICAgICAgICAgICAgICAgY29sb3I6IHZib3guYXZnKClcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBwYWxldHRlOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZib3hlcy5tYXAoZnVuY3Rpb24odmIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdmIuY29sb3JcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBzaXplOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZib3hlcy5zaXplKCk7XG4gICAgICAgIH0sXG4gICAgICAgIG1hcDogZnVuY3Rpb24oY29sb3IpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ZXMgPSB0aGlzLnZib3hlcztcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdmJveGVzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgaWYgKHZib3hlcy5wZWVrKGkpLnZib3guY29udGFpbnMoY29sb3IpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB2Ym94ZXMucGVlayhpKS5jb2xvcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5uZWFyZXN0KGNvbG9yKTtcbiAgICAgICAgfSxcbiAgICAgICAgbmVhcmVzdDogZnVuY3Rpb24oY29sb3IpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ZXMgPSB0aGlzLnZib3hlcyxcbiAgICAgICAgICAgICAgICBkMSwgZDIsIHBDb2xvcjtcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdmJveGVzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgZDIgPSBNYXRoLnNxcnQoXG4gICAgICAgICAgICAgICAgICAgIE1hdGgucG93KGNvbG9yWzBdIC0gdmJveGVzLnBlZWsoaSkuY29sb3JbMF0sIDIpICtcbiAgICAgICAgICAgICAgICAgICAgTWF0aC5wb3coY29sb3JbMV0gLSB2Ym94ZXMucGVlayhpKS5jb2xvclsxXSwgMikgK1xuICAgICAgICAgICAgICAgICAgICBNYXRoLnBvdyhjb2xvclsyXSAtIHZib3hlcy5wZWVrKGkpLmNvbG9yWzJdLCAyKVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgaWYgKGQyIDwgZDEgfHwgZDEgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgICAgICBkMSA9IGQyO1xuICAgICAgICAgICAgICAgICAgICBwQ29sb3IgPSB2Ym94ZXMucGVlayhpKS5jb2xvcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcENvbG9yO1xuICAgICAgICB9LFxuICAgICAgICBmb3JjZWJ3OiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIC8vIFhYWDogd29uJ3QgIHdvcmsgeWV0XG4gICAgICAgICAgICB2YXIgdmJveGVzID0gdGhpcy52Ym94ZXM7XG4gICAgICAgICAgICB2Ym94ZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihwdi5zdW0oYS5jb2xvciksIHB2LnN1bShiLmNvbG9yKSlcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICAvLyBmb3JjZSBkYXJrZXN0IGNvbG9yIHRvIGJsYWNrIGlmIGV2ZXJ5dGhpbmcgPCA1XG4gICAgICAgICAgICB2YXIgbG93ZXN0ID0gdmJveGVzWzBdLmNvbG9yO1xuICAgICAgICAgICAgaWYgKGxvd2VzdFswXSA8IDUgJiYgbG93ZXN0WzFdIDwgNSAmJiBsb3dlc3RbMl0gPCA1KVxuICAgICAgICAgICAgICAgIHZib3hlc1swXS5jb2xvciA9IFswLCAwLCAwXTtcblxuICAgICAgICAgICAgLy8gZm9yY2UgbGlnaHRlc3QgY29sb3IgdG8gd2hpdGUgaWYgZXZlcnl0aGluZyA+IDI1MVxuICAgICAgICAgICAgdmFyIGlkeCA9IHZib3hlcy5sZW5ndGggLSAxLFxuICAgICAgICAgICAgICAgIGhpZ2hlc3QgPSB2Ym94ZXNbaWR4XS5jb2xvcjtcbiAgICAgICAgICAgIGlmIChoaWdoZXN0WzBdID4gMjUxICYmIGhpZ2hlc3RbMV0gPiAyNTEgJiYgaGlnaGVzdFsyXSA+IDI1MSlcbiAgICAgICAgICAgICAgICB2Ym94ZXNbaWR4XS5jb2xvciA9IFsyNTUsIDI1NSwgMjU1XTtcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBoaXN0byAoMS1kIGFycmF5LCBnaXZpbmcgdGhlIG51bWJlciBvZiBwaXhlbHMgaW5cbiAgICAvLyBlYWNoIHF1YW50aXplZCByZWdpb24gb2YgY29sb3Igc3BhY2UpLCBvciBudWxsIG9uIGVycm9yXG5cbiAgICBmdW5jdGlvbiBnZXRIaXN0byhwaXhlbHMpIHtcbiAgICAgICAgdmFyIGhpc3Rvc2l6ZSA9IDEgPDwgKDMgKiBzaWdiaXRzKSxcbiAgICAgICAgICAgIGhpc3RvID0gbmV3IEFycmF5KGhpc3Rvc2l6ZSksXG4gICAgICAgICAgICBpbmRleCwgcnZhbCwgZ3ZhbCwgYnZhbDtcbiAgICAgICAgcGl4ZWxzLmZvckVhY2goZnVuY3Rpb24ocGl4ZWwpIHtcbiAgICAgICAgICAgIHJ2YWwgPSBwaXhlbFswXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBndmFsID0gcGl4ZWxbMV0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgYnZhbCA9IHBpeGVsWzJdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChydmFsLCBndmFsLCBidmFsKTtcbiAgICAgICAgICAgIGhpc3RvW2luZGV4XSA9IChoaXN0b1tpbmRleF0gfHwgMCkgKyAxO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIGhpc3RvO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZib3hGcm9tUGl4ZWxzKHBpeGVscywgaGlzdG8pIHtcbiAgICAgICAgdmFyIHJtaW4gPSAxMDAwMDAwLFxuICAgICAgICAgICAgcm1heCA9IDAsXG4gICAgICAgICAgICBnbWluID0gMTAwMDAwMCxcbiAgICAgICAgICAgIGdtYXggPSAwLFxuICAgICAgICAgICAgYm1pbiA9IDEwMDAwMDAsXG4gICAgICAgICAgICBibWF4ID0gMCxcbiAgICAgICAgICAgIHJ2YWwsIGd2YWwsIGJ2YWw7XG4gICAgICAgIC8vIGZpbmQgbWluL21heFxuICAgICAgICBwaXhlbHMuZm9yRWFjaChmdW5jdGlvbihwaXhlbCkge1xuICAgICAgICAgICAgcnZhbCA9IHBpeGVsWzBdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGd2YWwgPSBwaXhlbFsxXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBidmFsID0gcGl4ZWxbMl0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgaWYgKHJ2YWwgPCBybWluKSBybWluID0gcnZhbDtcbiAgICAgICAgICAgIGVsc2UgaWYgKHJ2YWwgPiBybWF4KSBybWF4ID0gcnZhbDtcbiAgICAgICAgICAgIGlmIChndmFsIDwgZ21pbikgZ21pbiA9IGd2YWw7XG4gICAgICAgICAgICBlbHNlIGlmIChndmFsID4gZ21heCkgZ21heCA9IGd2YWw7XG4gICAgICAgICAgICBpZiAoYnZhbCA8IGJtaW4pIGJtaW4gPSBidmFsO1xuICAgICAgICAgICAgZWxzZSBpZiAoYnZhbCA+IGJtYXgpIGJtYXggPSBidmFsO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIG5ldyBWQm94KHJtaW4sIHJtYXgsIGdtaW4sIGdtYXgsIGJtaW4sIGJtYXgsIGhpc3RvKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBtZWRpYW5DdXRBcHBseShoaXN0bywgdmJveCkge1xuICAgICAgICBpZiAoIXZib3guY291bnQoKSkgcmV0dXJuO1xuXG4gICAgICAgIHZhciBydyA9IHZib3gucjIgLSB2Ym94LnIxICsgMSxcbiAgICAgICAgICAgIGd3ID0gdmJveC5nMiAtIHZib3guZzEgKyAxLFxuICAgICAgICAgICAgYncgPSB2Ym94LmIyIC0gdmJveC5iMSArIDEsXG4gICAgICAgICAgICBtYXh3ID0gcHYubWF4KFtydywgZ3csIGJ3XSk7XG4gICAgICAgIC8vIG9ubHkgb25lIHBpeGVsLCBubyBzcGxpdFxuICAgICAgICBpZiAodmJveC5jb3VudCgpID09IDEpIHtcbiAgICAgICAgICAgIHJldHVybiBbdmJveC5jb3B5KCldXG4gICAgICAgIH1cbiAgICAgICAgLyogRmluZCB0aGUgcGFydGlhbCBzdW0gYXJyYXlzIGFsb25nIHRoZSBzZWxlY3RlZCBheGlzLiAqL1xuICAgICAgICB2YXIgdG90YWwgPSAwLFxuICAgICAgICAgICAgcGFydGlhbHN1bSA9IFtdLFxuICAgICAgICAgICAgbG9va2FoZWFkc3VtID0gW10sXG4gICAgICAgICAgICBpLCBqLCBrLCBzdW0sIGluZGV4O1xuICAgICAgICBpZiAobWF4dyA9PSBydykge1xuICAgICAgICAgICAgZm9yIChpID0gdmJveC5yMTsgaSA8PSB2Ym94LnIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICBzdW0gPSAwO1xuICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3guZzE7IGogPD0gdmJveC5nMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaSwgaiwgayk7XG4gICAgICAgICAgICAgICAgICAgICAgICBzdW0gKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgICAgICAgcGFydGlhbHN1bVtpXSA9IHRvdGFsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgaWYgKG1heHcgPT0gZ3cpIHtcbiAgICAgICAgICAgIGZvciAoaSA9IHZib3guZzE7IGkgPD0gdmJveC5nMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgc3VtID0gMDtcbiAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LnIxOyBqIDw9IHZib3gucjI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmIxOyBrIDw9IHZib3guYjI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGosIGksIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgc3VtICs9IChoaXN0b1tpbmRleF0gfHwgMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgICAgICAgIHBhcnRpYWxzdW1baV0gPSB0b3RhbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHsgLyogbWF4dyA9PSBidyAqL1xuICAgICAgICAgICAgZm9yIChpID0gdmJveC5iMTsgaSA8PSB2Ym94LmIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICBzdW0gPSAwO1xuICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3gucjE7IGogPD0gdmJveC5yMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guZzE7IGsgPD0gdmJveC5nMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaiwgaywgaSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBzdW0gKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgICAgICAgcGFydGlhbHN1bVtpXSA9IHRvdGFsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHBhcnRpYWxzdW0uZm9yRWFjaChmdW5jdGlvbihkLCBpKSB7XG4gICAgICAgICAgICBsb29rYWhlYWRzdW1baV0gPSB0b3RhbCAtIGRcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZnVuY3Rpb24gZG9DdXQoY29sb3IpIHtcbiAgICAgICAgICAgIHZhciBkaW0xID0gY29sb3IgKyAnMScsXG4gICAgICAgICAgICAgICAgZGltMiA9IGNvbG9yICsgJzInLFxuICAgICAgICAgICAgICAgIGxlZnQsIHJpZ2h0LCB2Ym94MSwgdmJveDIsIGQyLCBjb3VudDIgPSAwO1xuICAgICAgICAgICAgZm9yIChpID0gdmJveFtkaW0xXTsgaSA8PSB2Ym94W2RpbTJdOyBpKyspIHtcbiAgICAgICAgICAgICAgICBpZiAocGFydGlhbHN1bVtpXSA+IHRvdGFsIC8gMikge1xuICAgICAgICAgICAgICAgICAgICB2Ym94MSA9IHZib3guY29weSgpO1xuICAgICAgICAgICAgICAgICAgICB2Ym94MiA9IHZib3guY29weSgpO1xuICAgICAgICAgICAgICAgICAgICBsZWZ0ID0gaSAtIHZib3hbZGltMV07XG4gICAgICAgICAgICAgICAgICAgIHJpZ2h0ID0gdmJveFtkaW0yXSAtIGk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChsZWZ0IDw9IHJpZ2h0KVxuICAgICAgICAgICAgICAgICAgICAgICAgZDIgPSBNYXRoLm1pbih2Ym94W2RpbTJdIC0gMSwgfn4gKGkgKyByaWdodCAvIDIpKTtcbiAgICAgICAgICAgICAgICAgICAgZWxzZSBkMiA9IE1hdGgubWF4KHZib3hbZGltMV0sIH5+IChpIC0gMSAtIGxlZnQgLyAyKSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGF2b2lkIDAtY291bnQgYm94ZXNcbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCFwYXJ0aWFsc3VtW2QyXSkgZDIrKztcbiAgICAgICAgICAgICAgICAgICAgY291bnQyID0gbG9va2FoZWFkc3VtW2QyXTtcbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCFjb3VudDIgJiYgcGFydGlhbHN1bVtkMiAtIDFdKSBjb3VudDIgPSBsb29rYWhlYWRzdW1bLS1kMl07XG4gICAgICAgICAgICAgICAgICAgIC8vIHNldCBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgICAgIHZib3gxW2RpbTJdID0gZDI7XG4gICAgICAgICAgICAgICAgICAgIHZib3gyW2RpbTFdID0gdmJveDFbZGltMl0gKyAxO1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZygndmJveCBjb3VudHM6JywgdmJveC5jb3VudCgpLCB2Ym94MS5jb3VudCgpLCB2Ym94Mi5jb3VudCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFt2Ym94MSwgdmJveDJdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICB9XG4gICAgICAgIC8vIGRldGVybWluZSB0aGUgY3V0IHBsYW5lc1xuICAgICAgICByZXR1cm4gbWF4dyA9PSBydyA/IGRvQ3V0KCdyJykgOlxuICAgICAgICAgICAgbWF4dyA9PSBndyA/IGRvQ3V0KCdnJykgOlxuICAgICAgICAgICAgZG9DdXQoJ2InKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBxdWFudGl6ZShwaXhlbHMsIG1heGNvbG9ycykge1xuICAgICAgICAvLyBzaG9ydC1jaXJjdWl0XG4gICAgICAgIGlmICghcGl4ZWxzLmxlbmd0aCB8fCBtYXhjb2xvcnMgPCAyIHx8IG1heGNvbG9ycyA+IDI1Nikge1xuICAgICAgICAgICAgLy8gY29uc29sZS5sb2coJ3dyb25nIG51bWJlciBvZiBtYXhjb2xvcnMnKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFhYWDogY2hlY2sgY29sb3IgY29udGVudCBhbmQgY29udmVydCB0byBncmF5c2NhbGUgaWYgaW5zdWZmaWNpZW50XG5cbiAgICAgICAgdmFyIGhpc3RvID0gZ2V0SGlzdG8ocGl4ZWxzKSxcbiAgICAgICAgICAgIGhpc3Rvc2l6ZSA9IDEgPDwgKDMgKiBzaWdiaXRzKTtcblxuICAgICAgICAvLyBjaGVjayB0aGF0IHdlIGFyZW4ndCBiZWxvdyBtYXhjb2xvcnMgYWxyZWFkeVxuICAgICAgICB2YXIgbkNvbG9ycyA9IDA7XG4gICAgICAgIGhpc3RvLmZvckVhY2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBuQ29sb3JzKytcbiAgICAgICAgfSk7XG4gICAgICAgIGlmIChuQ29sb3JzIDw9IG1heGNvbG9ycykge1xuICAgICAgICAgICAgLy8gWFhYOiBnZW5lcmF0ZSB0aGUgbmV3IGNvbG9ycyBmcm9tIHRoZSBoaXN0byBhbmQgcmV0dXJuXG4gICAgICAgIH1cblxuICAgICAgICAvLyBnZXQgdGhlIGJlZ2lubmluZyB2Ym94IGZyb20gdGhlIGNvbG9yc1xuICAgICAgICB2YXIgdmJveCA9IHZib3hGcm9tUGl4ZWxzKHBpeGVscywgaGlzdG8pLFxuICAgICAgICAgICAgcHEgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKGEuY291bnQoKSwgYi5jb3VudCgpKVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIHBxLnB1c2godmJveCk7XG5cbiAgICAgICAgLy8gaW5uZXIgZnVuY3Rpb24gdG8gZG8gdGhlIGl0ZXJhdGlvblxuXG4gICAgICAgIGZ1bmN0aW9uIGl0ZXIobGgsIHRhcmdldCkge1xuICAgICAgICAgICAgdmFyIG5jb2xvcnMgPSAxLFxuICAgICAgICAgICAgICAgIG5pdGVycyA9IDAsXG4gICAgICAgICAgICAgICAgdmJveDtcbiAgICAgICAgICAgIHdoaWxlIChuaXRlcnMgPCBtYXhJdGVyYXRpb25zKSB7XG4gICAgICAgICAgICAgICAgdmJveCA9IGxoLnBvcCgpO1xuICAgICAgICAgICAgICAgIGlmICghdmJveC5jb3VudCgpKSB7IC8qIGp1c3QgcHV0IGl0IGJhY2sgKi9cbiAgICAgICAgICAgICAgICAgICAgbGgucHVzaCh2Ym94KTtcbiAgICAgICAgICAgICAgICAgICAgbml0ZXJzKys7XG4gICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBkbyB0aGUgY3V0XG4gICAgICAgICAgICAgICAgdmFyIHZib3hlcyA9IG1lZGlhbkN1dEFwcGx5KGhpc3RvLCB2Ym94KSxcbiAgICAgICAgICAgICAgICAgICAgdmJveDEgPSB2Ym94ZXNbMF0sXG4gICAgICAgICAgICAgICAgICAgIHZib3gyID0gdmJveGVzWzFdO1xuXG4gICAgICAgICAgICAgICAgaWYgKCF2Ym94MSkge1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZyhcInZib3gxIG5vdCBkZWZpbmVkOyBzaG91bGRuJ3QgaGFwcGVuIVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBsaC5wdXNoKHZib3gxKTtcbiAgICAgICAgICAgICAgICBpZiAodmJveDIpIHsgLyogdmJveDIgY2FuIGJlIG51bGwgKi9cbiAgICAgICAgICAgICAgICAgICAgbGgucHVzaCh2Ym94Mik7XG4gICAgICAgICAgICAgICAgICAgIG5jb2xvcnMrKztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKG5jb2xvcnMgPj0gdGFyZ2V0KSByZXR1cm47XG4gICAgICAgICAgICAgICAgaWYgKG5pdGVycysrID4gbWF4SXRlcmF0aW9ucykge1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZyhcImluZmluaXRlIGxvb3A7IHBlcmhhcHMgdG9vIGZldyBwaXhlbHMhXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gZmlyc3Qgc2V0IG9mIGNvbG9ycywgc29ydGVkIGJ5IHBvcHVsYXRpb25cbiAgICAgICAgaXRlcihwcSwgZnJhY3RCeVBvcHVsYXRpb25zICogbWF4Y29sb3JzKTtcbiAgICAgICAgLy8gY29uc29sZS5sb2cocHEuc2l6ZSgpLCBwcS5kZWJ1ZygpLmxlbmd0aCwgcHEuZGVidWcoKS5zbGljZSgpKTtcblxuICAgICAgICAvLyBSZS1zb3J0IGJ5IHRoZSBwcm9kdWN0IG9mIHBpeGVsIG9jY3VwYW5jeSB0aW1lcyB0aGUgc2l6ZSBpbiBjb2xvciBzcGFjZS5cbiAgICAgICAgdmFyIHBxMiA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihhLmNvdW50KCkgKiBhLnZvbHVtZSgpLCBiLmNvdW50KCkgKiBiLnZvbHVtZSgpKVxuICAgICAgICB9KTtcbiAgICAgICAgd2hpbGUgKHBxLnNpemUoKSkge1xuICAgICAgICAgICAgcHEyLnB1c2gocHEucG9wKCkpO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gbmV4dCBzZXQgLSBnZW5lcmF0ZSB0aGUgbWVkaWFuIGN1dHMgdXNpbmcgdGhlIChucGl4ICogdm9sKSBzb3J0aW5nLlxuICAgICAgICBpdGVyKHBxMiwgbWF4Y29sb3JzIC0gcHEyLnNpemUoKSk7XG5cbiAgICAgICAgLy8gY2FsY3VsYXRlIHRoZSBhY3R1YWwgY29sb3JzXG4gICAgICAgIHZhciBjbWFwID0gbmV3IENNYXAoKTtcbiAgICAgICAgd2hpbGUgKHBxMi5zaXplKCkpIHtcbiAgICAgICAgICAgIGNtYXAucHVzaChwcTIucG9wKCkpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGNtYXA7XG4gICAgfVxuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcXVhbnRpemU6IHF1YW50aXplXG4gICAgfVxufSkoKTtcblxubW9kdWxlLmV4cG9ydHMgPSBNTUNRLnF1YW50aXplXG4iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxuJ3VzZSBzdHJpY3QnO1xuXG4vLyBJZiBvYmouaGFzT3duUHJvcGVydHkgaGFzIGJlZW4gb3ZlcnJpZGRlbiwgdGhlbiBjYWxsaW5nXG4vLyBvYmouaGFzT3duUHJvcGVydHkocHJvcCkgd2lsbCBicmVhay5cbi8vIFNlZTogaHR0cHM6Ly9naXRodWIuY29tL2pveWVudC9ub2RlL2lzc3Vlcy8xNzA3XG5mdW5jdGlvbiBoYXNPd25Qcm9wZXJ0eShvYmosIHByb3ApIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uKHFzLCBzZXAsIGVxLCBvcHRpb25zKSB7XG4gIHNlcCA9IHNlcCB8fCAnJic7XG4gIGVxID0gZXEgfHwgJz0nO1xuICB2YXIgb2JqID0ge307XG5cbiAgaWYgKHR5cGVvZiBxcyAhPT0gJ3N0cmluZycgfHwgcXMubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIG9iajtcbiAgfVxuXG4gIHZhciByZWdleHAgPSAvXFwrL2c7XG4gIHFzID0gcXMuc3BsaXQoc2VwKTtcblxuICB2YXIgbWF4S2V5cyA9IDEwMDA7XG4gIGlmIChvcHRpb25zICYmIHR5cGVvZiBvcHRpb25zLm1heEtleXMgPT09ICdudW1iZXInKSB7XG4gICAgbWF4S2V5cyA9IG9wdGlvbnMubWF4S2V5cztcbiAgfVxuXG4gIHZhciBsZW4gPSBxcy5sZW5ndGg7XG4gIC8vIG1heEtleXMgPD0gMCBtZWFucyB0aGF0IHdlIHNob3VsZCBub3QgbGltaXQga2V5cyBjb3VudFxuICBpZiAobWF4S2V5cyA+IDAgJiYgbGVuID4gbWF4S2V5cykge1xuICAgIGxlbiA9IG1heEtleXM7XG4gIH1cblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbjsgKytpKSB7XG4gICAgdmFyIHggPSBxc1tpXS5yZXBsYWNlKHJlZ2V4cCwgJyUyMCcpLFxuICAgICAgICBpZHggPSB4LmluZGV4T2YoZXEpLFxuICAgICAgICBrc3RyLCB2c3RyLCBrLCB2O1xuXG4gICAgaWYgKGlkeCA+PSAwKSB7XG4gICAgICBrc3RyID0geC5zdWJzdHIoMCwgaWR4KTtcbiAgICAgIHZzdHIgPSB4LnN1YnN0cihpZHggKyAxKTtcbiAgICB9IGVsc2Uge1xuICAgICAga3N0ciA9IHg7XG4gICAgICB2c3RyID0gJyc7XG4gICAgfVxuXG4gICAgayA9IGRlY29kZVVSSUNvbXBvbmVudChrc3RyKTtcbiAgICB2ID0gZGVjb2RlVVJJQ29tcG9uZW50KHZzdHIpO1xuXG4gICAgaWYgKCFoYXNPd25Qcm9wZXJ0eShvYmosIGspKSB7XG4gICAgICBvYmpba10gPSB2O1xuICAgIH0gZWxzZSBpZiAoaXNBcnJheShvYmpba10pKSB7XG4gICAgICBvYmpba10ucHVzaCh2KTtcbiAgICB9IGVsc2Uge1xuICAgICAgb2JqW2tdID0gW29ialtrXSwgdl07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG9iajtcbn07XG5cbnZhciBpc0FycmF5ID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoeHMpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh4cykgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59O1xuIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbid1c2Ugc3RyaWN0JztcblxudmFyIHN0cmluZ2lmeVByaW1pdGl2ZSA9IGZ1bmN0aW9uKHYpIHtcbiAgc3dpdGNoICh0eXBlb2Ygdikge1xuICAgIGNhc2UgJ3N0cmluZyc6XG4gICAgICByZXR1cm4gdjtcblxuICAgIGNhc2UgJ2Jvb2xlYW4nOlxuICAgICAgcmV0dXJuIHYgPyAndHJ1ZScgOiAnZmFsc2UnO1xuXG4gICAgY2FzZSAnbnVtYmVyJzpcbiAgICAgIHJldHVybiBpc0Zpbml0ZSh2KSA/IHYgOiAnJztcblxuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gJyc7XG4gIH1cbn07XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ob2JqLCBzZXAsIGVxLCBuYW1lKSB7XG4gIHNlcCA9IHNlcCB8fCAnJic7XG4gIGVxID0gZXEgfHwgJz0nO1xuICBpZiAob2JqID09PSBudWxsKSB7XG4gICAgb2JqID0gdW5kZWZpbmVkO1xuICB9XG5cbiAgaWYgKHR5cGVvZiBvYmogPT09ICdvYmplY3QnKSB7XG4gICAgcmV0dXJuIG1hcChvYmplY3RLZXlzKG9iaiksIGZ1bmN0aW9uKGspIHtcbiAgICAgIHZhciBrcyA9IGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUoaykpICsgZXE7XG4gICAgICBpZiAoaXNBcnJheShvYmpba10pKSB7XG4gICAgICAgIHJldHVybiBtYXAob2JqW2tdLCBmdW5jdGlvbih2KSB7XG4gICAgICAgICAgcmV0dXJuIGtzICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZSh2KSk7XG4gICAgICAgIH0pLmpvaW4oc2VwKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiBrcyArIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUob2JqW2tdKSk7XG4gICAgICB9XG4gICAgfSkuam9pbihzZXApO1xuXG4gIH1cblxuICBpZiAoIW5hbWUpIHJldHVybiAnJztcbiAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUobmFtZSkpICsgZXEgK1xuICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShvYmopKTtcbn07XG5cbnZhciBpc0FycmF5ID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoeHMpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh4cykgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59O1xuXG5mdW5jdGlvbiBtYXAgKHhzLCBmKSB7XG4gIGlmICh4cy5tYXApIHJldHVybiB4cy5tYXAoZik7XG4gIHZhciByZXMgPSBbXTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCB4cy5sZW5ndGg7IGkrKykge1xuICAgIHJlcy5wdXNoKGYoeHNbaV0sIGkpKTtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxuXG52YXIgb2JqZWN0S2V5cyA9IE9iamVjdC5rZXlzIHx8IGZ1bmN0aW9uIChvYmopIHtcbiAgdmFyIHJlcyA9IFtdO1xuICBmb3IgKHZhciBrZXkgaW4gb2JqKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSkpIHJlcy5wdXNoKGtleSk7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbmV4cG9ydHMuZGVjb2RlID0gZXhwb3J0cy5wYXJzZSA9IHJlcXVpcmUoJy4vZGVjb2RlJyk7XG5leHBvcnRzLmVuY29kZSA9IGV4cG9ydHMuc3RyaW5naWZ5ID0gcmVxdWlyZSgnLi9lbmNvZGUnKTtcbiIsIlZpYnJhbnQgPSByZXF1aXJlKCcuL3ZpYnJhbnQnKVxuVmlicmFudC5EZWZhdWx0T3B0cy5JbWFnZSA9IHJlcXVpcmUoJy4vaW1hZ2UvYnJvd3NlcicpXG5cbm1vZHVsZS5leHBvcnRzID0gVmlicmFudFxuIiwid2luZG93LlZpYnJhbnQgPSBWaWJyYW50ID0gcmVxdWlyZSgnLi9icm93c2VyJylcbiIsIm1vZHVsZS5leHBvcnRzID0gKHIsIGcsIGIsIGEpIC0+XG4gIGEgPj0gMTI1IGFuZCBub3QgKHIgPiAyNTAgYW5kIGcgPiAyNTAgYW5kIGIgPiAyNTApXG4iLCJtb2R1bGUuZXhwb3J0cy5EZWZhdWx0ID0gcmVxdWlyZSgnLi9kZWZhdWx0JylcbiIsIlN3YXRjaCA9IHJlcXVpcmUoJy4uL3N3YXRjaCcpXG51dGlsID0gcmVxdWlyZSgnLi4vdXRpbCcpXG5HZW5lcmF0b3IgPSByZXF1aXJlKCcuL2luZGV4JylcblxuRGVmYXVsdE9wdHMgPVxuICB0YXJnZXREYXJrTHVtYTogMC4yNlxuICBtYXhEYXJrTHVtYTogMC40NVxuICBtaW5MaWdodEx1bWE6IDAuNTVcbiAgdGFyZ2V0TGlnaHRMdW1hOiAwLjc0XG4gIG1pbk5vcm1hbEx1bWE6IDAuM1xuICB0YXJnZXROb3JtYWxMdW1hOiAwLjVcbiAgbWF4Tm9ybWFsTHVtYTogMC43XG4gIHRhcmdldE11dGVzU2F0dXJhdGlvbjogMC4zXG4gIG1heE11dGVzU2F0dXJhdGlvbjogMC40XG4gIHRhcmdldFZpYnJhbnRTYXR1cmF0aW9uOiAxLjBcbiAgbWluVmlicmFudFNhdHVyYXRpb246IDAuMzVcbiAgd2VpZ2h0U2F0dXJhdGlvbjogM1xuICB3ZWlnaHRMdW1hOiA2XG4gIHdlaWdodFBvcHVsYXRpb246IDFcblxubW9kdWxlLmV4cG9ydHMgPVxuY2xhc3MgRGVmYXVsdEdlbmVyYXRvciBleHRlbmRzIEdlbmVyYXRvclxuICBjb25zdHJ1Y3RvcjogKG9wdHMpIC0+XG4gICAgQG9wdHMgPSB1dGlsLmRlZmF1bHRzKG9wdHMsIERlZmF1bHRPcHRzKVxuICAgIEBWaWJyYW50U3dhdGNoID0gbnVsbFxuICAgIEBMaWdodFZpYnJhbnRTd2F0Y2ggPSBudWxsXG4gICAgQERhcmtWaWJyYW50U3dhdGNoID0gbnVsbFxuICAgIEBNdXRlZFN3YXRjaCA9IG51bGxcbiAgICBATGlnaHRNdXRlZFN3YXRjaCA9IG51bGxcbiAgICBARGFya011dGVkU3dhdGNoID0gbnVsbFxuXG4gIGdlbmVyYXRlOiAoQHN3YXRjaGVzKSAtPlxuICAgIEBtYXhQb3B1bGF0aW9uID0gQGZpbmRNYXhQb3B1bGF0aW9uKClcblxuICAgIEBnZW5lcmF0ZVZhcmF0aW9uQ29sb3JzKClcbiAgICBAZ2VuZXJhdGVFbXB0eVN3YXRjaGVzKClcblxuICBnZXRWaWJyYW50U3dhdGNoOiAtPlxuICAgIEBWaWJyYW50U3dhdGNoXG5cbiAgZ2V0TGlnaHRWaWJyYW50U3dhdGNoOiAtPlxuICAgIEBMaWdodFZpYnJhbnRTd2F0Y2hcblxuICBnZXREYXJrVmlicmFudFN3YXRjaDogLT5cbiAgICBARGFya1ZpYnJhbnRTd2F0Y2hcblxuICBnZXRNdXRlZFN3YXRjaDogLT5cbiAgICBATXV0ZWRTd2F0Y2hcblxuICBnZXRMaWdodE11dGVkU3dhdGNoOiAtPlxuICAgIEBMaWdodE11dGVkU3dhdGNoXG5cbiAgZ2V0RGFya011dGVkU3dhdGNoOiAtPlxuICAgIEBEYXJrTXV0ZWRTd2F0Y2hcblxuICBnZW5lcmF0ZVZhcmF0aW9uQ29sb3JzOiAtPlxuICAgIEBWaWJyYW50U3dhdGNoID0gQGZpbmRDb2xvclZhcmlhdGlvbihAb3B0cy50YXJnZXROb3JtYWxMdW1hLCBAb3B0cy5taW5Ob3JtYWxMdW1hLCBAb3B0cy5tYXhOb3JtYWxMdW1hLFxuICAgICAgQG9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIEBvcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcblxuICAgIEBMaWdodFZpYnJhbnRTd2F0Y2ggPSBAZmluZENvbG9yVmFyaWF0aW9uKEBvcHRzLnRhcmdldExpZ2h0THVtYSwgQG9wdHMubWluTGlnaHRMdW1hLCAxLFxuICAgICAgQG9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIEBvcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcblxuICAgIEBEYXJrVmlicmFudFN3YXRjaCA9IEBmaW5kQ29sb3JWYXJpYXRpb24oQG9wdHMudGFyZ2V0RGFya0x1bWEsIDAsIEBvcHRzLm1heERhcmtMdW1hLFxuICAgICAgQG9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIEBvcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcblxuICAgIEBNdXRlZFN3YXRjaCA9IEBmaW5kQ29sb3JWYXJpYXRpb24oQG9wdHMudGFyZ2V0Tm9ybWFsTHVtYSwgQG9wdHMubWluTm9ybWFsTHVtYSwgQG9wdHMubWF4Tm9ybWFsTHVtYSxcbiAgICAgIEBvcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgQG9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcblxuICAgIEBMaWdodE11dGVkU3dhdGNoID0gQGZpbmRDb2xvclZhcmlhdGlvbihAb3B0cy50YXJnZXRMaWdodEx1bWEsIEBvcHRzLm1pbkxpZ2h0THVtYSwgMSxcbiAgICAgIEBvcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgQG9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcblxuICAgIEBEYXJrTXV0ZWRTd2F0Y2ggPSBAZmluZENvbG9yVmFyaWF0aW9uKEBvcHRzLnRhcmdldERhcmtMdW1hLCAwLCBAb3B0cy5tYXhEYXJrTHVtYSxcbiAgICAgIEBvcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgQG9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcblxuICBnZW5lcmF0ZUVtcHR5U3dhdGNoZXM6IC0+XG4gICAgaWYgQFZpYnJhbnRTd2F0Y2ggaXMgbnVsbFxuICAgICAgIyBJZiB3ZSBkbyBub3QgaGF2ZSBhIHZpYnJhbnQgY29sb3IuLi5cbiAgICAgIGlmIEBEYXJrVmlicmFudFN3YXRjaCBpc250IG51bGxcbiAgICAgICAgIyAuLi5idXQgd2UgZG8gaGF2ZSBhIGRhcmsgdmlicmFudCwgZ2VuZXJhdGUgdGhlIHZhbHVlIGJ5IG1vZGlmeWluZyB0aGUgbHVtYVxuICAgICAgICBoc2wgPSBARGFya1ZpYnJhbnRTd2F0Y2guZ2V0SHNsKClcbiAgICAgICAgaHNsWzJdID0gQG9wdHMudGFyZ2V0Tm9ybWFsTHVtYVxuICAgICAgICBAVmlicmFudFN3YXRjaCA9IG5ldyBTd2F0Y2ggdXRpbC5oc2xUb1JnYihoc2xbMF0sIGhzbFsxXSwgaHNsWzJdKSwgMFxuXG4gICAgaWYgQERhcmtWaWJyYW50U3dhdGNoIGlzIG51bGxcbiAgICAgICMgSWYgd2UgZG8gbm90IGhhdmUgYSB2aWJyYW50IGNvbG9yLi4uXG4gICAgICBpZiBAVmlicmFudFN3YXRjaCBpc250IG51bGxcbiAgICAgICAgIyAuLi5idXQgd2UgZG8gaGF2ZSBhIGRhcmsgdmlicmFudCwgZ2VuZXJhdGUgdGhlIHZhbHVlIGJ5IG1vZGlmeWluZyB0aGUgbHVtYVxuICAgICAgICBoc2wgPSBAVmlicmFudFN3YXRjaC5nZXRIc2woKVxuICAgICAgICBoc2xbMl0gPSBAb3B0cy50YXJnZXREYXJrTHVtYVxuICAgICAgICBARGFya1ZpYnJhbnRTd2F0Y2ggPSBuZXcgU3dhdGNoIHV0aWwuaHNsVG9SZ2IoaHNsWzBdLCBoc2xbMV0sIGhzbFsyXSksIDBcblxuICBmaW5kTWF4UG9wdWxhdGlvbjogLT5cbiAgICBwb3B1bGF0aW9uID0gMFxuICAgIHBvcHVsYXRpb24gPSBNYXRoLm1heChwb3B1bGF0aW9uLCBzd2F0Y2guZ2V0UG9wdWxhdGlvbigpKSBmb3Igc3dhdGNoIGluIEBzd2F0Y2hlc1xuICAgIHBvcHVsYXRpb25cblxuICBmaW5kQ29sb3JWYXJpYXRpb246ICh0YXJnZXRMdW1hLCBtaW5MdW1hLCBtYXhMdW1hLCB0YXJnZXRTYXR1cmF0aW9uLCBtaW5TYXR1cmF0aW9uLCBtYXhTYXR1cmF0aW9uKSAtPlxuICAgIG1heCA9IG51bGxcbiAgICBtYXhWYWx1ZSA9IDBcblxuICAgIGZvciBzd2F0Y2ggaW4gQHN3YXRjaGVzXG4gICAgICBzYXQgPSBzd2F0Y2guZ2V0SHNsKClbMV07XG4gICAgICBsdW1hID0gc3dhdGNoLmdldEhzbCgpWzJdXG5cbiAgICAgIGlmIHNhdCA+PSBtaW5TYXR1cmF0aW9uIGFuZCBzYXQgPD0gbWF4U2F0dXJhdGlvbiBhbmRcbiAgICAgICAgbHVtYSA+PSBtaW5MdW1hIGFuZCBsdW1hIDw9IG1heEx1bWEgYW5kXG4gICAgICAgIG5vdCBAaXNBbHJlYWR5U2VsZWN0ZWQoc3dhdGNoKVxuICAgICAgICAgIHZhbHVlID0gQGNyZWF0ZUNvbXBhcmlzb25WYWx1ZSBzYXQsIHRhcmdldFNhdHVyYXRpb24sIGx1bWEsIHRhcmdldEx1bWEsXG4gICAgICAgICAgICBzd2F0Y2guZ2V0UG9wdWxhdGlvbigpLCBAbWF4UG9wdWxhdGlvblxuICAgICAgICAgIGlmIG1heCBpcyBudWxsIG9yIHZhbHVlID4gbWF4VmFsdWVcbiAgICAgICAgICAgIG1heCA9IHN3YXRjaFxuICAgICAgICAgICAgbWF4VmFsdWUgPSB2YWx1ZVxuXG4gICAgbWF4XG5cbiAgY3JlYXRlQ29tcGFyaXNvblZhbHVlOiAoc2F0dXJhdGlvbiwgdGFyZ2V0U2F0dXJhdGlvbixcbiAgICAgIGx1bWEsIHRhcmdldEx1bWEsIHBvcHVsYXRpb24sIG1heFBvcHVsYXRpb24pIC0+XG4gICAgQHdlaWdodGVkTWVhbihcbiAgICAgIEBpbnZlcnREaWZmKHNhdHVyYXRpb24sIHRhcmdldFNhdHVyYXRpb24pLCBAb3B0cy53ZWlnaHRTYXR1cmF0aW9uLFxuICAgICAgQGludmVydERpZmYobHVtYSwgdGFyZ2V0THVtYSksIEBvcHRzLndlaWdodEx1bWEsXG4gICAgICBwb3B1bGF0aW9uIC8gbWF4UG9wdWxhdGlvbiwgQG9wdHMud2VpZ2h0UG9wdWxhdGlvblxuICAgIClcblxuICBpbnZlcnREaWZmOiAodmFsdWUsIHRhcmdldFZhbHVlKSAtPlxuICAgIDEgLSBNYXRoLmFicyB2YWx1ZSAtIHRhcmdldFZhbHVlXG5cbiAgd2VpZ2h0ZWRNZWFuOiAodmFsdWVzLi4uKSAtPlxuICAgIHN1bSA9IDBcbiAgICBzdW1XZWlnaHQgPSAwXG4gICAgaSA9IDBcbiAgICB3aGlsZSBpIDwgdmFsdWVzLmxlbmd0aFxuICAgICAgdmFsdWUgPSB2YWx1ZXNbaV1cbiAgICAgIHdlaWdodCA9IHZhbHVlc1tpICsgMV1cbiAgICAgIHN1bSArPSB2YWx1ZSAqIHdlaWdodFxuICAgICAgc3VtV2VpZ2h0ICs9IHdlaWdodFxuICAgICAgaSArPSAyXG4gICAgc3VtIC8gc3VtV2VpZ2h0XG5cbiAgaXNBbHJlYWR5U2VsZWN0ZWQ6IChzd2F0Y2gpIC0+XG4gICAgQFZpYnJhbnRTd2F0Y2ggaXMgc3dhdGNoIG9yIEBEYXJrVmlicmFudFN3YXRjaCBpcyBzd2F0Y2ggb3JcbiAgICAgIEBMaWdodFZpYnJhbnRTd2F0Y2ggaXMgc3dhdGNoIG9yIEBNdXRlZFN3YXRjaCBpcyBzd2F0Y2ggb3JcbiAgICAgIEBEYXJrTXV0ZWRTd2F0Y2ggaXMgc3dhdGNoIG9yIEBMaWdodE11dGVkU3dhdGNoIGlzIHN3YXRjaFxuIiwibW9kdWxlLmV4cG9ydHMgPVxuY2xhc3MgR2VuZXJhdG9yXG4gIGdlbmVyYXRlOiAoc3dhdGNoZXMpIC0+XG5cbiAgZ2V0VmlicmFudFN3YXRjaDogLT5cblxuICBnZXRMaWdodFZpYnJhbnRTd2F0Y2g6IC0+XG5cbiAgZ2V0RGFya1ZpYnJhbnRTd2F0Y2g6IC0+XG5cbiAgZ2V0TXV0ZWRTd2F0Y2g6IC0+XG5cbiAgZ2V0TGlnaHRNdXRlZFN3YXRjaDogLT5cblxuICBnZXREYXJrTXV0ZWRTd2F0Y2g6IC0+XG5cbm1vZHVsZS5leHBvcnRzLkRlZmF1bHQgPSByZXF1aXJlKCcuL2RlZmF1bHQnKVxuIiwiSW1hZ2UgPSByZXF1aXJlKCcuL2luZGV4JylcblVybCA9IHJlcXVpcmUoJ3VybCcpXG5cbmlzUmVsYXRpdmVVcmwgPSAodXJsKSAtPlxuICB1ID0gVXJsLnBhcnNlKHVybClcblxuICB1LnByb3RvY29sID09IG51bGwgJiYgdS5ob3N0ID09IG51bGwgJiYgdS5wb3J0ID09IG51bGxcblxuaXNTYW1lT3JpZ2luID0gKGEsIGIpIC0+XG4gIHVhID0gVXJsLnBhcnNlKGEpXG4gIHViID0gVXJsLnBhcnNlKGIpXG5cbiAgIyBodHRwczovL2RldmVsb3Blci5tb3ppbGxhLm9yZy9lbi1VUy9kb2NzL1dlYi9TZWN1cml0eS9TYW1lLW9yaWdpbl9wb2xpY3lcbiAgdWEucHJvdG9jb2wgPT0gdWIucHJvdG9jb2wgJiYgdWEuaG9zdG5hbWUgPT0gdWIuaG9zdG5hbWUgJiYgdWEucG9ydCA9PSB1Yi5wb3J0XG5cbm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIEJyb3dzZXJJbWFnZSBleHRlbmRzIEltYWdlXG5cbiAgY29uc3RydWN0b3I6IChwYXRoLCBjYikgLT5cbiAgICBpZiB0eXBlb2YgcGF0aCA9PSAnb2JqZWN0JyBhbmQgcGF0aCBpbnN0YW5jZW9mIEhUTUxJbWFnZUVsZW1lbnRcbiAgICAgIEBpbWcgPSBwYXRoXG4gICAgICBwYXRoID0gQGltZy5zcmNcbiAgICBlbHNlXG4gICAgICBAaW1nID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaW1nJylcbiAgICAgIEBpbWcuc3JjID0gcGF0aFxuXG4gICAgaWYgbm90IGlzUmVsYXRpdmVVcmwocGF0aCkgJiYgbm90IGlzU2FtZU9yaWdpbih3aW5kb3cubG9jYXRpb24uaHJlZiwgcGF0aClcbiAgICAgIEBpbWcuY3Jvc3NPcmlnaW4gPSAnYW5vbnltb3VzJ1xuXG4gICAgQGltZy5vbmxvYWQgPSA9PlxuICAgICAgQF9pbml0Q2FudmFzKClcbiAgICAgIGNiPyhudWxsLCBAKVxuXG4gICAgIyBBbHJlYXlkIGxvYWRlZFxuICAgIGlmIEBpbWcuY29tcGxldGVcbiAgICAgIEBpbWcub25sb2FkKClcblxuICAgIEBpbWcub25lcnJvciA9IChlKSA9PlxuICAgICAgZXJyID0gbmV3IEVycm9yKFwiRmFpbCB0byBsb2FkIGltYWdlOiBcIiArIHBhdGgpO1xuICAgICAgZXJyLnJhdyA9IGU7XG4gICAgICBjYj8oZXJyKVxuXG5cbiAgX2luaXRDYW52YXM6IC0+XG4gICAgQGNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2NhbnZhcycpXG4gICAgQGNvbnRleHQgPSBAY2FudmFzLmdldENvbnRleHQoJzJkJylcbiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkIEBjYW52YXNcbiAgICBAd2lkdGggPSBAY2FudmFzLndpZHRoID0gQGltZy53aWR0aFxuICAgIEBoZWlnaHQgPSBAY2FudmFzLmhlaWdodCA9IEBpbWcuaGVpZ2h0XG4gICAgQGNvbnRleHQuZHJhd0ltYWdlIEBpbWcsIDAsIDAsIEB3aWR0aCwgQGhlaWdodFxuXG4gIGNsZWFyOiAtPlxuICAgIEBjb250ZXh0LmNsZWFyUmVjdCAwLCAwLCBAd2lkdGgsIEBoZWlnaHRcblxuICBnZXRXaWR0aDogLT5cbiAgICBAd2lkdGhcblxuICBnZXRIZWlnaHQ6IC0+XG4gICAgQGhlaWdodFxuXG4gIHJlc2l6ZTogKHcsIGgsIHIpIC0+XG4gICAgQHdpZHRoID0gQGNhbnZhcy53aWR0aCA9IHdcbiAgICBAaGVpZ2h0ID0gQGNhbnZhcy5oZWlnaHQgPSBoXG4gICAgQGNvbnRleHQuc2NhbGUociwgcilcbiAgICBAY29udGV4dC5kcmF3SW1hZ2UgQGltZywgMCwgMFxuXG4gIHVwZGF0ZTogKGltYWdlRGF0YSkgLT5cbiAgICBAY29udGV4dC5wdXRJbWFnZURhdGEgaW1hZ2VEYXRhLCAwLCAwXG5cbiAgZ2V0UGl4ZWxDb3VudDogLT5cbiAgICBAd2lkdGggKiBAaGVpZ2h0XG5cbiAgZ2V0SW1hZ2VEYXRhOiAtPlxuICAgIEBjb250ZXh0LmdldEltYWdlRGF0YSAwLCAwLCBAd2lkdGgsIEBoZWlnaHRcblxuICByZW1vdmVDYW52YXM6IC0+XG4gICAgQGNhbnZhcy5wYXJlbnROb2RlLnJlbW92ZUNoaWxkIEBjYW52YXNcbiIsIm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIEltYWdlXG4gIGNsZWFyOiAtPlxuXG4gIHVwZGF0ZTogKGltYWdlRGF0YSkgLT5cblxuICBnZXRXaWR0aDogLT5cblxuICBnZXRIZWlnaHQ6IC0+XG5cbiAgc2NhbGVEb3duOiAob3B0cykgLT5cbiAgICB3aWR0aCA9IEBnZXRXaWR0aCgpXG4gICAgaGVpZ2h0ID0gQGdldEhlaWdodCgpXG5cbiAgICByYXRpbyA9IDFcbiAgICBpZiBvcHRzLm1heERpbWVuc2lvbj9cbiAgICAgIG1heFNpZGUgPSBNYXRoLm1heCh3aWR0aCwgaGVpZ2h0KVxuICAgICAgaWYgbWF4U2lkZSA+IG9wdHMubWF4RGltZW5zaW9uXG4gICAgICAgIHJhdGlvID0gb3B0cy5tYXhEaW1lbnNpb24gLyBtYXhTaWRlXG4gICAgZWxzZVxuICAgICAgcmF0aW8gPSAxIC8gb3B0cy5xdWFsaXR5XG5cbiAgICBpZiByYXRpbyA8IDFcbiAgICAgIEByZXNpemUgd2lkdGggKiByYXRpbywgaGVpZ2h0ICogcmF0aW8sIHJhdGlvXG5cbiAgcmVzaXplOiAodywgaCwgcikgLT5cblxuXG4gIGdldFBpeGVsQ291bnQ6IC0+XG5cbiAgZ2V0SW1hZ2VEYXRhOiAtPlxuXG4gIHJlbW92ZUNhbnZhczogLT5cbiIsIiMgU0lHQklUUyA9IDVcbiMgUlNISUZUID0gOCAtIFNJR0JJVFNcbiNcbiMgZ2V0Q29sb3JJbmRleCA9IChyLCBnLCBiKSAtPlxuIyAgIChyPDwoMipTSUdCSVRTKSkgKyAoZyA8PCBTSUdCSVRTKSArIGJcblxue2dldENvbG9ySW5kZXgsIFNJR0JJVFMsIFJTSElGVH0gPSB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpXG5Td2F0Y2ggPSByZXF1aXJlKCcuLi8uLi9zd2F0Y2gnKVxuVkJveCA9IHJlcXVpcmUoJy4vdmJveCcpXG5QUXVldWUgPSByZXF1aXJlKCcuL3BxdWV1ZScpXG5cbm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIE1NQ1FcbiAgQERlZmF1bHRPcHRzOlxuICAgIG1heEl0ZXJhdGlvbnM6IDEwMDBcbiAgICBmcmFjdEJ5UG9wdWxhdGlvbnM6IDAuNzVcblxuICBjb25zdHJ1Y3RvcjogKG9wdHMpIC0+XG4gICAgQG9wdHMgPSB1dGlsLmRlZmF1bHRzIG9wdHMsIEBjb25zdHJ1Y3Rvci5EZWZhdWx0T3B0c1xuICBxdWFudGl6ZTogKHBpeGVscywgb3B0cykgLT5cbiAgICBpZiBwaXhlbHMubGVuZ3RoID09IDAgb3Igb3B0cy5jb2xvckNvdW50IDwgMiBvciBvcHRzLmNvbG9yQ291bnQgPiAyNTZcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIldyb25nIE1NQ1EgcGFyYW1ldGVyc1wiKVxuXG4gICAgc2hvdWxkSWdub3JlID0gLT4gZmFsc2VcblxuICAgIGlmIEFycmF5LmlzQXJyYXkob3B0cy5maWx0ZXJzKSBhbmQgb3B0cy5maWx0ZXJzLmxlbmd0aCA+IDBcbiAgICAgIHNob3VsZElnbm9yZSA9IChyLCBnLCBiLCBhKSAtPlxuICAgICAgICBmb3IgZiBpbiBvcHRzLmZpbHRlcnNcbiAgICAgICAgICBpZiBub3QgZihyLCBnLCBiLCBhKSB0aGVuIHJldHVybiB0cnVlXG4gICAgICAgIHJldHVybiBmYWxzZVxuXG5cbiAgICB2Ym94ID0gVkJveC5idWlsZChwaXhlbHMsIHNob3VsZElnbm9yZSlcbiAgICBoaXN0ID0gdmJveC5oaXN0XG4gICAgY29sb3JDb3VudCA9IE9iamVjdC5rZXlzKGhpc3QpLmxlbmd0aFxuICAgIHBxID0gbmV3IFBRdWV1ZSAoYSwgYikgLT4gYS5jb3VudCgpIC0gYi5jb3VudCgpXG5cbiAgICBwcS5wdXNoKHZib3gpXG5cbiAgICAjIGZpcnN0IHNldCBvZiBjb2xvcnMsIHNvcnRlZCBieSBwb3B1bGF0aW9uXG4gICAgQF9zcGxpdEJveGVzKHBxLCBAb3B0cy5mcmFjdEJ5UG9wdWxhdGlvbnMgKiBvcHRzLmNvbG9yQ291bnQpXG5cbiAgICAjIFJlLW9yZGVyXG4gICAgcHEyID0gbmV3IFBRdWV1ZSAoYSwgYikgLT4gYS5jb3VudCgpICogYS52b2x1bWUoKSAtIGIuY291bnQoKSAqIGIudm9sdW1lKClcbiAgICBwcTIuY29udGVudHMgPSBwcS5jb250ZW50c1xuXG4gICAgIyBuZXh0IHNldCAtIGdlbmVyYXRlIHRoZSBtZWRpYW4gY3V0cyB1c2luZyB0aGUgKG5waXggKiB2b2wpIHNvcnRpbmcuXG4gICAgQF9zcGxpdEJveGVzKHBxMiwgb3B0cy5jb2xvckNvdW50IC0gcHEyLnNpemUoKSlcblxuICAgICMgY2FsY3VsYXRlIHRoZSBhY3R1YWwgY29sb3JzXG4gICAgc3dhdGNoZXMgPSBbXVxuICAgIEB2Ym94ZXMgPSBbXVxuICAgIHdoaWxlIHBxMi5zaXplKClcbiAgICAgIHYgPSBwcTIucG9wKClcbiAgICAgIGNvbG9yID0gdi5hdmcoKVxuICAgICAgaWYgbm90IHNob3VsZElnbm9yZT8oY29sb3JbMF0sIGNvbG9yWzFdLCBjb2xvclsyXSwgMjU1KVxuICAgICAgICBAdmJveGVzLnB1c2ggdlxuICAgICAgICBzd2F0Y2hlcy5wdXNoIG5ldyBTd2F0Y2ggY29sb3IsIHYuY291bnQoKVxuXG4gICAgc3dhdGNoZXNcblxuICBfc3BsaXRCb3hlczogKHBxLCB0YXJnZXQpIC0+XG4gICAgY29sb3JDb3VudCA9IDFcbiAgICBpdGVyYXRpb24gPSAwXG4gICAgbWF4SXRlcmF0aW9ucyA9IEBvcHRzLm1heEl0ZXJhdGlvbnNcbiAgICB3aGlsZSBpdGVyYXRpb24gPCBtYXhJdGVyYXRpb25zXG4gICAgICBpdGVyYXRpb24rK1xuICAgICAgdmJveCA9IHBxLnBvcCgpXG4gICAgICBpZiAhdmJveC5jb3VudCgpXG4gICAgICAgIGNvbnRpbnVlXG5cbiAgICAgIFt2Ym94MSwgdmJveDJdID0gdmJveC5zcGxpdCgpXG5cbiAgICAgIHBxLnB1c2godmJveDEpXG4gICAgICBpZiB2Ym94MlxuICAgICAgICBwcS5wdXNoKHZib3gyKVxuICAgICAgICBjb2xvckNvdW50KytcbiAgICAgIGlmIGNvbG9yQ291bnQgPj0gdGFyZ2V0IG9yIGl0ZXJhdGlvbiA+IG1heEl0ZXJhdGlvbnNcbiAgICAgICAgcmV0dXJuXG4iLCJtb2R1bGUuZXhwb3J0cyA9XG5jbGFzcyBQUXVldWVcbiAgY29uc3RydWN0b3I6IChAY29tcGFyYXRvcikgLT5cbiAgICBAY29udGVudHMgPSBbXVxuICAgIEBzb3J0ZWQgPSBmYWxzZVxuXG4gIF9zb3J0OiAtPlxuICAgIEBjb250ZW50cy5zb3J0KEBjb21wYXJhdG9yKVxuICAgIEBzb3J0ZWQgPSB0cnVlXG5cbiAgcHVzaDogKG8pIC0+XG4gICAgQGNvbnRlbnRzLnB1c2ggb1xuICAgIEBzb3J0ZWQgPSBmYWxzZVxuXG4gIHBlZWs6IChpbmRleCkgLT5cbiAgICBpZiBub3QgQHNvcnRlZFxuICAgICAgQF9zb3J0KClcbiAgICBpbmRleCA/PSBAY29udGVudHMubGVuZ3RoIC0gMVxuICAgIEBjb250ZW50c1tpbmRleF1cblxuICBwb3A6IC0+XG4gICAgaWYgbm90IEBzb3J0ZWRcbiAgICAgIEBfc29ydCgpXG4gICAgQGNvbnRlbnRzLnBvcCgpXG5cbiAgc2l6ZTogLT5cbiAgICBAY29udGVudHMubGVuZ3RoXG5cbiAgbWFwOiAoZikgLT5cbiAgICBpZiBub3QgQHNvcnRlZFxuICAgICAgQF9zb3J0KClcbiAgICBAY29udGVudHMubWFwKGYpXG4iLCJ7Z2V0Q29sb3JJbmRleCwgU0lHQklUUywgUlNISUZUfSA9IHV0aWwgPSByZXF1aXJlKCcuLi8uLi91dGlsJylcblxubW9kdWxlLmV4cG9ydHMgPVxuY2xhc3MgVkJveFxuICBAYnVpbGQ6IChwaXhlbHMsIHNob3VsZElnbm9yZSkgLT5cbiAgICBobiA9IDE8PCgzKlNJR0JJVFMpXG4gICAgaGlzdCA9IG5ldyBVaW50MzJBcnJheShobilcbiAgICBybWF4ID0gZ21heCA9IGJtYXggPSAwXG4gICAgcm1pbiA9IGdtaW4gPSBibWluID0gTnVtYmVyLk1BWF9WQUxVRVxuICAgIG4gPSBwaXhlbHMubGVuZ3RoIC8gNFxuICAgIGkgPSAwXG5cbiAgICB3aGlsZSBpIDwgblxuICAgICAgb2Zmc2V0ID0gaSAqIDRcbiAgICAgIGkrK1xuICAgICAgciA9IHBpeGVsc1tvZmZzZXQgKyAwXVxuICAgICAgZyA9IHBpeGVsc1tvZmZzZXQgKyAxXVxuICAgICAgYiA9IHBpeGVsc1tvZmZzZXQgKyAyXVxuICAgICAgYSA9IHBpeGVsc1tvZmZzZXQgKyAzXVxuICAgICAgIyBUT0RPOiB1c2UgcmVzdWx0IGZyb20gaGlzdFxuICAgICAgaWYgc2hvdWxkSWdub3JlKHIsIGcsIGIsIGEpIHRoZW4gY29udGludWVcblxuICAgICAgciA9IHIgPj4gUlNISUZUXG4gICAgICBnID0gZyA+PiBSU0hJRlRcbiAgICAgIGIgPSBiID4+IFJTSElGVFxuXG5cbiAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKVxuICAgICAgaGlzdFtpbmRleF0gKz0gMVxuXG4gICAgICBpZiByID4gcm1heFxuICAgICAgICBybWF4ID0gclxuICAgICAgaWYgciA8IHJtaW5cbiAgICAgICAgcm1pbiA9IHJcbiAgICAgIGlmIGcgPiBnbWF4XG4gICAgICAgIGdtYXggPSBnXG4gICAgICBpZiBnIDwgZ21pblxuICAgICAgICBnbWluID0gZ1xuICAgICAgaWYgYiA+IGJtYXhcbiAgICAgICAgYm1heCA9IGJcbiAgICAgIGlmIGIgPCBibWluXG4gICAgICAgIGJtaW4gPSBiXG5cbiAgICBuZXcgVkJveChybWluLCBybWF4LCBnbWluLCBnbWF4LCBibWluLCBibWF4LCBoaXN0KVxuXG4gIGNvbnN0cnVjdG9yOiAoQHIxLCBAcjIsIEBnMSwgQGcyLCBAYjEsIEBiMiwgQGhpc3QpIC0+XG4gICAgIyBAX2luaXRCb3goKVxuXG4gIGludmFsaWRhdGU6IC0+XG4gICAgZGVsZXRlIEBfY291bnRcbiAgICBkZWxldGUgQF9hdmdcbiAgICBkZWxldGUgQF92b2x1bWVcblxuICB2b2x1bWU6IC0+XG4gICAgaWYgbm90IEBfdm9sdW1lP1xuICAgICAgQF92b2x1bWUgPSAoQHIyIC0gQHIxICsgMSkgKiAoQGcyIC0gQGcxICsgMSkgKiAoQGIyIC0gQGIxICsgMSlcbiAgICBAX3ZvbHVtZVxuXG4gIGNvdW50OiAtPlxuICAgIGlmIG5vdCBAX2NvdW50P1xuICAgICAgaGlzdCA9IEBoaXN0XG4gICAgICBjID0gMFxuICAgICAgYFxuICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgIGMgKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBgXG4gICAgICAjIGZvciByIGluIFtAcjEuLkByMl1cbiAgICAgICMgICBmb3IgZyBpbiBbQGcxLi5AZzJdXG4gICAgICAjICAgICBmb3IgYiBpbiBbQGIxLi5AYjJdXG4gICAgICAjICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKVxuICAgICAgIyAgICAgICBjICs9IGhpc3RbaW5kZXhdXG4gICAgICBAX2NvdW50ID0gY1xuICAgIEBfY291bnRcblxuICBjbG9uZTogLT5cbiAgICBuZXcgVkJveChAcjEsIEByMiwgQGcxLCBAZzIsIEBiMSwgQGIyLCBAaGlzdClcblxuICBhdmc6IC0+XG4gICAgaWYgbm90IEBfYXZnP1xuICAgICAgaGlzdCA9IEBoaXN0XG4gICAgICBudG90ID0gMFxuICAgICAgbXVsdCA9IDEgPDwgKDggLSBTSUdCSVRTKVxuICAgICAgcnN1bSA9IGdzdW0gPSBic3VtID0gMFxuICAgICAgYFxuICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgIHZhciBoID0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICBudG90ICs9IGg7XG4gICAgICAgICAgICByc3VtICs9IChoICogKHIgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICBnc3VtICs9IChoICogKGcgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICBic3VtICs9IChoICogKGIgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBgXG4gICAgICAjIE5PVEU6IENvZmZlZVNjcmlwdCB3aWxsIHNjcmV3IHRoaW5ncyB1cCB3aGVuIEByMSA+IEByMlxuICAgICAgIyBmb3IgciBpbiBbQHIxLi5AcjJdXG4gICAgICAjICAgZm9yIGcgaW4gW0BnMS4uQGcyXVxuICAgICAgIyAgICAgZm9yIGIgaW4gW0BiMS4uQGIyXVxuICAgICAgIyAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYilcbiAgICAgICMgICAgICAgaCA9IGhpc3RbaW5kZXhdXG4gICAgICAjICAgICAgIG50b3QgKz0gaFxuICAgICAgIyAgICAgICByc3VtICs9IChoICogKHIgKyAwLjUpICogbXVsdClcbiAgICAgICMgICAgICAgZ3N1bSArPSAoaCAqIChnICsgMC41KSAqIG11bHQpXG4gICAgICAjICAgICAgIGJzdW0gKz0gKGggKiAoYiArIDAuNSkgKiBtdWx0KVxuXG4gICAgICBpZiBudG90XG4gICAgICAgIEBfYXZnID0gW1xuICAgICAgICAgIH5+KHJzdW0gLyBudG90KVxuICAgICAgICAgIH5+KGdzdW0gLyBudG90KVxuICAgICAgICAgIH5+KGJzdW0gLyBudG90KVxuICAgICAgICBdXG4gICAgICBlbHNlXG4gICAgICAgIEBfYXZnID0gW1xuICAgICAgICAgIH5+KG11bHQgKiAoQHIxICsgQHIyICsgMSkgLyAyKVxuICAgICAgICAgIH5+KG11bHQgKiAoQGcxICsgQGcyICsgMSkgLyAyKVxuICAgICAgICAgIH5+KG11bHQgKiAoQGIxICsgQGIyICsgMSkgLyAyKVxuICAgICAgICBdXG4gICAgQF9hdmdcblxuICBzcGxpdDogLT5cbiAgICBoaXN0ID0gQGhpc3RcbiAgICBpZiAhQGNvdW50KClcbiAgICAgIHJldHVybiBudWxsXG4gICAgaWYgQGNvdW50KCkgPT0gMVxuICAgICAgcmV0dXJuIFtAY2xvbmUoKV1cblxuICAgIHJ3ID0gQHIyIC0gQHIxICsgMVxuICAgIGd3ID0gQGcyIC0gQGcxICsgMVxuICAgIGJ3ID0gQGIyIC0gQGIxICsgMVxuXG4gICAgbWF4dyA9IE1hdGgubWF4KHJ3LCBndywgYncpXG4gICAgYWNjU3VtID0gbnVsbFxuICAgIHN1bSA9IHRvdGFsID0gMFxuXG4gICAgbWF4ZCA9IG51bGxcbiAgICBzd2l0Y2ggbWF4d1xuICAgICAgd2hlbiByd1xuICAgICAgICBtYXhkID0gJ3InXG4gICAgICAgIGFjY1N1bSA9IG5ldyBVaW50MzJBcnJheShAcjIgKyAxKVxuICAgICAgICBgXG4gICAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICAgIHN1bSA9IDBcbiAgICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgICBzdW0gKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICBhY2NTdW1bcl0gPSB0b3RhbDtcbiAgICAgICAgfVxuICAgICAgICBgXG4gICAgICAgICMgZm9yIHIgaW4gW0ByMS4uQHIyXVxuICAgICAgICAjICAgc3VtID0gMFxuICAgICAgICAjICAgZm9yIGcgaW4gW0BnMS4uQGcyXVxuICAgICAgICAjICAgICBmb3IgYiBpbiBbQGIxLi5AYjJdXG4gICAgICAgICMgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpXG4gICAgICAgICMgICAgICAgc3VtICs9IGhpc3RbaW5kZXhdXG4gICAgICAgICMgICB0b3RhbCArPSBzdW1cbiAgICAgICAgIyAgIGFjY1N1bVtyXSA9IHRvdGFsXG4gICAgICB3aGVuIGd3XG4gICAgICAgIG1heGQgPSAnZydcbiAgICAgICAgYWNjU3VtID0gbmV3IFVpbnQzMkFycmF5KEBnMiArIDEpXG4gICAgICAgIGBcbiAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgc3VtID0gMFxuICAgICAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICAgIHN1bSArPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgIGFjY1N1bVtnXSA9IHRvdGFsO1xuICAgICAgICB9XG4gICAgICAgIGBcbiAgICAgICAgIyBmb3IgZyBpbiBbQGcxLi5AZzJdXG4gICAgICAgICMgICBzdW0gPSAwXG4gICAgICAgICMgICBmb3IgciBpbiBbQHIxLi5AcjJdXG4gICAgICAgICMgICAgIGZvciBiIGluIFtAYjEuLkBiMl1cbiAgICAgICAgIyAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYilcbiAgICAgICAgIyAgICAgICBzdW0gKz0gaGlzdFtpbmRleF1cbiAgICAgICAgIyAgIHRvdGFsICs9IHN1bVxuICAgICAgICAjICAgYWNjU3VtW2ddID0gdG90YWxcbiAgICAgIHdoZW4gYndcbiAgICAgICAgbWF4ZCA9ICdiJ1xuICAgICAgICBhY2NTdW0gPSBuZXcgVWludDMyQXJyYXkoQGIyICsgMSlcbiAgICAgICAgYFxuICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICBzdW0gPSAwXG4gICAgICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgICAgc3VtICs9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgYWNjU3VtW2JdID0gdG90YWw7XG4gICAgICAgIH1cbiAgICAgICAgYFxuICAgICAgICAjIGZvciBiIGluIFtAYjEuLkBiMl1cbiAgICAgICAgIyAgIHN1bSA9IDBcbiAgICAgICAgIyAgIGZvciByIGluIFtAcjEuLkByMl1cbiAgICAgICAgIyAgICAgZm9yIGcgaW4gW0BnMS4uQGcyXVxuICAgICAgICAjICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKVxuICAgICAgICAjICAgICAgIHN1bSArPSBoaXN0W2luZGV4XVxuICAgICAgICAjICAgdG90YWwgKz0gc3VtXG4gICAgICAgICMgICBhY2NTdW1bYl0gPSB0b3RhbFxuXG4gICAgc3BsaXRQb2ludCA9IC0xXG4gICAgcmV2ZXJzZVN1bSA9IG5ldyBVaW50MzJBcnJheShhY2NTdW0ubGVuZ3RoKVxuICAgIGZvciBpIGluIFswLi5hY2NTdW0ubGVuZ3RoLTFdXG4gICAgICBkID0gYWNjU3VtW2ldXG4gICAgICBpZiBzcGxpdFBvaW50IDwgMCAmJiBkID4gdG90YWwgLyAyXG4gICAgICAgIHNwbGl0UG9pbnQgPSBpXG4gICAgICByZXZlcnNlU3VtW2ldID0gdG90YWwgLSBkXG5cbiAgICB2Ym94ID0gdGhpc1xuICAgIGRvQ3V0ID0gKGQpIC0+XG4gICAgICBkaW0xID0gZCArIFwiMVwiXG4gICAgICBkaW0yID0gZCArIFwiMlwiXG4gICAgICBkMSA9IHZib3hbZGltMV1cbiAgICAgIGQyID0gdmJveFtkaW0yXVxuICAgICAgdmJveDEgPSB2Ym94LmNsb25lKClcbiAgICAgIHZib3gyID0gdmJveC5jbG9uZSgpXG4gICAgICBsZWZ0ID0gc3BsaXRQb2ludCAtIGQxXG4gICAgICByaWdodCA9IGQyIC0gc3BsaXRQb2ludFxuICAgICAgaWYgbGVmdCA8PSByaWdodFxuICAgICAgICBkMiA9IE1hdGgubWluKGQyIC0gMSwgfn4gKHNwbGl0UG9pbnQgKyByaWdodCAvIDIpKVxuICAgICAgICBkMiA9IE1hdGgubWF4KDAsIGQyKVxuICAgICAgZWxzZVxuICAgICAgICBkMiA9IE1hdGgubWF4KGQxLCB+fiAoc3BsaXRQb2ludCAtIDEgLSBsZWZ0IC8gMikpXG4gICAgICAgIGQyID0gTWF0aC5taW4odmJveFtkaW0yXSwgZDIpXG5cblxuICAgICAgd2hpbGUgIWFjY1N1bVtkMl1cbiAgICAgICAgZDIrK1xuXG5cbiAgICAgIGMyID0gcmV2ZXJzZVN1bVtkMl1cbiAgICAgIHdoaWxlICFjMiBhbmQgYWNjU3VtW2QyIC0gMV1cbiAgICAgICAgYzIgPSByZXZlcnNlU3VtWy0tZDJdXG5cbiAgICAgIHZib3gxW2RpbTJdID0gZDJcbiAgICAgIHZib3gyW2RpbTFdID0gZDIgKyAxXG4gICAgICAjIHZib3guaW52YWxpZGF0ZSgpXG5cbiAgICAgIHJldHVybiBbdmJveDEsIHZib3gyXVxuXG4gICAgZG9DdXQgbWF4ZFxuXG4gIGNvbnRhaW5zOiAocCkgLT5cbiAgICByID0gcFswXT4+UlNISUZUXG4gICAgZyA9IHBbMV0+PlJTSElGVFxuICAgIGIgPSBwWzJdPj5SU0hJRlRcblxuICAgIHIgPj0gQHIxIGFuZCByIDw9IEByMiBhbmQgZyA+PSBAZzEgYW5kIGcgPD0gQGcyIGFuZCBiID49IEBiMSBhbmQgYiA8PSBAYjJcbiIsIm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIFF1YW50aXplclxuICBpbml0aWFsaXplOiAocGl4ZWxzLCBvcHRzKSAtPlxuXG4gIGdldFF1YW50aXplZENvbG9yczogLT5cblxubW9kdWxlLmV4cG9ydHMuTU1DUSA9IHJlcXVpcmUoJy4vbW1jcScpXG4iLCJTd2F0Y2ggPSByZXF1aXJlKCcuLi9zd2F0Y2gnKVxuUXVhbnRpemVyID0gcmVxdWlyZSgnLi9pbmRleCcpXG5NTUNRSW1wbCA9IHJlcXVpcmUoJy4vaW1wbC9tbWNxJylcblxubW9kdWxlLmV4cG9ydHMgPVxuY2xhc3MgTU1DUSBleHRlbmRzIFF1YW50aXplclxuICBpbml0aWFsaXplOiAocGl4ZWxzLCBAb3B0cykgLT5cbiAgICBtbWNxID0gbmV3IE1NQ1FJbXBsKClcbiAgICBAc3dhdGNoZXMgPSBtbWNxLnF1YW50aXplIHBpeGVscywgQG9wdHNcblxuICBnZXRRdWFudGl6ZWRDb2xvcnM6IC0+XG4gICAgQHN3YXRjaGVzXG4iLCJ1dGlsID0gcmVxdWlyZSgnLi91dGlsJylcbiMjI1xuICBGcm9tIFZpYnJhbnQuanMgYnkgSmFyaSBad2FydHNcbiAgUG9ydGVkIHRvIG5vZGUuanMgYnkgQUtGaXNoXG5cbiAgU3dhdGNoIGNsYXNzXG4jIyNcbm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIFN3YXRjaFxuICBoc2w6IHVuZGVmaW5lZFxuICByZ2I6IHVuZGVmaW5lZFxuICBwb3B1bGF0aW9uOiAxXG4gIHlpcTogMFxuXG4gIGNvbnN0cnVjdG9yOiAocmdiLCBwb3B1bGF0aW9uKSAtPlxuICAgIEByZ2IgPSByZ2JcbiAgICBAcG9wdWxhdGlvbiA9IHBvcHVsYXRpb25cblxuICBnZXRIc2w6IC0+XG4gICAgaWYgbm90IEBoc2xcbiAgICAgIEBoc2wgPSB1dGlsLnJnYlRvSHNsIEByZ2JbMF0sIEByZ2JbMV0sIEByZ2JbMl1cbiAgICBlbHNlIEBoc2xcblxuICBnZXRQb3B1bGF0aW9uOiAtPlxuICAgIEBwb3B1bGF0aW9uXG5cbiAgZ2V0UmdiOiAtPlxuICAgIEByZ2JcblxuICBnZXRIZXg6IC0+XG4gICAgdXRpbC5yZ2JUb0hleChAcmdiWzBdLCBAcmdiWzFdLCBAcmdiWzJdKVxuXG4gIGdldFRpdGxlVGV4dENvbG9yOiAtPlxuICAgIEBfZW5zdXJlVGV4dENvbG9ycygpXG4gICAgaWYgQHlpcSA8IDIwMCB0aGVuIFwiI2ZmZlwiIGVsc2UgXCIjMDAwXCJcblxuICBnZXRCb2R5VGV4dENvbG9yOiAtPlxuICAgIEBfZW5zdXJlVGV4dENvbG9ycygpXG4gICAgaWYgQHlpcSA8IDE1MCB0aGVuIFwiI2ZmZlwiIGVsc2UgXCIjMDAwXCJcblxuICBfZW5zdXJlVGV4dENvbG9yczogLT5cbiAgICBpZiBub3QgQHlpcSB0aGVuIEB5aXEgPSAoQHJnYlswXSAqIDI5OSArIEByZ2JbMV0gKiA1ODcgKyBAcmdiWzJdICogMTE0KSAvIDEwMDBcbiIsIkRFTFRBRTk0ID1cbiAgTkE6IDBcbiAgUEVSRkVDVDogMVxuICBDTE9TRTogMlxuICBHT09EOiAxMFxuICBTSU1JTEFSOiA1MFxuXG5TSUdCSVRTID0gNVxuUlNISUZUID0gOCAtIFNJR0JJVFNcblxuXG5cbm1vZHVsZS5leHBvcnRzID1cbiAgY2xvbmU6IChvKSAtPlxuICAgIGlmIHR5cGVvZiBvID09ICdvYmplY3QnXG4gICAgICBpZiBBcnJheS5pc0FycmF5IG9cbiAgICAgICAgcmV0dXJuIG8ubWFwICh2KSA9PiB0aGlzLmNsb25lIHZcbiAgICAgIGVsc2VcbiAgICAgICAgX28gPSB7fVxuICAgICAgICBmb3Iga2V5LCB2YWx1ZSBvZiBvXG4gICAgICAgICAgX29ba2V5XSA9IHRoaXMuY2xvbmUgdmFsdWVcbiAgICAgICAgcmV0dXJuIF9vXG4gICAgb1xuXG4gIGRlZmF1bHRzOiAoKSAtPlxuICAgIG8gPSB7fVxuICAgIGZvciBfbyBpbiBhcmd1bWVudHNcbiAgICAgIGZvciBrZXksIHZhbHVlIG9mIF9vXG4gICAgICAgIGlmIG5vdCBvW2tleV0/IHRoZW4gb1trZXldID0gdGhpcy5jbG9uZSB2YWx1ZVxuXG4gICAgb1xuXG4gIGhleFRvUmdiOiAoaGV4KSAtPlxuICAgIG0gPSAvXiM/KFthLWZcXGRdezJ9KShbYS1mXFxkXXsyfSkoW2EtZlxcZF17Mn0pJC9pLmV4ZWMoaGV4KVxuICAgIGlmIG0/XG4gICAgICByZXR1cm4gW21bMV0sIG1bMl0sIG1bM11dLm1hcCAocykgLT4gcGFyc2VJbnQocywgMTYpXG4gICAgcmV0dXJuIG51bGxcblxuICByZ2JUb0hleDogKHIsIGcsIGIpIC0+XG4gICAgXCIjXCIgKyAoKDEgPDwgMjQpICsgKHIgPDwgMTYpICsgKGcgPDwgOCkgKyBiKS50b1N0cmluZygxNikuc2xpY2UoMSwgNylcblxuICByZ2JUb0hzbDogKHIsIGcsIGIpIC0+XG4gICAgciAvPSAyNTVcbiAgICBnIC89IDI1NVxuICAgIGIgLz0gMjU1XG4gICAgbWF4ID0gTWF0aC5tYXgociwgZywgYilcbiAgICBtaW4gPSBNYXRoLm1pbihyLCBnLCBiKVxuICAgIGggPSB1bmRlZmluZWRcbiAgICBzID0gdW5kZWZpbmVkXG4gICAgbCA9IChtYXggKyBtaW4pIC8gMlxuICAgIGlmIG1heCA9PSBtaW5cbiAgICAgIGggPSBzID0gMFxuICAgICAgIyBhY2hyb21hdGljXG4gICAgZWxzZVxuICAgICAgZCA9IG1heCAtIG1pblxuICAgICAgcyA9IGlmIGwgPiAwLjUgdGhlbiBkIC8gKDIgLSBtYXggLSBtaW4pIGVsc2UgZCAvIChtYXggKyBtaW4pXG4gICAgICBzd2l0Y2ggbWF4XG4gICAgICAgIHdoZW4gclxuICAgICAgICAgIGggPSAoZyAtIGIpIC8gZCArIChpZiBnIDwgYiB0aGVuIDYgZWxzZSAwKVxuICAgICAgICB3aGVuIGdcbiAgICAgICAgICBoID0gKGIgLSByKSAvIGQgKyAyXG4gICAgICAgIHdoZW4gYlxuICAgICAgICAgIGggPSAociAtIGcpIC8gZCArIDRcbiAgICAgIGggLz0gNlxuICAgIFtoLCBzLCBsXVxuXG4gIGhzbFRvUmdiOiAoaCwgcywgbCkgLT5cbiAgICByID0gdW5kZWZpbmVkXG4gICAgZyA9IHVuZGVmaW5lZFxuICAgIGIgPSB1bmRlZmluZWRcblxuICAgIGh1ZTJyZ2IgPSAocCwgcSwgdCkgLT5cbiAgICAgIGlmIHQgPCAwXG4gICAgICAgIHQgKz0gMVxuICAgICAgaWYgdCA+IDFcbiAgICAgICAgdCAtPSAxXG4gICAgICBpZiB0IDwgMSAvIDZcbiAgICAgICAgcmV0dXJuIHAgKyAocSAtIHApICogNiAqIHRcbiAgICAgIGlmIHQgPCAxIC8gMlxuICAgICAgICByZXR1cm4gcVxuICAgICAgaWYgdCA8IDIgLyAzXG4gICAgICAgIHJldHVybiBwICsgKHEgLSBwKSAqICgyIC8gMyAtIHQpICogNlxuICAgICAgcFxuXG4gICAgaWYgcyA9PSAwXG4gICAgICByID0gZyA9IGIgPSBsXG4gICAgICAjIGFjaHJvbWF0aWNcbiAgICBlbHNlXG4gICAgICBxID0gaWYgbCA8IDAuNSB0aGVuIGwgKiAoMSArIHMpIGVsc2UgbCArIHMgLSAobCAqIHMpXG4gICAgICBwID0gMiAqIGwgLSBxXG4gICAgICByID0gaHVlMnJnYihwLCBxLCBoICsgMSAvIDMpXG4gICAgICBnID0gaHVlMnJnYihwLCBxLCBoKVxuICAgICAgYiA9IGh1ZTJyZ2IocCwgcSwgaCAtICgxIC8gMykpXG4gICAgW1xuICAgICAgciAqIDI1NVxuICAgICAgZyAqIDI1NVxuICAgICAgYiAqIDI1NVxuICAgIF1cblxuICByZ2JUb1h5ejogKHIsIGcsIGIpIC0+XG4gICAgciAvPSAyNTVcbiAgICBnIC89IDI1NVxuICAgIGIgLz0gMjU1XG4gICAgciA9IGlmIHIgPiAwLjA0MDQ1IHRoZW4gTWF0aC5wb3coKHIgKyAwLjAwNSkgLyAxLjA1NSwgMi40KSBlbHNlIHIgLyAxMi45MlxuICAgIGcgPSBpZiBnID4gMC4wNDA0NSB0aGVuIE1hdGgucG93KChnICsgMC4wMDUpIC8gMS4wNTUsIDIuNCkgZWxzZSBnIC8gMTIuOTJcbiAgICBiID0gaWYgYiA+IDAuMDQwNDUgdGhlbiBNYXRoLnBvdygoYiArIDAuMDA1KSAvIDEuMDU1LCAyLjQpIGVsc2UgYiAvIDEyLjkyXG5cbiAgICByICo9IDEwMFxuICAgIGcgKj0gMTAwXG4gICAgYiAqPSAxMDBcblxuICAgIHggPSByICogMC40MTI0ICsgZyAqIDAuMzU3NiArIGIgKiAwLjE4MDVcbiAgICB5ID0gciAqIDAuMjEyNiArIGcgKiAwLjcxNTIgKyBiICogMC4wNzIyXG4gICAgeiA9IHIgKiAwLjAxOTMgKyBnICogMC4xMTkyICsgYiAqIDAuOTUwNVxuXG4gICAgW3gsIHksIHpdXG5cbiAgeHl6VG9DSUVMYWI6ICh4LCB5LCB6KSAtPlxuICAgIFJFRl9YID0gOTUuMDQ3XG4gICAgUkVGX1kgPSAxMDBcbiAgICBSRUZfWiA9IDEwOC44ODNcblxuICAgIHggLz0gUkVGX1hcbiAgICB5IC89IFJFRl9ZXG4gICAgeiAvPSBSRUZfWlxuXG4gICAgeCA9IGlmIHggPiAwLjAwODg1NiB0aGVuIE1hdGgucG93KHgsIDEvMykgZWxzZSA3Ljc4NyAqIHggKyAxNiAvIDExNlxuICAgIHkgPSBpZiB5ID4gMC4wMDg4NTYgdGhlbiBNYXRoLnBvdyh5LCAxLzMpIGVsc2UgNy43ODcgKiB5ICsgMTYgLyAxMTZcbiAgICB6ID0gaWYgeiA+IDAuMDA4ODU2IHRoZW4gTWF0aC5wb3coeiwgMS8zKSBlbHNlIDcuNzg3ICogeiArIDE2IC8gMTE2XG5cbiAgICBMID0gMTE2ICogeSAtIDE2XG4gICAgYSA9IDUwMCAqICh4IC0geSlcbiAgICBiID0gMjAwICogKHkgLSB6KVxuXG4gICAgW0wsIGEsIGJdXG5cbiAgcmdiVG9DSUVMYWI6IChyLCBnLCBiKSAtPlxuICAgIFt4LCB5LCB6XSA9IHRoaXMucmdiVG9YeXogciwgZywgYlxuICAgIHRoaXMueHl6VG9DSUVMYWIgeCwgeSwgelxuXG4gIGRlbHRhRTk0OiAobGFiMSwgbGFiMikgLT5cbiAgICAjIFdlaWdodHNcbiAgICBXRUlHSFRfTCA9IDFcbiAgICBXRUlHSFRfQyA9IDFcbiAgICBXRUlHSFRfSCA9IDFcblxuICAgIFtMMSwgYTEsIGIxXSA9IGxhYjFcbiAgICBbTDIsIGEyLCBiMl0gPSBsYWIyXG4gICAgZEwgPSBMMSAtIEwyXG4gICAgZGEgPSBhMSAtIGEyXG4gICAgZGIgPSBiMSAtIGIyXG5cbiAgICB4QzEgPSBNYXRoLnNxcnQgYTEgKiBhMSArIGIxICogYjFcbiAgICB4QzIgPSBNYXRoLnNxcnQgYTIgKiBhMiArIGIyICogYjJcblxuICAgIHhETCA9IEwyIC0gTDFcbiAgICB4REMgPSB4QzIgLSB4QzFcbiAgICB4REUgPSBNYXRoLnNxcnQgZEwgKiBkTCArIGRhICogZGEgKyBkYiAqIGRiXG5cbiAgICBpZiBNYXRoLnNxcnQoeERFKSA+IE1hdGguc3FydChNYXRoLmFicyh4REwpKSArIE1hdGguc3FydChNYXRoLmFicyh4REMpKVxuICAgICAgeERIID0gTWF0aC5zcXJ0IHhERSAqIHhERSAtIHhETCAqIHhETCAtIHhEQyAqIHhEQ1xuICAgIGVsc2VcbiAgICAgIHhESCA9IDBcblxuICAgIHhTQyA9IDEgKyAwLjA0NSAqIHhDMVxuICAgIHhTSCA9IDEgKyAwLjAxNSAqIHhDMVxuXG4gICAgeERMIC89IFdFSUdIVF9MXG4gICAgeERDIC89IFdFSUdIVF9DICogeFNDXG4gICAgeERIIC89IFdFSUdIVF9IICogeFNIXG5cbiAgICBNYXRoLnNxcnQgeERMICogeERMICsgeERDICogeERDICsgeERIICogeERIXG5cbiAgcmdiRGlmZjogKHJnYjEsIHJnYjIpIC0+XG4gICAgbGFiMSA9IEByZ2JUb0NJRUxhYi5hcHBseSBALCByZ2IxXG4gICAgbGFiMiA9IEByZ2JUb0NJRUxhYi5hcHBseSBALCByZ2IyXG4gICAgQGRlbHRhRTk0IGxhYjEsIGxhYjJcblxuICBoZXhEaWZmOiAoaGV4MSwgaGV4MikgLT5cbiAgICAjIGNvbnNvbGUubG9nIFwiQ29tcGFyZSAje2hleDF9ICN7aGV4Mn1cIlxuICAgIHJnYjEgPSBAaGV4VG9SZ2IgaGV4MVxuICAgIHJnYjIgPSBAaGV4VG9SZ2IgaGV4MlxuICAgICMgY29uc29sZS5sb2cgcmdiMVxuICAgICMgY29uc29sZS5sb2cgcmdiMlxuICAgIEByZ2JEaWZmIHJnYjEsIHJnYjJcblxuICBERUxUQUU5NF9ESUZGX1NUQVRVUzogREVMVEFFOTRcblxuICBnZXRDb2xvckRpZmZTdGF0dXM6IChkKSAtPlxuICAgIGlmIGQgPCBERUxUQUU5NC5OQVxuICAgICAgcmV0dXJuIFwiTi9BXCJcbiAgICAjIE5vdCBwZXJjZXB0aWJsZSBieSBodW1hbiBleWVzXG4gICAgaWYgZCA8PSBERUxUQUU5NC5QRVJGRUNUXG4gICAgICByZXR1cm4gXCJQZXJmZWN0XCJcbiAgICAjIFBlcmNlcHRpYmxlIHRocm91Z2ggY2xvc2Ugb2JzZXJ2YXRpb25cbiAgICBpZiBkIDw9IERFTFRBRTk0LkNMT1NFXG4gICAgICByZXR1cm4gXCJDbG9zZVwiXG4gICAgIyBQZXJjZXB0aWJsZSBhdCBhIGdsYW5jZVxuICAgIGlmIGQgPD0gREVMVEFFOTQuR09PRFxuICAgICAgcmV0dXJuIFwiR29vZFwiXG4gICAgIyBDb2xvcnMgYXJlIG1vcmUgc2ltaWxhciB0aGFuIG9wcG9zaXRlXG4gICAgaWYgZCA8IERFTFRBRTk0LlNJTUlMQVJcbiAgICAgIHJldHVybiBcIlNpbWlsYXJcIlxuICAgIHJldHVybiBcIldyb25nXCJcblxuICBTSUdCSVRTOiBTSUdCSVRTXG4gIFJTSElGVDogUlNISUZUXG4gIGdldENvbG9ySW5kZXg6IChyLCBnLCBiKSAtPlxuICAgIChyPDwoMipTSUdCSVRTKSkgKyAoZyA8PCBTSUdCSVRTKSArIGJcbiIsIiMjI1xuICBGcm9tIFZpYnJhbnQuanMgYnkgSmFyaSBad2FydHNcbiAgUG9ydGVkIHRvIG5vZGUuanMgYnkgQUtGaXNoXG5cbiAgQ29sb3IgYWxnb3JpdGhtIGNsYXNzIHRoYXQgZmluZHMgdmFyaWF0aW9ucyBvbiBjb2xvcnMgaW4gYW4gaW1hZ2UuXG5cbiAgQ3JlZGl0c1xuICAtLS0tLS0tLVxuICBMb2tlc2ggRGhha2FyIChodHRwOi8vd3d3Lmxva2VzaGRoYWthci5jb20pIC0gQ3JlYXRlZCBDb2xvclRoaWVmXG4gIEdvb2dsZSAtIFBhbGV0dGUgc3VwcG9ydCBsaWJyYXJ5IGluIEFuZHJvaWRcbiMjI1xuU3dhdGNoID0gcmVxdWlyZSgnLi9zd2F0Y2gnKVxudXRpbCA9IHJlcXVpcmUoJy4vdXRpbCcpXG5EZWZhdWx0R2VuZXJhdG9yID0gcmVxdWlyZSgnLi9nZW5lcmF0b3InKS5EZWZhdWx0XG5GaWx0ZXIgPSByZXF1aXJlKCcuL2ZpbHRlcicpXG5cbm1vZHVsZS5leHBvcnRzID1cbmNsYXNzIFZpYnJhbnRcbiAgQERlZmF1bHRPcHRzOlxuICAgIGNvbG9yQ291bnQ6IDY0XG4gICAgcXVhbGl0eTogNVxuICAgIGdlbmVyYXRvcjogbmV3IERlZmF1bHRHZW5lcmF0b3IoKVxuICAgIEltYWdlOiBudWxsXG4gICAgUXVhbnRpemVyOiByZXF1aXJlKCcuL3F1YW50aXplcicpLk1NQ1FcbiAgICBmaWx0ZXJzOiBbXVxuXG4gIEBmcm9tOiAoc3JjKSAtPlxuICAgIG5ldyBCdWlsZGVyKHNyYylcblxuICBxdWFudGl6ZTogcmVxdWlyZSgncXVhbnRpemUnKVxuXG4gIF9zd2F0Y2hlczogW11cblxuICBjb25zdHJ1Y3RvcjogKEBzb3VyY2VJbWFnZSwgb3B0cyA9IHt9KSAtPlxuICAgIEBvcHRzID0gdXRpbC5kZWZhdWx0cyhvcHRzLCBAY29uc3RydWN0b3IuRGVmYXVsdE9wdHMpXG4gICAgQGdlbmVyYXRvciA9IEBvcHRzLmdlbmVyYXRvclxuXG4gIGdldFBhbGV0dGU6IChjYikgLT5cbiAgICBpbWFnZSA9IG5ldyBAb3B0cy5JbWFnZSBAc291cmNlSW1hZ2UsIChlcnIsIGltYWdlKSA9PlxuICAgICAgaWYgZXJyPyB0aGVuIHJldHVybiBjYihlcnIpXG4gICAgICB0cnlcbiAgICAgICAgQF9wcm9jZXNzIGltYWdlLCBAb3B0c1xuICAgICAgICBjYiBudWxsLCBAc3dhdGNoZXMoKVxuICAgICAgY2F0Y2ggZXJyb3JcbiAgICAgICAgcmV0dXJuIGNiKGVycm9yKVxuXG4gIGdldFN3YXRjaGVzOiAoY2IpIC0+XG4gICAgQGdldFBhbGV0dGUgY2JcblxuICBfcHJvY2VzczogKGltYWdlLCBvcHRzKSAtPlxuICAgIGltYWdlLnNjYWxlRG93bihAb3B0cylcbiAgICBpbWFnZURhdGEgPSBpbWFnZS5nZXRJbWFnZURhdGEoKVxuXG4gICAgcXVhbnRpemVyID0gbmV3IEBvcHRzLlF1YW50aXplcigpXG4gICAgcXVhbnRpemVyLmluaXRpYWxpemUoaW1hZ2VEYXRhLmRhdGEsIEBvcHRzKVxuXG4gICAgc3dhdGNoZXMgPSBxdWFudGl6ZXIuZ2V0UXVhbnRpemVkQ29sb3JzKClcblxuICAgIEBnZW5lcmF0b3IuZ2VuZXJhdGUoc3dhdGNoZXMpXG4gICAgIyBDbGVhbiB1cFxuICAgIGltYWdlLnJlbW92ZUNhbnZhcygpXG5cbiAgc3dhdGNoZXM6ID0+XG4gICAgVmlicmFudDogICAgICBAZ2VuZXJhdG9yLmdldFZpYnJhbnRTd2F0Y2goKVxuICAgIE11dGVkOiAgICAgICAgQGdlbmVyYXRvci5nZXRNdXRlZFN3YXRjaCgpXG4gICAgRGFya1ZpYnJhbnQ6ICBAZ2VuZXJhdG9yLmdldERhcmtWaWJyYW50U3dhdGNoKClcbiAgICBEYXJrTXV0ZWQ6ICAgIEBnZW5lcmF0b3IuZ2V0RGFya011dGVkU3dhdGNoKClcbiAgICBMaWdodFZpYnJhbnQ6IEBnZW5lcmF0b3IuZ2V0TGlnaHRWaWJyYW50U3dhdGNoKClcbiAgICBMaWdodE11dGVkOiAgIEBnZW5lcmF0b3IuZ2V0TGlnaHRNdXRlZFN3YXRjaCgpXG5cbm1vZHVsZS5leHBvcnRzLkJ1aWxkZXIgPVxuY2xhc3MgQnVpbGRlclxuICBjb25zdHJ1Y3RvcjogKEBzcmMsIEBvcHRzID0ge30pIC0+XG4gICAgQG9wdHMuZmlsdGVycyA9IHV0aWwuY2xvbmUgVmlicmFudC5EZWZhdWx0T3B0cy5maWx0ZXJzXG5cbiAgbWF4Q29sb3JDb3VudDogKG4pIC0+XG4gICAgQG9wdHMuY29sb3JDb3VudCA9IG5cbiAgICBAXG5cbiAgbWF4RGltZW5zaW9uOiAoZCkgLT5cbiAgICBAb3B0cy5tYXhEaW1lbnNpb24gPSBkXG4gICAgQFxuXG4gIGFkZEZpbHRlcjogKGYpIC0+XG4gICAgaWYgdHlwZW9mIGYgPT0gJ2Z1bmN0aW9uJ1xuICAgICAgQG9wdHMuZmlsdGVycy5wdXNoIGZcbiAgICBAXG5cbiAgcmVtb3ZlRmlsdGVyOiAoZikgLT5cbiAgICBpZiAoaSA9IEBvcHRzLmZpbHRlcnMuaW5kZXhPZihmKSkgPiAwXG4gICAgICBAb3B0cy5maWx0ZXJzLnNwbGljZShpKVxuICAgIEBcblxuICBjbGVhckZpbHRlcnM6IC0+XG4gICAgQG9wdHMuZmlsdGVycyA9IFtdXG4gICAgQFxuXG4gIHF1YWxpdHk6IChxKSAtPlxuICAgIEBvcHRzLnF1YWxpdHkgPSBxXG4gICAgQFxuXG4gIHVzZUltYWdlOiAoaW1hZ2UpIC0+XG4gICAgQG9wdHMuSW1hZ2UgPSBpbWFnZVxuICAgIEBcblxuICB1c2VHZW5lcmF0b3I6IChnZW5lcmF0b3IpIC0+XG4gICAgQG9wdHMuZ2VuZXJhdG9yID0gZ2VuZXJhdG9yXG4gICAgQFxuXG4gIHVzZVF1YW50aXplcjogKHF1YW50aXplcikgLT5cbiAgICBAb3B0cy5RdWFudGl6ZXIgPSBxdWFudGl6ZXJcbiAgICBAXG5cbiAgYnVpbGQ6IC0+XG4gICAgaWYgbm90IEB2P1xuICAgICAgQHYgPSBuZXcgVmlicmFudChAc3JjLCBAb3B0cylcbiAgICBAdlxuXG4gIGdldFN3YXRjaGVzOiAoY2IpIC0+XG4gICAgQGJ1aWxkKCkuZ2V0UGFsZXR0ZSBjYlxuXG4gIGdldFBhbGV0dGU6IChjYikgLT5cbiAgICBAYnVpbGQoKS5nZXRQYWxldHRlIGNiXG5cbiAgZnJvbTogKHNyYykgLT5cbiAgICBuZXcgVmlicmFudChzcmMsIEBvcHRzKVxuXG5tb2R1bGUuZXhwb3J0cy5VdGlsID0gdXRpbFxubW9kdWxlLmV4cG9ydHMuU3dhdGNoID0gU3dhdGNoXG5tb2R1bGUuZXhwb3J0cy5RdWFudGl6ZXIgPSByZXF1aXJlKCcuL3F1YW50aXplci8nKVxubW9kdWxlLmV4cG9ydHMuR2VuZXJhdG9yID0gcmVxdWlyZSgnLi9nZW5lcmF0b3IvJylcbm1vZHVsZS5leHBvcnRzLkZpbHRlciA9IHJlcXVpcmUoJy4vZmlsdGVyLycpXG4iXX0=
