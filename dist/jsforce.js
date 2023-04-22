"use strict";
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// lib/promise.js
var require_promise = __commonJS({
  "lib/promise.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var Promise2 = require("promise/lib/es6-extensions");
    Promise2.prototype.thenCall = function(callback) {
      if (_.isFunction(callback)) {
        this.then(function(res) {
          process.nextTick(function() {
            callback(null, res);
          });
        }, function(err) {
          process.nextTick(function() {
            callback(err);
          });
        });
      }
      return this;
    };
    Promise2.prototype.fail = Promise2.prototype["catch"];
    Promise2.defer = function() {
      return new Deferred();
    };
    var Deferred = function() {
      var self = this;
      this.promise = new Promise2(function(resolve, reject) {
        self.resolve = resolve;
        self.reject = reject;
      });
    };
    module2.exports = Promise2;
  }
});

// lib/logger.js
var require_logger = __commonJS({
  "lib/logger.js"(exports2, module2) {
    "use strict";
    var Logger = module2.exports = function(logLevel) {
      if (typeof logLevel === "string") {
        logLevel = LogLevels[logLevel];
      }
      if (!logLevel) {
        logLevel = LogLevels.INFO;
      }
      this._logLevel = logLevel;
    };
    var LogLevels = Logger.LogLevels = {
      "DEBUG": 1,
      "INFO": 2,
      "WARN": 3,
      "ERROR": 4,
      "FATAL": 5
    };
    Logger.prototype.log = function(level2, message) {
      if (this._logLevel <= level2) {
        if (level2 < LogLevels.ERROR) {
          console.log(message);
        } else {
          console.error(message);
        }
      }
    };
    for (level in LogLevels) {
      Logger.prototype[level.toLowerCase()] = createLoggerFunction(LogLevels[level]);
    }
    var level;
    function createLoggerFunction(level2) {
      return function(message) {
        this.log(level2, message);
      };
    }
  }
});

// lib/browser/canvas.js
var require_canvas = __commonJS({
  "lib/browser/canvas.js"(exports2, module2) {
    "use strict";
    var Duplex = require("readable-stream").Duplex;
    var _ = require("lodash/core");
    function parseHeaders(hs) {
      var headers = {};
      hs.split(/\n/).forEach(function(line) {
        var pair = line.split(/\s*:\s*/);
        var name = pair[0].toLowerCase();
        var value = pair[1];
        headers[name] = value;
      });
      return headers;
    }
    module2.exports = {
      supported: typeof Sfdc === "object" && typeof Sfdc.canvas !== "undefined",
      createRequest: function(signedRequest) {
        return function(params, callback) {
          var response;
          var str = new Duplex();
          str._read = function(size) {
            if (response) {
              str.push(response.body);
            }
          };
          var bufs = [];
          var sent = false;
          str._write = function(chunk, encoding, callback2) {
            bufs.push(chunk.toString(encoding));
            callback2();
          };
          str.on("finish", function() {
            if (!sent) {
              send(bufs.join(""));
              sent = true;
            }
          });
          if (params.body || params.body === "" || !/^(put|post|patch)$/i.test(params.method)) {
            send(params.body);
            sent = true;
          }
          function send(body) {
            var settings = {
              client: signedRequest.client,
              method: params.method,
              data: body
            };
            if (params.headers) {
              settings.headers = {};
              for (var name in params.headers) {
                if (name.toLowerCase() === "content-type") {
                  settings.contentType = params.headers[name];
                } else {
                  settings.headers[name] = params.headers[name];
                }
              }
            }
            settings.success = function(data) {
              var headers = parseHeaders(data.responseHeaders);
              var body2 = data.payload;
              if (!_.isString(body2)) {
                body2 = JSON.stringify(body2);
              }
              response = {
                statusCode: data.status,
                headers,
                body: body2
              };
              if (callback) {
                callback(null, response, response.body);
              }
              str.end();
            };
            settings.failure = function(err) {
              if (callback) {
                callback(err);
              }
            };
            Sfdc.canvas.client.ajax(params.url, settings);
          }
          return str;
        };
      }
    };
  }
});

// lib/browser/jsonp.js
var require_jsonp = __commonJS({
  "lib/browser/jsonp.js"(exports2, module2) {
    "use strict";
    var _index = 0;
    module2.exports = {
      supported: typeof window !== "undefined" && typeof document !== "undefined",
      createRequest: function(jsonpParam, timeout) {
        jsonpParam = jsonpParam || "callback";
        timeout = timeout || 1e4;
        return function(params, callback) {
          if (params.method.toUpperCase() !== "GET") {
            return callback(new Error("JSONP only supports GET request."));
          }
          var cbFuncName = "_jsforce_jsonpCallback_" + ++_index;
          var callbacks = window;
          var url = params.url;
          url += url.indexOf("?") > 0 ? "&" : "?";
          url += jsonpParam + "=" + cbFuncName;
          var script = document.createElement("script");
          script.type = "text/javascript";
          script.src = url;
          document.documentElement.appendChild(script);
          var pid = setTimeout(function() {
            cleanup();
            callback(new Error("JSONP call time out."));
          }, timeout);
          callbacks[cbFuncName] = function(res) {
            cleanup();
            callback(null, {
              statusCode: 200,
              headers: { "content-type": "application/json" },
              body: JSON.stringify(res)
            });
          };
          var cleanup = function() {
            clearTimeout(pid);
            document.documentElement.removeChild(script);
            delete callbacks[cbFuncName];
          };
        };
      }
    };
  }
});

// lib/transport.js
var require_transport = __commonJS({
  "lib/transport.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var Promise2 = require_promise();
    var request = require("request");
    var canvas = require_canvas();
    var jsonp = require_jsonp();
    if (request.defaults) {
      defaults = {
        followAllRedirects: true
      };
      if (process.env.HTTP_PROXY) {
        defaults.proxy = process.env.HTTP_PROXY;
      }
      if (parseInt(process.env.HTTP_TIMEOUT)) {
        defaults.timeout = parseInt(process.env.HTTP_TIMEOUT);
      }
      request = request.defaults(defaults);
    }
    var defaults;
    var baseUrl;
    if (typeof window === "undefined") {
      baseUrl = process.env.LOCATION_BASE_URL || "";
    } else {
      apiHost = normalizeApiHost(window.location.host);
      baseUrl = apiHost ? "https://" + apiHost : "";
    }
    var apiHost;
    function streamify(promise, factory) {
      var _then = promise.then;
      promise.then = function() {
        factory();
        var newPromise = _then.apply(promise, arguments);
        return streamify(newPromise, factory);
      };
      promise.stream = factory;
      return promise;
    }
    function normalizeApiHost(apiHost2) {
      var m = /(\w+)\.(visual\.force|salesforce)\.com$/.exec(apiHost2);
      if (m) {
        apiHost2 = m[1] + ".salesforce.com";
      }
      return apiHost2;
    }
    var Transport = module2.exports = function() {
    };
    Transport.prototype.httpRequest = function(params, callback) {
      var deferred = Promise2.defer();
      var req;
      var httpRequest = this._getHttpRequestModule();
      var createRequest = function() {
        if (!req) {
          req = httpRequest(params, function(err, response) {
            if (err) {
              deferred.reject(err);
            } else {
              deferred.resolve(response);
            }
          });
        }
        return req;
      };
      return streamify(deferred.promise, createRequest).thenCall(callback);
    };
    Transport.prototype._getHttpRequestModule = function() {
      return request;
    };
    var JsonpTransport = Transport.JsonpTransport = function(jsonpParam) {
      this._jsonpParam = jsonpParam;
    };
    inherits(JsonpTransport, Transport);
    JsonpTransport.prototype._getHttpRequestModule = function() {
      return jsonp.createRequest(this._jsonpParam);
    };
    JsonpTransport.supported = jsonp.supported;
    var CanvasTransport = Transport.CanvasTransport = function(signedRequest) {
      this._signedRequest = signedRequest;
    };
    inherits(CanvasTransport, Transport);
    CanvasTransport.prototype._getHttpRequestModule = function() {
      return canvas.createRequest(this._signedRequest);
    };
    CanvasTransport.supported = canvas.supported;
    var ProxyTransport = Transport.ProxyTransport = function(proxyUrl) {
      this._proxyUrl = proxyUrl;
    };
    inherits(ProxyTransport, Transport);
    ProxyTransport.prototype.httpRequest = function(params, callback) {
      var url = params.url;
      if (url.indexOf("/") === 0) {
        url = baseUrl + url;
      }
      var proxyParams = {
        method: params.method,
        url: this._proxyUrl + "?" + Date.now() + "." + ("" + Math.random()).substring(2),
        headers: {
          "salesforceproxy-endpoint": url
        }
      };
      if (params.body || params.body === "") {
        proxyParams.body = params.body;
      }
      if (params.headers) {
        for (var name in params.headers) {
          proxyParams.headers[name] = params.headers[name];
        }
      }
      return ProxyTransport.super_.prototype.httpRequest.call(this, proxyParams, callback);
    };
    var HttpProxyTransport = Transport.HttpProxyTransport = function(httpProxy) {
      this._httpProxy = httpProxy;
    };
    inherits(HttpProxyTransport, Transport);
    HttpProxyTransport.prototype.httpRequest = function(params, callback) {
      var url = params.url;
      if (url.indexOf("/") === 0) {
        url = baseUrl + url;
      }
      var proxyParams = {
        method: params.method,
        url: params.url,
        proxy: this._httpProxy,
        headers: {}
      };
      if (params.body || params.body === "") {
        proxyParams.body = params.body;
      }
      if (params.headers) {
        for (var name in params.headers) {
          proxyParams.headers[name] = params.headers[name];
        }
      }
      return HttpProxyTransport.super_.prototype.httpRequest.call(this, proxyParams, callback);
    };
  }
});

// lib/oauth2.js
var require_oauth2 = __commonJS({
  "lib/oauth2.js"(exports2, module2) {
    "use strict";
    var querystring = require("querystring");
    var _ = require("lodash/core");
    var Transport = require_transport();
    var defaults = {
      loginUrl: "https://login.salesforce.com"
    };
    var OAuth2 = module2.exports = function(options) {
      if (options.authzServiceUrl && options.tokenServiceUrl) {
        this.loginUrl = options.authzServiceUrl.split("/").slice(0, 3).join("/");
        this.authzServiceUrl = options.authzServiceUrl;
        this.tokenServiceUrl = options.tokenServiceUrl;
        this.revokeServiceUrl = options.revokeServiceUrl;
      } else {
        this.loginUrl = options.loginUrl || defaults.loginUrl;
        this.authzServiceUrl = this.loginUrl + "/services/oauth2/authorize";
        this.tokenServiceUrl = this.loginUrl + "/services/oauth2/token";
        this.revokeServiceUrl = this.loginUrl + "/services/oauth2/revoke";
      }
      this.clientId = options.clientId;
      this.clientSecret = options.clientSecret;
      this.redirectUri = options.redirectUri;
      if (options.proxyUrl) {
        this._transport = new Transport.ProxyTransport(options.proxyUrl);
      } else if (options.httpProxy) {
        this._transport = new Transport.HttpProxyTransport(options.httpProxy);
      } else {
        this._transport = new Transport();
      }
    };
    _.extend(
      OAuth2.prototype,
      /** @lends OAuth2.prototype **/
      {
        /**
         * Get Salesforce OAuth2 authorization page URL to redirect user agent.
         *
         * @param {Object} params - Parameters
         * @param {String} [params.scope] - Scope values in space-separated string
         * @param {String} [params.state] - State parameter
         * @param {String} [params.code_challenge] - Code challenge value (RFC 7636 - Proof Key of Code Exchange)
         * @returns {String} Authorization page URL
         */
        getAuthorizationUrl: function(params) {
          params = _.extend({
            response_type: "code",
            client_id: this.clientId,
            redirect_uri: this.redirectUri
          }, params || {});
          return this.authzServiceUrl + (this.authzServiceUrl.indexOf("?") >= 0 ? "&" : "?") + querystring.stringify(params);
        },
        /**
         * @typedef TokenResponse
         * @type {Object}
         * @property {String} access_token
         * @property {String} refresh_token
         */
        /**
         * OAuth2 Refresh Token Flow
         *
         * @param {String} refreshToken - Refresh token
         * @param {Callback.<TokenResponse>} [callback] - Callback function
         * @returns {Promise.<TokenResponse>}
         */
        refreshToken: function(refreshToken, callback) {
          var params = {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: this.clientId
          };
          if (this.clientSecret) {
            params.client_secret = this.clientSecret;
          }
          return this._postParams(params, callback);
        },
        /**
         * OAuth2 Web Server Authentication Flow (Authorization Code)
         * Access Token Request
         *
         * @param {String} code - Authorization code
         * @param {Object} [params] - Optional parameters to send in token retrieval
         * @param {String} [params.code_verifier] - Code verifier value (RFC 7636 - Proof Key of Code Exchange)
         * @param {Callback.<TokenResponse>} [callback] - Callback function
         * @returns {Promise.<TokenResponse>}
         */
        requestToken: function(code, params, callback) {
          if (typeof params === "function") {
            callback = params;
            params = {};
          }
          params = _.extend({
            grant_type: "authorization_code",
            code,
            client_id: this.clientId,
            redirect_uri: this.redirectUri
          }, params || {});
          if (this.clientSecret) {
            params.client_secret = this.clientSecret;
          }
          return this._postParams(params, callback);
        },
        /**
         * OAuth2 Username-Password Flow (Resource Owner Password Credentials)
         *
         * @param {String} username - Salesforce username
         * @param {String} password - Salesforce password
         * @param {Callback.<TokenResponse>} [callback] - Callback function
         * @returns {Promise.<TokenResponse>}
         */
        authenticate: function(username, password, callback) {
          return this._postParams({
            grant_type: "password",
            username,
            password,
            client_id: this.clientId,
            client_secret: this.clientSecret,
            redirect_uri: this.redirectUri
          }, callback);
        },
        /**
         * OAuth2 Revoke Session or API Token
         *
         * @param {String} token - Access or Refresh token to revoke. Passing in the Access token revokes the session. Passing in the Refresh token revokes API Access.
         * @param {Callback.<undefined>} [callback] - Callback function
         * @returns {Promise.<undefined>}
         */
        revokeToken: function(token, callback) {
          return this._transport.httpRequest({
            method: "POST",
            url: this.revokeServiceUrl,
            body: querystring.stringify({ token }),
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            }
          }).then(function(response) {
            if (response.statusCode >= 400) {
              var res = querystring.parse(response.body);
              if (!res || !res.error) {
                res = { error: "ERROR_HTTP_" + response.statusCode, error_description: response.body };
              }
              var err = new Error(res.error_description);
              err.name = res.error;
              throw err;
            }
          }).thenCall(callback);
        },
        /**
         * @private
         */
        _postParams: function(params, callback) {
          return this._transport.httpRequest({
            method: "POST",
            url: this.tokenServiceUrl,
            body: querystring.stringify(params),
            headers: {
              "content-type": "application/x-www-form-urlencoded"
            }
          }).then(function(response) {
            var res;
            try {
              res = JSON.parse(response.body);
            } catch (e) {
            }
            if (response.statusCode >= 400) {
              res = res || { error: "ERROR_HTTP_" + response.statusCode, error_description: response.body };
              var err = new Error(res.error_description);
              err.name = res.error;
              throw err;
            }
            return res;
          }).thenCall(callback);
        }
      }
    );
  }
});

// lib/date.js
var require_date = __commonJS({
  "lib/date.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var SfDate = module2.exports = function(literal2) {
      this._literal = literal2;
    };
    SfDate.prototype.toString = SfDate.prototype.toJSON = function() {
      return this._literal;
    };
    function zeropad(n) {
      return (n < 10 ? "0" : "") + n;
    }
    SfDate.toDateLiteral = function(date) {
      if (_.isNumber(date)) {
        date = new Date(date);
      } else if (_.isString(date)) {
        date = SfDate.parseDate(date);
      }
      var yy = date.getFullYear();
      var mm = date.getMonth() + 1;
      var dd = date.getDate();
      var dstr = [yy, zeropad(mm), zeropad(dd)].join("-");
      return new SfDate(dstr);
    };
    SfDate.toDateTimeLiteral = function(date) {
      if (_.isNumber(date)) {
        date = new Date(date);
      } else if (_.isString(date)) {
        date = SfDate.parseDate(date);
      }
      var yy = date.getUTCFullYear();
      var mm = date.getUTCMonth() + 1;
      var dd = date.getUTCDate();
      var hh = date.getUTCHours();
      var mi = date.getUTCMinutes();
      var ss = date.getUTCSeconds();
      var dtstr = [yy, zeropad(mm), zeropad(dd)].join("-") + "T" + [zeropad(hh), zeropad(mi), zeropad(ss)].join(":") + "Z";
      return new SfDate(dtstr);
    };
    SfDate.parseDate = function(str) {
      var d = /* @__PURE__ */ new Date();
      var regexp = /^([\d]{4})-?([\d]{2})-?([\d]{2})(T([\d]{2}):?([\d]{2}):?([\d]{2})(.([\d]{3}))?(Z|([\+\-])([\d]{2}):?([\d]{2})))?$/;
      var m = str.match(regexp);
      if (m) {
        d = /* @__PURE__ */ new Date(0);
        if (!m[4]) {
          d.setFullYear(parseInt(m[1], 10));
          d.setDate(parseInt(m[3], 10));
          d.setMonth(parseInt(m[2], 10) - 1);
          d.setHours(0);
          d.setMinutes(0);
          d.setSeconds(0);
          d.setMilliseconds(0);
        } else {
          d.setUTCFullYear(parseInt(m[1], 10));
          d.setUTCDate(parseInt(m[3], 10));
          d.setUTCMonth(parseInt(m[2], 10) - 1);
          d.setUTCHours(parseInt(m[5], 10));
          d.setUTCMinutes(parseInt(m[6], 10));
          d.setUTCSeconds(parseInt(m[7], 10));
          d.setUTCMilliseconds(parseInt(m[9] || "0", 10));
          if (m[10] && m[10] !== "Z") {
            var offset = parseInt(m[12], 10) * 60 + parseInt(m[13], 10);
            d.setTime((m[11] === "+" ? -1 : 1) * offset * 60 * 1e3 + d.getTime());
          }
        }
        return d;
      } else {
        throw new Error("Invalid date format is specified : " + str);
      }
    };
    var SfDateLiterals = {
      YESTERDAY: 1,
      TODAY: 1,
      TOMORROW: 1,
      LAST_WEEK: 1,
      THIS_WEEK: 1,
      NEXT_WEEK: 1,
      LAST_MONTH: 1,
      THIS_MONTH: 1,
      NEXT_MONTH: 1,
      LAST_90_DAYS: 1,
      NEXT_90_DAYS: 1,
      LAST_N_DAYS: 2,
      NEXT_N_DAYS: 2,
      NEXT_N_WEEKS: 2,
      LAST_N_WEEKS: 2,
      NEXT_N_MONTHS: 2,
      LAST_N_MONTHS: 2,
      THIS_QUARTER: 1,
      LAST_QUARTER: 1,
      NEXT_QUARTER: 1,
      NEXT_N_QUARTERS: 2,
      LAST_N_QUARTERS: 2,
      THIS_YEAR: 1,
      LAST_YEAR: 1,
      NEXT_YEAR: 1,
      NEXT_N_YEARS: 2,
      LAST_N_YEARS: 2,
      THIS_FISCAL_QUARTER: 1,
      LAST_FISCAL_QUARTER: 1,
      NEXT_FISCAL_QUARTER: 1,
      NEXT_N_FISCAL_QUARTERS: 2,
      LAST_N_FISCAL_QUARTERS: 2,
      THIS_FISCAL_YEAR: 1,
      LAST_FISCAL_YEAR: 1,
      NEXT_FISCAL_YEAR: 1,
      NEXT_N_FISCAL_YEARS: 2,
      LAST_N_FISCAL_YEARS: 2
    };
    for (literal in SfDateLiterals) {
      type = SfDateLiterals[literal];
      SfDate[literal] = type === 1 ? new SfDate(literal) : createLiteralBuilder(literal);
    }
    var type;
    var literal;
    function createLiteralBuilder(literal2) {
      return function(num) {
        return new SfDate(literal2 + ":" + num);
      };
    }
  }
});

// lib/soql-builder.js
var require_soql_builder = __commonJS({
  "lib/soql-builder.js"(exports2) {
    "use strict";
    var _ = require("lodash/core");
    var SfDate = require_date();
    function createSOQL(query) {
      var soql = [
        "SELECT ",
        createFieldsClause(query.fields, query.includes),
        " FROM ",
        query.table
      ].join("");
      var cond = createConditionClause(query.conditions);
      if (cond) {
        soql += " WHERE " + cond;
      }
      var orderby = createOrderByClause(query.sort);
      if (orderby) {
        soql += " ORDER BY " + orderby;
      }
      if (query.limit) {
        soql += " LIMIT " + query.limit;
      }
      if (query.offset) {
        soql += " OFFSET " + query.offset;
      }
      return soql;
    }
    function createFieldsClause(fields, childQueries) {
      childQueries = _.map(_.values(childQueries || {}), function(cquery) {
        return "(" + createSOQL(cquery) + ")";
      });
      return (fields || ["Id"]).concat(childQueries).join(", ");
    }
    function createConditionClause(conditions, operator, depth) {
      if (_.isString(conditions)) {
        return conditions;
      }
      conditions = conditions || [];
      operator = operator || "AND";
      depth = depth || 0;
      if (!isArray(conditions)) {
        conditions = _.keys(conditions).map(function(key) {
          return {
            key,
            value: conditions[key]
          };
        });
      } else {
        conditions = conditions.map(function(cond) {
          var conds = [];
          for (var key in cond) {
            conds.push({
              key,
              value: cond[key]
            });
          }
          return conds.length > 1 ? conds : conds[0];
        });
      }
      conditions = conditions.map(function(cond) {
        var d = depth + 1, op;
        switch (cond.key) {
          case "$or":
          case "$and":
          case "$not":
            if (operator !== "NOT" && conditions.length === 1) {
              d = depth;
            }
            op = cond.key === "$or" ? "OR" : cond.key === "$and" ? "AND" : "NOT";
            return createConditionClause(cond.value, op, d);
          default:
            return createFieldExpression(cond.key, cond.value);
        }
      }).filter(function(expr) {
        return expr;
      });
      var paren;
      if (operator === "NOT") {
        paren = depth > 0;
        return (paren ? "(" : "") + "NOT " + conditions[0] + (paren ? ")" : "");
      } else {
        paren = depth > 0 && conditions.length > 1;
        return (paren ? "(" : "") + conditions.join(" " + operator + " ") + (paren ? ")" : "");
      }
    }
    var opMap = {
      "=": "=",
      "$eq": "=",
      "!=": "!=",
      "$ne": "!=",
      ">": ">",
      "$gt": ">",
      "<": "<",
      "$lt": "<",
      ">=": ">=",
      "$gte": ">=",
      "<=": "<=",
      "$lte": "<=",
      "$like": "LIKE",
      "$nlike": "NOT LIKE",
      "$in": "IN",
      "$nin": "NOT IN",
      "$includes": "INCLUDES",
      "$excludes": "EXCLUDES",
      "$exists": "EXISTS"
    };
    function createFieldExpression(field, value) {
      if (_.isArray(value)) {
        return createOpExpression(field, "$in", value);
      } else if (_.isObject(value)) {
        var expressions = _.map(value, function(v, k) {
          if (k[0] === "$")
            return createOpExpression(field, k, v);
        });
        return expressions.join(" AND ");
      } else
        return createOpExpression(field, "$eq", value);
    }
    function createOpExpression(field, op, value) {
      var sfop = opMap[op];
      if (!sfop || _.isUndefined(value)) {
        return null;
      }
      var valueExpr = createValueExpression(value);
      if (_.isUndefined(valueExpr)) {
        return null;
      }
      switch (sfop) {
        case "NOT LIKE":
          return "(" + ["NOT", field, "LIKE", valueExpr].join(" ") + ")";
        case "EXISTS":
          return [field, value ? "!=" : "=", "null"].join(" ");
        default:
          return [field, sfop, valueExpr].join(" ");
      }
    }
    function createValueExpression(value) {
      if (isArray(value)) {
        return value.length > 0 ? "(" + value.map(createValueExpression).join(", ") + ")" : void 0;
      }
      if (value instanceof SfDate) {
        return value.toString();
      }
      if (_.isString(value)) {
        return "'" + escapeSOQLString(value) + "'";
      }
      if (_.isNumber(value)) {
        return value.toString();
      }
      if (_.isNull(value)) {
        return "null";
      }
      return value;
    }
    function escapeSOQLString(str) {
      return String(str || "").replace(/'/g, "\\'");
    }
    function isArray(a) {
      return _.isObject(a) && _.isFunction(a.pop);
    }
    function createOrderByClause(sort) {
      sort = sort || [];
      if (_.isString(sort)) {
        if (/,|\s+(asc|desc)\s*$/.test(sort)) {
          return sort;
        }
        sort = sort.split(/\s+/).map(function(field) {
          var dir = "ASC";
          var flag = field[0];
          if (flag === "-") {
            dir = "DESC";
            field = field.substring(1);
          } else if (flag === "+") {
            field = field.substring(1);
          }
          return [field, dir];
        });
      } else if (!isArray(sort)) {
        sort = _.keys(sort).map(function(field) {
          var dir = sort[field];
          return [field, dir];
        });
      }
      return sort.map(function(s) {
        var field = s[0], dir = s[1];
        switch (String(dir)) {
          case "DESC":
          case "desc":
          case "descending":
          case "-":
          case "-1":
            dir = "DESC";
            break;
          default:
            dir = "ASC";
        }
        return field + " " + dir;
      }).join(", ");
    }
    exports2.createSOQL = createSOQL;
  }
});

// lib/csv.js
var require_csv = __commonJS({
  "lib/csv.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var csvParse = require("csv-parse/lib/es5");
    var csvParseSync = require("csv-parse/lib/es5/sync");
    var csvStringify = require("csv-stringify");
    var csvStringifySync = require("csv-stringify/lib/sync");
    function parseCSV(str, options) {
      options = _.extend({}, options, { columns: true });
      return csvParseSync(str, options);
    }
    function toCSV(records, options) {
      options = _.extend({}, options, { header: true });
      return csvStringifySync(records, options);
    }
    function parseCSVStream(options) {
      options = _.extend({}, options, { columns: true });
      return csvParse(options);
    }
    function serializeCSVStream(options) {
      options = _.extend({}, options, { header: true });
      return csvStringify(options);
    }
    module2.exports = {
      parseCSV,
      toCSV,
      parseCSVStream,
      serializeCSVStream
    };
  }
});

// lib/record-stream.js
var require_record_stream = __commonJS({
  "lib/record-stream.js"(exports2, module2) {
    "use strict";
    var events = require("events");
    var stream = require("readable-stream");
    var Duplex = stream.Duplex;
    var Transform = stream.Transform;
    var PassThrough = stream.PassThrough;
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var CSV = require_csv();
    var RecordStream = module2.exports = function() {
      RecordStream.super_.call(this, { objectMode: true });
    };
    inherits(RecordStream, Transform);
    RecordStream.prototype._transform = function(record, enc, callback) {
      this.emit("record", record);
      this.push(record);
      callback();
    };
    RecordStream.prototype.map = function(fn) {
      return this.pipe(RecordStream.map(fn));
    };
    RecordStream.prototype.filter = function(fn) {
      return this.pipe(RecordStream.filter(fn));
    };
    var Serializable = RecordStream.Serializable = function() {
      Serializable.super_.call(this);
      this._dataStream = null;
    };
    inherits(Serializable, RecordStream);
    Serializable.prototype.stream = function(type, options) {
      type = type || "csv";
      var converter = DataStreamConverters[type];
      if (!converter) {
        throw new Error("Converting [" + type + "] data stream is not supported.");
      }
      if (!this._dataStream) {
        this._dataStream = new PassThrough();
        this.pipe(converter.serialize(options)).pipe(this._dataStream);
      }
      return this._dataStream;
    };
    var Parsable = RecordStream.Parsable = function() {
      Parsable.super_.call(this);
      this._dataStream = null;
    };
    inherits(Parsable, RecordStream);
    Parsable.prototype.stream = function(type, options) {
      type = type || "csv";
      var converter = DataStreamConverters[type];
      var self = this;
      if (!converter) {
        throw new Error("Converting [" + type + "] data stream is not supported.");
      }
      if (!this._dataStream) {
        this._dataStream = new PassThrough();
        this._parserStream = converter.parse(options).on("error", function(error) {
          self.emit("error", error);
        });
        this._parserStream.pipe(this).pipe(new PassThrough({ objectMode: true, highWaterMark: 500 * 1e3 }));
      }
      return this._dataStream;
    };
    Parsable.prototype.on = function(ev, fn) {
      if (ev === "readable" || ev === "record") {
        this._dataStream.pipe(this._parserStream);
      }
      return Parsable.super_.prototype.on.call(this, ev, fn);
    };
    Parsable.prototype.addListener = Parsable.prototype.on;
    RecordStream.map = function(fn) {
      var mapStream = new RecordStream.Serializable();
      mapStream._transform = function(record, enc, callback) {
        var rec = fn(record) || record;
        this.push(rec);
        callback();
      };
      return mapStream;
    };
    RecordStream.recordMapStream = function(record, noeval) {
      return RecordStream.map(function(rec) {
        var mapped = { Id: rec.Id };
        for (var prop in record) {
          mapped[prop] = noeval ? record[prop] : evalMapping(record[prop], rec);
        }
        return mapped;
      });
      function evalMapping(value, mapping) {
        if (_.isString(value)) {
          var m = /^\$\{(\w+)\}$/.exec(value);
          if (m) {
            return mapping[m[1]];
          }
          return value.replace(/\$\{(\w+)\}/g, function($0, prop) {
            var v = mapping[prop];
            return _.isNull(v) || _.isUndefined(v) ? "" : String(v);
          });
        } else {
          return value;
        }
      }
    };
    RecordStream.filter = function(fn) {
      var filterStream = new RecordStream.Serializable();
      filterStream._transform = function(record, enc, callback) {
        if (fn(record)) {
          this.push(record);
        }
        callback();
      };
      return filterStream;
    };
    function convertRecordForSerialization(record, options) {
      return Object.keys(record).reduce(function(rec, key) {
        var value = rec[key];
        var t = typeof value;
        var urec = {};
        if (key === "attributes") {
          rec = _.extend({}, rec);
          delete rec[key];
        } else if (options.nullValue && value === null) {
          urec[key] = options.nullValue;
          rec = _.extend({}, rec, urec);
        } else if (value !== null && typeof value === "object") {
          var precord = convertRecordForSerialization(value, options);
          rec = Object.keys(precord).reduce(function(prec, pkey) {
            prec[key + "." + pkey] = precord[pkey];
            return prec;
          }, _.extend({}, rec));
        }
        return rec;
      }, record);
    }
    function createPipelineStream(s1, s2) {
      var pipeline = new PassThrough();
      pipeline.on("pipe", function(source) {
        source.unpipe(pipeline);
        source.pipe(s1).pipe(s2);
      });
      pipeline.pipe = function(dest, options) {
        return s2.pipe(dest, options);
      };
      return pipeline;
    }
    var CSVStreamConverter = {
      serialize: function(options) {
        options = options || {};
        return createPipelineStream(
          RecordStream.map(function(record) {
            return convertRecordForSerialization(record, options);
          }),
          CSV.serializeCSVStream(options)
        );
      },
      parse: function(options) {
        return CSV.parseCSVStream(options);
      }
    };
    var DataStreamConverters = RecordStream.DataStreamConverters = {
      csv: CSVStreamConverter
    };
  }
});

// lib/query.js
var require_query = __commonJS({
  "lib/query.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var events = require("events");
    var stream = require("readable-stream");
    var _ = require("lodash/core");
    var Promise2 = require_promise();
    var SfDate = require_date();
    var SOQLBuilder = require_soql_builder();
    var RecordStream = require_record_stream();
    var Query = module2.exports = function(conn, config, options) {
      Query.super_.call(this, { objectMode: true });
      this._conn = conn;
      if (_.isString(config)) {
        this._soql = config;
      } else if (config.locator && config.locator.indexOf("/") >= 0) {
        this._locator = config.locator.split("/").pop();
      } else {
        this._config = config;
        this.select(config.fields);
        if (config.includes) {
          this.include(config.includes);
        }
        if (config.sort) {
          this.sort(config.sort);
        }
      }
      this._options = _.defaults(options || {}, {
        maxFetch: 1e4,
        autoFetch: false,
        scanAll: false,
        responseTarget: ResponseTargets.QueryResult
      });
      this._executed = false;
      this._finished = false;
      this._chaining = false;
      this._deferred = Promise2.defer();
      var self = this;
    };
    inherits(Query, stream.Readable);
    Query.prototype.select = function(fields) {
      if (this._soql) {
        throw Error("Cannot set select fields for the query which has already built SOQL.");
      }
      fields = fields || "*";
      if (_.isString(fields)) {
        fields = fields.split(/\s*,\s*/);
      } else if (_.isObject(fields) && !_.isArray(fields)) {
        var _fields = [];
        for (var k in fields) {
          if (fields[k]) {
            _fields.push(k);
          }
        }
        fields = _fields;
      }
      this._config.fields = fields;
      return this;
    };
    Query.prototype.where = function(conditions) {
      if (this._soql) {
        throw Error("Cannot set where conditions for the query which has already built SOQL.");
      }
      this._config.conditions = conditions;
      return this;
    };
    Query.prototype.limit = function(limit) {
      if (this._soql) {
        throw Error("Cannot set limit for the query which has already built SOQL.");
      }
      this._config.limit = limit;
      return this;
    };
    Query.prototype.skip = Query.prototype.offset = function(offset) {
      if (this._soql) {
        throw Error("Cannot set skip/offset for the query which has already built SOQL.");
      }
      this._config.offset = offset;
      return this;
    };
    Query.prototype.sort = Query.prototype.orderby = function(sort, dir) {
      if (this._soql) {
        throw Error("Cannot set sort for the query which has already built SOQL.");
      }
      if (_.isString(sort) && _.isString(dir)) {
        sort = [[sort, dir]];
      }
      this._config.sort = sort;
      return this;
    };
    Query.prototype.include = function(childRelName, conditions, fields, options) {
      if (this._soql) {
        throw Error("Cannot include child relationship into the query which has already built SOQL.");
      }
      if (_.isObject(childRelName)) {
        var includes = childRelName;
        for (var crname in includes) {
          var config = includes[crname];
          this.include(crname, config.conditions, config.fields, config);
        }
        return;
      }
      var childConfig = {
        table: childRelName,
        conditions,
        fields,
        limit: options && options.limit,
        offset: options && (options.offset || options.skip),
        sort: options && options.sort
      };
      if (!_.isArray(this._config.includes))
        this._config.includes = [];
      this._config.includes.push(childConfig);
      var childQuery = new SubQuery(this._conn, this, childConfig);
      this._children = this._children || [];
      this._children.push(childQuery);
      return childQuery;
    };
    Query.prototype.maxFetch = function(maxFetch) {
      this._options.maxFetch = maxFetch;
      return this;
    };
    Query.prototype.autoFetch = function(autoFetch) {
      this._options.autoFetch = autoFetch;
      return this;
    };
    Query.prototype.scanAll = function(scanAll) {
      this._options.scanAll = scanAll;
      return this;
    };
    var ResponseTargets = Query.ResponseTargets = {};
    ["QueryResult", "Records", "SingleRecord", "Count"].forEach(function(f) {
      ResponseTargets[f] = f;
    });
    Query.prototype.setResponseTarget = function(responseTarget) {
      if (responseTarget in ResponseTargets) {
        this._options.responseTarget = responseTarget;
      }
      return this;
    };
    Query.prototype.run = /**
     * Synonym of Query#execute()
     *
     * @method Query#exec
     * @param {Object} [options] - Query options
     * @param {Boolean} [options.autoFetch] - Using auto fetch mode or not
     * @param {Number} [options.maxFetch] - Max fetching records in auto fetch mode
     * @param {Boolean} [options.scanAll] - Including deleted records for query target or not
     * @param {Object} [options.headers] - Additional HTTP request headers sent in query request
     * @param {Callback.<T>} [callback] - Callback function
     * @returns {Query.<T>}
     */
    Query.prototype.exec = /**
     * Execute query and fetch records from server.
     *
     * @method Query#execute
     * @param {Object} [options] - Query options
     * @param {Boolean} [options.autoFetch] - Using auto fetch mode or not
     * @param {Number} [options.maxFetch] - Max fetching records in auto fetch mode
     * @param {Boolean} [options.scanAll] - Including deleted records for query target or not
     * @param {Object} [options.headers] - Additional HTTP request headers sent in query request
     * @param {Callback.<T>} [callback] - Callback function
     * @returns {Query.<T>}
     */
    Query.prototype.execute = function(options, callback) {
      var self = this;
      var logger = this._conn._logger;
      var deferred = this._deferred;
      if (this._executed) {
        deferred.reject(new Error("re-executing already executed query"));
        return this;
      }
      if (this._finished) {
        deferred.reject(new Error("executing already closed query"));
        return this;
      }
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      options = {
        headers: options.headers || self._options.headers,
        responseTarget: options.responseTarget || self._options.responseTarget,
        autoFetch: options.autoFetch || self._options.autoFetch,
        maxFetch: options.maxFetch || self._options.maxFetch,
        scanAll: options.scanAll || self._options.scanAll
      };
      var promiseCallback = function(err, res) {
        if (_.isFunction(callback)) {
          try {
            res = callback(err, res);
            err = null;
          } catch (e) {
            err = e;
          }
        }
        if (err) {
          deferred.reject(err);
        } else {
          deferred.resolve(res);
        }
      };
      this.once("response", function(res) {
        promiseCallback(null, res);
      });
      this.once("error", function(err) {
        promiseCallback(err);
      });
      this.once("fetch", function() {
        if (options.responseTarget === ResponseTargets.Records && (self._chaining || callback)) {
          logger.debug("--- collecting all fetched records ---");
          var records = [];
          var onRecord = function(record) {
            records.push(record);
          };
          self.on("record", onRecord);
          self.once("end", function() {
            self.removeListener("record", onRecord);
            self.emit("response", records, self);
          });
        }
      });
      this._executed = true;
      logger.debug(">>> Query start >>>");
      this._execute(options).then(function() {
        logger.debug("*** Query finished ***");
      }).fail(function(err) {
        logger.debug("--- Query error ---");
        self.emit("error", err);
      });
      return this;
    };
    Query.prototype._execute = function(options) {
      var self = this;
      var logger = this._conn._logger;
      var responseTarget = options.responseTarget;
      var autoFetch = options.autoFetch;
      var maxFetch = options.maxFetch;
      var scanAll = options.scanAll;
      return Promise2.resolve(
        self._locator ? self._conn._baseUrl() + "/query/" + self._locator : self.toSOQL().then(function(soql) {
          self.totalFetched = 0;
          logger.debug("SOQL = " + soql);
          return self._conn._baseUrl() + "/" + (scanAll ? "queryAll" : "query") + "?q=" + encodeURIComponent(soql);
        })
      ).then(function(url) {
        return self._conn.request({
          method: "GET",
          url,
          headers: options.headers
        });
      }).then(function(data) {
        self.emit("fetch");
        self.totalSize = data.totalSize;
        var res;
        switch (responseTarget) {
          case ResponseTargets.SingleRecord:
            res = data.records && data.records.length > 0 ? data.records[0] : null;
            break;
          case ResponseTargets.Records:
            res = data.records;
            break;
          case ResponseTargets.Count:
            res = data.totalSize;
            break;
          default:
            res = data;
        }
        if (responseTarget !== ResponseTargets.Records) {
          self.emit("response", res, self);
        }
        var numRecords = data.records && data.records.length || 0;
        for (var i = 0; i < numRecords; i++) {
          if (self.totalFetched >= maxFetch) {
            self._finished = true;
            break;
          }
          var record = data.records[i];
          self.push(record);
          self.emit("record", record, self.totalFetched++, self);
        }
        if (data.nextRecordsUrl) {
          self._locator = data.nextRecordsUrl.split("/").pop();
        }
        self._finished = self._finished || data.done || !autoFetch;
        if (self._finished) {
          self.push(null);
        } else {
          self._execute(options);
        }
        return res;
      });
    };
    Query.prototype._read = function(size) {
      if (!this._finished && !this._executed) {
        this.execute({ autoFetch: true });
      }
    };
    Query.prototype.on = function(e, fn) {
      if (e === "record") {
        var self = this;
        this.on("readable", function() {
          while (self.read() !== null) {
          }
        });
      }
      return Query.super_.prototype.on.call(this, e, fn);
    };
    Query.prototype.addListener = Query.prototype.on;
    Query.prototype._expandFields = function() {
      if (this._soql) {
        return Promise2.reject(new Error("Cannot expand fields for the query which has already built SOQL."));
      }
      var self = this;
      var logger = self._conn._logger;
      var conn = this._conn;
      var table = this._config.table;
      var fields = this._config.fields || [];
      logger.debug("_expandFields: table = " + table + ", fields = " + fields.join(", "));
      return Promise2.all([
        Promise2.resolve(self._parent ? findRelationTable(table) : table).then(function(table2) {
          return Promise2.all(
            _.map(fields, function(field) {
              return expandAsteriskField(table2, field);
            })
          ).then(function(expandedFields) {
            self._config.fields = _.flatten(expandedFields);
          });
        }),
        Promise2.all(
          _.map(self._children || [], function(childQuery) {
            return childQuery._expandFields();
          })
        )
      ]);
      function findRelationTable(rname) {
        var ptable = self._parent._config.table;
        logger.debug('finding table for relation "' + rname + '" in "' + ptable + '"...');
        return describeCache(ptable).then(function(sobject) {
          var upperRname = rname.toUpperCase();
          var childRelation = _.find(sobject.childRelationships, function(cr) {
            return (cr.relationshipName || "").toUpperCase() === upperRname;
          });
          return childRelation ? childRelation.childSObject : Promise2.reject(new Error("No child relationship found: " + rname));
        });
      }
      function describeCache(table2) {
        logger.debug("describe cache: " + table2);
        var deferred = Promise2.defer();
        conn.describe$(table2, function(err, sobject) {
          logger.debug("... done.");
          if (err) {
            deferred.reject(err);
          } else {
            deferred.resolve(sobject);
          }
        });
        return deferred.promise;
      }
      function expandAsteriskField(table2, field) {
        logger.debug('expanding field "' + field + '" in "' + table2 + '"...');
        var fpath = field.split(".");
        return fpath[fpath.length - 1] === "*" ? describeCache(table2).then(function(sobject) {
          logger.debug("table " + table2 + "has been described");
          if (fpath.length > 1) {
            var rname = fpath.shift();
            var rfield = _.find(sobject.fields, function(f) {
              return f.relationshipName && f.relationshipName.toUpperCase() === rname.toUpperCase();
            });
            if (rfield) {
              var rtable = rfield.referenceTo.length === 1 ? rfield.referenceTo[0] : "Name";
              return expandAsteriskField(rtable, fpath.join(".")).then(function(fpaths) {
                return _.map(fpaths, function(fpath2) {
                  return rname + "." + fpath2;
                });
              });
            } else {
              return [];
            }
          } else {
            return _.map(sobject.fields, function(f) {
              return f.name;
            });
          }
        }) : Promise2.resolve([field]);
      }
    };
    Query.prototype.explain = function(callback) {
      var self = this;
      var logger = this._conn._logger;
      return self.toSOQL().then(function(soql) {
        logger.debug("SOQL = " + soql);
        var url = "/query/?explain=" + encodeURIComponent(soql);
        return self._conn.request(url);
      }).thenCall(callback);
    };
    Query.prototype.toSOQL = function(callback) {
      var self = this;
      return Promise2.resolve(
        self._soql || self._expandFields().then(function() {
          return SOQLBuilder.createSOQL(self._config);
        })
      ).thenCall(callback);
    };
    Query.prototype.stream = RecordStream.Serializable.prototype.stream;
    Query.prototype.map = RecordStream.prototype.map;
    Query.prototype.filter = RecordStream.prototype.map;
    var DEFAULT_BULK_THRESHOLD = 200;
    Query.prototype["delete"] = Query.prototype.del = Query.prototype.destroy = function(type, options, callback) {
      if (typeof type === "function") {
        callback = type;
        options = {};
        type = null;
      } else if (typeof type === "object" && type !== null) {
        callback = options;
        options = type;
        type = null;
      }
      options = options || {};
      type = type || this._config && this._config.table;
      if (!type) {
        throw new Error("SOQL based query needs SObject type information to bulk delete.");
      }
      var thresholdNum = options.allowBulk === false ? -1 : typeof options.bulkThreshold === "number" ? options.bulkThreshold : (
        // determine threshold if the connection version supports SObject collection API or not
        this._conn._ensureVersion(42) ? DEFAULT_BULK_THRESHOLD : this._conn.maxRequest / 2
      );
      var self = this;
      return new Promise2(function(resolve, reject) {
        var records = [];
        var batch = null;
        var handleRecord = function(rec) {
          if (!rec.Id) {
            self.emit("error", new Error("Queried record does not include Salesforce record ID."));
            return;
          }
          var record = { Id: rec.Id };
          if (batch) {
            batch.write(record);
          } else {
            records.push(record);
            if (thresholdNum < 0 || records.length > thresholdNum) {
              batch = self._conn.sobject(type).deleteBulk().on("response", resolve).on("error", reject);
              records.forEach(function(record2) {
                batch.write(record2);
              });
              records = [];
            }
          }
        };
        var handleEnd = function() {
          if (batch) {
            batch.end();
          } else {
            var ids = records.map(function(record) {
              return record.Id;
            });
            self._conn.sobject(type).destroy(ids, { allowRecursive: true }).then(resolve, reject);
          }
        };
        self.on("data", handleRecord).on("end", handleEnd).on("error", reject);
      }).thenCall(callback);
    };
    Query.prototype.update = function(mapping, type, options, callback) {
      if (typeof type === "function") {
        callback = type;
        options = {};
        type = null;
      } else if (typeof type === "object" && type !== null) {
        callback = options;
        options = type;
        type = null;
      }
      options = options || {};
      type = type || this._config && this._config.table;
      if (!type) {
        throw new Error("SOQL based query needs SObject type information to bulk update.");
      }
      var updateStream = _.isFunction(mapping) ? RecordStream.map(mapping) : RecordStream.recordMapStream(mapping);
      var thresholdNum = options.allowBulk === false ? -1 : typeof options.bulkThreshold === "number" ? options.bulkThreshold : (
        // determine threshold if the connection version supports SObject collection API or not
        this._conn._ensureVersion(42) ? DEFAULT_BULK_THRESHOLD : this._conn.maxRequest / 2
      );
      var self = this;
      return new Promise2(function(resolve, reject) {
        var records = [];
        var batch = null;
        var handleRecord = function(record) {
          if (batch) {
            batch.write(record);
          } else {
            records.push(record);
            if (thresholdNum < 0 || records.length > thresholdNum) {
              batch = self._conn.sobject(type).updateBulk().on("response", resolve).on("error", reject);
              records.forEach(function(record2) {
                batch.write(record2);
              });
              records = [];
            }
          }
        };
        var handleEnd = function() {
          if (batch) {
            batch.end();
          } else {
            self._conn.sobject(type).update(records, { allowRecursive: true }).then(resolve, reject);
          }
        };
        self.on("error", reject).pipe(updateStream).on("data", handleRecord).on("end", handleEnd).on("error", reject);
      }).thenCall(callback);
    };
    Query.prototype.then = function(onResolved, onReject) {
      this._chaining = true;
      if (!this._finished && !this._executed) {
        this.execute();
      }
      return this._deferred.promise.then.apply(this._deferred.promise, arguments);
    };
    Query.prototype.thenCall = function(callback) {
      if (_.isFunction(callback)) {
        this.then(function(res) {
          process.nextTick(function() {
            callback(null, res);
          });
        }, function(err) {
          process.nextTick(function() {
            callback(err);
          });
        });
      }
      return this;
    };
    var SubQuery = function(conn, parent, config) {
      SubQuery.super_.call(this, conn, config);
      this._parent = parent;
    };
    inherits(SubQuery, Query);
    SubQuery.prototype.include = function() {
      throw new Error("Not allowed to include another subquery in subquery.");
    };
    SubQuery.prototype.end = function() {
      return this._parent;
    };
    SubQuery.prototype.run = SubQuery.prototype.exec = SubQuery.prototype.execute = function() {
      return this._parent.execute.apply(this._parent, arguments);
    };
  }
});

// lib/record.js
var require_record = __commonJS({
  "lib/record.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var RecordReference = module2.exports = function(conn, type, id) {
      this._conn = conn;
      this.type = type;
      this.id = id;
    };
    RecordReference.prototype.retrieve = function(options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.retrieve(this.type, this.id, options, callback);
    };
    RecordReference.prototype.update = function(record, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      record = _.clone(record);
      record.Id = this.id;
      return this._conn.update(this.type, record, options, callback);
    };
    RecordReference.prototype["delete"] = /**
     * Synonym of Record#destroy()
     *
     * @method RecordReference#del
     * @param {Callback.<RecordResult>} [callback] - Callback function
     * @returns {Promise.<RecordResult>}
     */
    RecordReference.prototype.del = /**
     * Delete record field
     *
     * @method RecordReference#destroy
     * @param {Object} [options] - Options for rest api.
     * @param {Callback.<RecordResult>} [callback] - Callback function
     * @returns {Promise.<RecordResult>}
     */
    RecordReference.prototype.destroy = function(options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.destroy(this.type, this.id, options, callback);
    };
    RecordReference.prototype.blob = function(fieldName) {
      var url = [this._conn._baseUrl(), "sobjects", this.type, this.id, fieldName].join("/");
      return this._conn.request(url).stream();
    };
  }
});

// lib/cache.js
var require_cache = __commonJS({
  "lib/cache.js"(exports2, module2) {
    "use strict";
    var events = require("events");
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var CacheEntry = function() {
      this.fetching = false;
    };
    inherits(CacheEntry, events.EventEmitter);
    CacheEntry.prototype.get = function(callback) {
      if (!callback) {
        return this._value;
      } else {
        this.once("value", callback);
        if (!_.isUndefined(this._value)) {
          this.emit("value", this._value);
        }
      }
    };
    CacheEntry.prototype.set = function(value) {
      this._value = value;
      this.emit("value", this._value);
    };
    CacheEntry.prototype.clear = function() {
      this.fetching = false;
      delete this._value;
    };
    var Cache = function() {
      this._entries = {};
    };
    Cache.prototype.get = function(key) {
      if (key && this._entries[key]) {
        return this._entries[key];
      } else {
        var entry = new CacheEntry();
        this._entries[key] = entry;
        return entry;
      }
    };
    Cache.prototype.clear = function(key) {
      for (var k in this._entries) {
        if (!key || k.indexOf(key) === 0) {
          this._entries[k].clear();
        }
      }
    };
    function createCacheKey(namespace, args) {
      args = Array.prototype.slice.apply(args);
      return namespace + "(" + _.map(args, function(a) {
        return JSON.stringify(a);
      }).join(",") + ")";
    }
    Cache.prototype.makeResponseCacheable = function(fn, scope, options) {
      var cache = this;
      options = options || {};
      return function() {
        var args = Array.prototype.slice.apply(arguments);
        var callback = args.pop();
        if (!_.isFunction(callback)) {
          args.push(callback);
          callback = null;
        }
        var keys = _.isString(options.key) ? options.key : _.isFunction(options.key) ? options.key.apply(scope, args) : createCacheKey(options.namespace, args);
        if (!Array.isArray(keys)) {
          keys = [keys];
        }
        var entries = [];
        keys.forEach(function(key) {
          var entry = cache.get(key);
          entry.fetching = true;
          entries.push(entry);
        });
        if (callback) {
          args.push(function(err, result) {
            if (Array.isArray(result) && result.length == entries.length) {
              entries.forEach(function(entry, index) {
                entry.set({ error: err, result: result[index] });
              });
            } else {
              entries.forEach(function(entry) {
                entry.set({ error: err, result });
              });
            }
            callback(err, result);
          });
        }
        var ret, error;
        try {
          ret = fn.apply(scope || this, args);
        } catch (e) {
          error = e;
        }
        if (ret && _.isFunction(ret.then)) {
          if (!callback) {
            return ret.then(function(result) {
              if (Array.isArray(result) && result.length == entries.length) {
                entries.forEach(function(entry, index) {
                  entry.set({ error: void 0, result: result[index] });
                });
              } else {
                entries.forEach(function(entry) {
                  entry.set({ error: void 0, result });
                });
              }
              return result;
            }, function(err) {
              if (Array.isArray(err) && err.length == entries.length) {
                entries.forEach(function(entry, index) {
                  entry.set({ error: err[index], result: void 0 });
                });
              } else {
                entries.forEach(function(entry) {
                  entry.set({ error: err, result: void 0 });
                });
              }
              throw err;
            });
          } else {
            return ret;
          }
        } else {
          if (Array.isArray(ret) && ret.length == entries.length) {
            entries.forEach(function(entry, index) {
              entry.set({ error, result: ret[index] });
            });
          } else {
            entries.forEach(function(entry) {
              entry.set({ error, result: ret });
            });
          }
          if (error) {
            throw error;
          }
          return ret;
        }
      };
    };
    Cache.prototype.makeCacheable = function(fn, scope, options) {
      var cache = this;
      options = options || {};
      var $fn = function() {
        var args = Array.prototype.slice.apply(arguments);
        var callback = args.pop();
        if (!_.isFunction(callback)) {
          args.push(callback);
        }
        var key = _.isString(options.key) ? options.key : _.isFunction(options.key) ? options.key.apply(scope, args) : createCacheKey(options.namespace, args);
        var entry = cache.get(key);
        if (!_.isFunction(callback)) {
          var value = entry.get();
          if (!value) {
            throw new Error("Function call result is not cached yet.");
          }
          if (value.error) {
            throw value.error;
          }
          return value.result;
        }
        entry.get(function(value2) {
          callback(value2.error, value2.result);
        });
        if (!entry.fetching) {
          entry.fetching = true;
          args.push(function(err, result) {
            entry.set({ error: err, result });
          });
          fn.apply(scope || this, args);
        }
      };
      $fn.clear = function() {
        var key = _.isString(options.key) ? options.key : _.isFunction(options.key) ? options.key.apply(scope, arguments) : createCacheKey(options.namespace, arguments);
        cache.clear(key);
      };
      return $fn;
    };
    module2.exports = Cache;
  }
});

// lib/quick-action.js
var require_quick_action = __commonJS({
  "lib/quick-action.js"(exports2, module2) {
    "use strict";
    var QuickAction = module2.exports = function(conn, path) {
      this._conn = conn;
      this._path = path;
    };
    QuickAction.prototype.describe = function(callback) {
      var url = this._path + "/describe";
      return this._conn.request(url).thenCall(callback);
    };
    QuickAction.prototype.defaultValues = function(contextId, callback) {
      if (typeof contextId === "function") {
        callback = contextId;
        contextId = null;
      }
      var url = this._path + "/defaultValues";
      if (contextId) {
        url += "/" + contextId;
      }
      return this._conn.request(url).thenCall(callback);
    };
    QuickAction.prototype.execute = function(contextId, record, callback) {
      var body = {
        contextId,
        record
      };
      return this._conn.requestPost(this._path, body).thenCall(callback);
    };
  }
});

// lib/sobject.js
var require_sobject = __commonJS({
  "lib/sobject.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var Record = require_record();
    var Query = require_query();
    var Cache = require_cache();
    var QuickAction = require_quick_action();
    var SObject = module2.exports = function(conn, type) {
      this._conn = conn;
      this.type = type;
      var cacheOptions = { key: "describe." + this.type };
      this.describe$ = conn.cache.makeCacheable(this.describe, this, cacheOptions);
      this.describe = conn.cache.makeResponseCacheable(this.describe, this, cacheOptions);
      cacheOptions = { key: "layouts." + this.type };
      this.layouts$ = conn.cache.makeCacheable(this.layouts, this, cacheOptions);
      this.layouts = conn.cache.makeResponseCacheable(this.layouts, this, cacheOptions);
      cacheOptions = { key: "compactLayouts." + this.type };
      this.compactLayouts$ = conn.cache.makeCacheable(this.compactLayouts, this, cacheOptions);
      this.compactLayouts = conn.cache.makeResponseCacheable(this.compactLayouts, this, cacheOptions);
      cacheOptions = { key: "approvalLayouts." + this.type };
      this.approvalLayouts$ = conn.cache.makeCacheable(this.approvalLayouts, this, cacheOptions);
      this.approvalLayouts = conn.cache.makeResponseCacheable(this.approvalLayouts, this, cacheOptions);
    };
    SObject.prototype.insert = SObject.prototype.create = function(records, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.create(this.type, records, options, callback);
    };
    SObject.prototype.retrieve = function(ids, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.retrieve(this.type, ids, options, callback);
    };
    SObject.prototype.update = function(records, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.update(this.type, records, options, callback);
    };
    SObject.prototype.upsert = function(records, extIdField, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.upsert(this.type, records, extIdField, options, callback);
    };
    SObject.prototype["delete"] = SObject.prototype.del = SObject.prototype.destroy = function(ids, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      return this._conn.destroy(this.type, ids, options, callback);
    };
    SObject.prototype.describe = function(callback) {
      return this._conn.describe(this.type, callback);
    };
    SObject.prototype.record = function(id) {
      return new Record(this._conn, this.type, id);
    };
    SObject.prototype.find = function(conditions, fields, options, callback) {
      if (typeof conditions === "function") {
        callback = conditions;
        conditions = {};
        fields = null;
        options = null;
      } else if (typeof fields === "function") {
        callback = fields;
        fields = null;
        options = null;
      } else if (typeof options === "function") {
        callback = options;
        options = null;
      }
      options = options || {};
      var config = {
        fields,
        includes: options.includes,
        table: this.type,
        conditions,
        limit: options.limit,
        sort: options.sort,
        offset: options.offset || options.skip
      };
      var query = new Query(this._conn, config, options);
      query.setResponseTarget(Query.ResponseTargets.Records);
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    SObject.prototype.findOne = function(conditions, fields, options, callback) {
      if (typeof conditions === "function") {
        callback = conditions;
        conditions = {};
        fields = null;
        options = null;
      } else if (typeof fields === "function") {
        callback = fields;
        fields = null;
        options = null;
      } else if (typeof options === "function") {
        callback = options;
        options = null;
      }
      options = _.extend(options || {}, { limit: 1 });
      var query = this.find(conditions, fields, options);
      query.setResponseTarget(Query.ResponseTargets.SingleRecord);
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    SObject.prototype.select = function(fields, callback) {
      return this.find(null, fields, null, callback);
    };
    SObject.prototype.count = function(conditions, callback) {
      if (typeof conditions === "function") {
        callback = conditions;
        conditions = {};
      }
      var query = this.find(conditions, { "count()": true });
      query.setResponseTarget("Count");
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    SObject.prototype.bulkload = function(operation, options, input, callback) {
      return this._conn.bulk.load(this.type, operation, options, input, callback);
    };
    SObject.prototype.insertBulk = SObject.prototype.createBulk = function(input, callback) {
      return this.bulkload("insert", input, callback);
    };
    SObject.prototype.updateBulk = function(input, callback) {
      return this.bulkload("update", input, callback);
    };
    SObject.prototype.upsertBulk = function(input, extIdField, callback) {
      return this.bulkload("upsert", { extIdField }, input, callback);
    };
    SObject.prototype.deleteBulk = SObject.prototype.destroyBulk = function(input, callback) {
      return this.bulkload("delete", input, callback);
    };
    SObject.prototype.deleteHardBulk = SObject.prototype.destroyHardBulk = function(input, callback) {
      return this.bulkload("hardDelete", input, callback);
    };
    SObject.prototype.recent = function(callback) {
      return this._conn.recent(this.type, callback);
    };
    SObject.prototype.updated = function(start, end, callback) {
      return this._conn.updated(this.type, start, end, callback);
    };
    SObject.prototype.deleted = function(start, end, callback) {
      return this._conn.deleted(this.type, start, end, callback);
    };
    SObject.prototype.layouts = function(layoutName, callback) {
      if (typeof layoutName === "function") {
        callback = layoutName;
        layoutName = null;
      }
      var url = "/sobjects/" + this.type + "/describe/" + (layoutName ? "namedLayouts/" + layoutName : "layouts");
      return this._conn.request(url, callback);
    };
    SObject.prototype.compactLayouts = function(callback) {
      var url = "/sobjects/" + this.type + "/describe/compactLayouts";
      return this._conn.request(url, callback);
    };
    SObject.prototype.approvalLayouts = function(callback) {
      var url = "/sobjects/" + this.type + "/describe/approvalLayouts";
      return this._conn.request(url, callback);
    };
    SObject.prototype.listviews = function(callback) {
      var url = this._conn._baseUrl() + "/sobjects/" + this.type + "/listviews";
      return this._conn.request(url, callback);
    };
    SObject.prototype.listview = function(id) {
      return new ListView(this._conn, this.type, id);
    };
    SObject.prototype.quickActions = function(callback) {
      return this._conn.request("/sobjects/" + this.type + "/quickActions").thenCall(callback);
    };
    SObject.prototype.quickAction = function(actionName) {
      return new QuickAction(this._conn, "/sobjects/" + this.type + "/quickActions/" + actionName);
    };
    var ListView = function(conn, type, id) {
      this._conn = conn;
      this.type = type;
      this.id = id;
    };
    ListView.prototype.results = function(callback) {
      var url = this._conn._baseUrl() + "/sobjects/" + this.type + "/listviews/" + this.id + "/results";
      return this._conn.request(url, callback);
    };
    ListView.prototype.describe = function(options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      var url = this._conn._baseUrl() + "/sobjects/" + this.type + "/listviews/" + this.id + "/describe";
      return this._conn.request({ method: "GET", url, headers: options.headers }, callback);
    };
    ListView.prototype.explain = function(callback) {
      var url = "/query/?explain=" + this.id;
      return this._conn.request(url, callback);
    };
  }
});

// lib/http-api.js
var require_http_api = __commonJS({
  "lib/http-api.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var events = require("events");
    var _ = require("lodash/core");
    var Promise2 = require_promise();
    var HttpApi = function(conn, options) {
      options = options || {};
      this._conn = conn;
      this.on("resume", function(err) {
        conn.emit("resume", err);
      });
      this._responseType = options.responseType;
      this._transport = options.transport || conn._transport;
      this._noContentResponse = options.noContentResponse;
    };
    inherits(HttpApi, events.EventEmitter);
    HttpApi.prototype.request = function(request, callback) {
      var self = this;
      var conn = this._conn;
      var logger = conn._logger;
      var refreshDelegate = this.getRefreshDelegate();
      var lastInstanceUrl = conn.instanceUrl;
      var deferred = Promise2.defer();
      var onResume = function(err) {
        if (err) {
          deferred.reject(err);
          return;
        }
        if (lastInstanceUrl !== conn.instanceUrl) {
          request.url = request.url.replace(lastInstanceUrl, conn.instanceUrl);
        }
        self.request(request).then(function(response) {
          deferred.resolve(response);
        }, function(err2) {
          deferred.reject(err2);
        });
      };
      if (refreshDelegate && refreshDelegate._refreshing) {
        refreshDelegate.once("resume", onResume);
        return deferred.promise.thenCall(callback);
      }
      self.beforeSend(request);
      self.emit("request", request);
      logger.debug("<request> method=" + request.method + ", url=" + request.url);
      var requestTime = Date.now();
      return this._transport.httpRequest(request).then(function(response) {
        var responseTime = Date.now();
        logger.debug("elapsed time : " + (responseTime - requestTime) + "msec");
        logger.debug("<response> status=" + response.statusCode + ", url=" + request.url);
        self.emit("response", response);
        if (self.isSessionExpired(response) && refreshDelegate) {
          refreshDelegate.refresh(requestTime, onResume);
          return deferred.promise;
        }
        if (self.isErrorResponse(response)) {
          var err = self.getError(response);
          throw err;
        }
        return self.getResponseBody(response);
      }, function(err) {
        var responseTime = Date.now();
        logger.debug("elapsed time : " + (responseTime - requestTime) + "msec");
        logger.error(err);
        throw err;
      }).thenCall(callback);
    };
    HttpApi.prototype.getRefreshDelegate = function() {
      return this._conn._refreshDelegate;
    };
    HttpApi.prototype.beforeSend = function(request) {
      request.headers = request.headers || {};
      if (this._conn.accessToken) {
        request.headers.Authorization = "Bearer " + this._conn.accessToken;
      }
      if (this._conn.callOptions) {
        var callOptions = [];
        for (var name in this._conn.callOptions) {
          callOptions.push(name + "=" + this._conn.callOptions[name]);
        }
        request.headers["Sforce-Call-Options"] = callOptions.join(", ");
      }
    };
    HttpApi.prototype.getResponseContentType = function(response) {
      return this._responseType || response.headers && response.headers["content-type"];
    };
    HttpApi.prototype.parseResponseBody = function(response) {
      var contentType = this.getResponseContentType(response);
      var parseBody = /^(text|application)\/xml(;|$)/.test(contentType) ? parseXML : /^application\/json(;|$)/.test(contentType) ? parseJSON : /^text\/csv(;|$)/.test(contentType) ? parseCSV : parseText;
      try {
        return parseBody(response.body);
      } catch (e) {
        return response.body;
      }
    };
    HttpApi.prototype.getResponseBody = function(response) {
      if (response.statusCode === 204) {
        return this._noContentResponse;
      }
      var body = this.parseResponseBody(response);
      var err;
      if (this.hasErrorInResponseBody(body)) {
        err = this.getError(response, body);
        throw err;
      }
      if (response.statusCode === 300) {
        err = new Error("Multiple records found");
        err.name = "MULTIPLE_CHOICES";
        err.content = body;
        throw err;
      }
      return body;
    };
    function parseJSON(str) {
      return JSON.parse(str);
    }
    function parseXML(str) {
      var ret = {};
      require("xml2js").parseString(str, { explicitArray: false }, function(err, result) {
        ret = { error: err, result };
      });
      if (ret.error) {
        throw ret.error;
      }
      return ret.result;
    }
    function parseCSV(str) {
      return require_csv().parseCSV(str);
    }
    function parseText(str) {
      return str;
    }
    HttpApi.prototype.isSessionExpired = function(response) {
      return response.statusCode === 401;
    };
    HttpApi.prototype.isErrorResponse = function(response) {
      return response.statusCode >= 400;
    };
    HttpApi.prototype.hasErrorInResponseBody = function(body) {
      return false;
    };
    HttpApi.prototype.parseError = function(body) {
      var errors = body;
      return _.isArray(errors) ? errors[0] : errors;
    };
    HttpApi.prototype.getError = function(response, body) {
      var error;
      try {
        error = this.parseError(body || this.parseResponseBody(response));
      } catch (e) {
      }
      error = _.isObject(error) && _.isString(error.message) ? error : {
        errorCode: "ERROR_HTTP_" + response.statusCode,
        message: response.body
      };
      var err = new Error(error.message);
      err.name = error.errorCode;
      for (var key in error) {
        err[key] = error[key];
      }
      return err;
    };
    var SessionRefreshDelegate = function(conn, refreshFn) {
      this._conn = conn;
      this._refreshFn = refreshFn;
      this._refreshing = false;
    };
    inherits(SessionRefreshDelegate, events.EventEmitter);
    SessionRefreshDelegate.prototype.refresh = function(since, callback) {
      if (this._lastRefreshedAt > since) {
        return callback();
      }
      var self = this;
      var conn = this._conn;
      var logger = conn._logger;
      self.once("resume", callback);
      if (self._refreshing) {
        return;
      }
      logger.debug("<refresh token>");
      self._refreshing = true;
      return self._refreshFn(conn, function(err, accessToken, res) {
        if (!err) {
          logger.debug("Connection refresh completed.");
          conn.accessToken = accessToken;
          conn.emit("refresh", accessToken, res);
        }
        self._lastRefreshedAt = Date.now();
        self._refreshing = false;
        self.emit("resume", err);
      });
    };
    HttpApi.SessionRefreshDelegate = SessionRefreshDelegate;
    module2.exports = HttpApi;
  }
});

// lib/process.js
var require_process = __commonJS({
  "lib/process.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var Promise2 = require_promise();
    var Conneciton = require_connection();
    var Process = module2.exports = function(conn) {
      this.rule = new ProcessRule(conn);
      this.approval = new ApprovalProcess(conn);
    };
    var ProcessRule = function(conn) {
      this._conn = conn;
    };
    ProcessRule.prototype.list = function(callback) {
      return this._conn.request("/process/rules").then(function(res) {
        return res.rules;
      }).thenCall(callback);
    };
    ProcessRule.prototype.trigger = function(contextIds, callback) {
      contextIds = _.isArray(contextIds) ? contextIds : [contextIds];
      return this._conn.request({
        method: "POST",
        url: "/process/rules/",
        body: JSON.stringify({
          contextIds
        }),
        headers: {
          "content-type": "application/json"
        }
      }).thenCall(callback);
    };
    var ApprovalProcess = function(conn) {
      this._conn = conn;
    };
    ApprovalProcess.prototype.list = function(callback) {
      return this._conn.request("/process/approvals").then(function(res) {
        return res.approvals;
      }).thenCall(callback);
    };
    ApprovalProcess.prototype.request = function(requests, callback) {
      requests = requests.map(function(req) {
        return req._request ? req._request : req;
      });
      return this._conn.request({
        method: "POST",
        url: "/process/approvals",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ requests })
      }).thenCall(callback);
    };
    ApprovalProcess.prototype._createRequest = function(actionType, contextId, comments, options, callback) {
      if (typeof comments === "function") {
        callback = comments;
        options = null;
        comments = null;
      }
      if (typeof options === "function") {
        callback = options;
        options = null;
      }
      options = options || {};
      var request = {
        actionType,
        contextId,
        comments
      };
      _.extend(request, options);
      return new ApprovalProcessRequest(this, request).thenCall(callback);
    };
    ApprovalProcess.prototype.submit = function(contextId, comments, options, callback) {
      return this._createRequest("Submit", contextId, comments, options, callback);
    };
    ApprovalProcess.prototype.approve = function(workitemId, comments, options, callback) {
      return this._createRequest("Approve", workitemId, comments, options, callback);
    };
    ApprovalProcess.prototype.reject = function(workitemId, comments, options, callback) {
      return this._createRequest("Reject", workitemId, comments, options, callback);
    };
    var ApprovalProcessRequest = function(process2, request) {
      this._process = process2;
      this._request = request;
    };
    ApprovalProcessRequest.prototype.then = function(onResolve, onReject) {
      if (!this._promise) {
        this._promise = this._process.request([this]).then(function(rets) {
          return rets[0];
        });
      }
      this._promise.then(onResolve, onReject);
    };
    ApprovalProcessRequest.prototype.thenCall = function(callback) {
      return callback ? this.then(function(res) {
        callback(null, res);
      }, function(err) {
        callback(err);
      }) : this;
    };
  }
});

// lib/connection.js
var require_connection = __commonJS({
  "lib/connection.js"(exports2, module2) {
    "use strict";
    var events = require("events");
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var Promise2 = require_promise();
    var Logger = require_logger();
    var OAuth2 = require_oauth2();
    var Query = require_query();
    var SObject = require_sobject();
    var QuickAction = require_quick_action();
    var HttpApi = require_http_api();
    var Transport = require_transport();
    var Process = require_process();
    var Cache = require_cache();
    var defaults = {
      loginUrl: "https://login.salesforce.com",
      instanceUrl: "",
      version: "42.0"
    };
    var MAX_DML_COUNT = 200;
    var MAX_BATCH_REQUESTS = 25;
    var Connection = module2.exports = function(options) {
      options = options || {};
      this._logger = new Logger(options.logLevel);
      var oauth2 = options.oauth2 || {
        loginUrl: options.loginUrl,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        redirectUri: options.redirectUri,
        proxyUrl: options.proxyUrl,
        httpProxy: options.httpProxy
      };
      this.oauth2 = oauth2 = oauth2 instanceof OAuth2 ? oauth2 : new OAuth2(oauth2);
      this.loginUrl = options.loginUrl || oauth2.loginUrl || defaults.loginUrl;
      this.version = options.version || defaults.version;
      this.maxRequest = options.maxRequest || this.maxRequest || 10;
      if (options.proxyUrl) {
        this._transport = new Transport.ProxyTransport(options.proxyUrl);
      } else if (options.httpProxy) {
        this._transport = new Transport.HttpProxyTransport(options.httpProxy);
      } else {
        this._transport = new Transport();
      }
      this.callOptions = options.callOptions;
      var jsforce = require_core();
      jsforce.emit("connection:new", this);
      this.process = new Process(this);
      this.cache = new Cache();
      var self = this;
      var refreshFn = options.refreshFn;
      if (!refreshFn && this.oauth2.clientId) {
        refreshFn = oauthRefreshFn;
      }
      if (refreshFn) {
        this._refreshDelegate = new HttpApi.SessionRefreshDelegate(this, refreshFn);
      }
      var cacheOptions = {
        key: function(type) {
          return type ? type.type ? "describe." + type.type : "describe." + type : "describe";
        }
      };
      this.describe$ = this.cache.makeCacheable(this.describe, this, cacheOptions);
      this.describe = this.cache.makeResponseCacheable(this.describe, this, cacheOptions);
      this.describeSObject$ = this.describe$;
      this.describeSObject = this.describe;
      var batchCacheOptions = {
        key: function(options2) {
          var types = options2.types;
          var autofetch = options2.autofetch || false;
          var typesToFetch2 = types.length > MAX_BATCH_REQUESTS ? autofetch ? types : types.slice(0, MAX_BATCH_REQUESTS) : types;
          var keys = [];
          typesToFetch2.forEach(function(type) {
            keys.push("describe." + type);
          });
          return keys;
        }
      };
      this.batchDescribe = this.cache.makeResponseCacheable(this.batchDescribe, this, batchCacheOptions);
      this.batchDescribeSObjects = this.batchDescribe;
      cacheOptions = { key: "describeGlobal" };
      this.describeGlobal$ = this.cache.makeCacheable(this.describeGlobal, this, cacheOptions);
      this.describeGlobal = this.cache.makeResponseCacheable(this.describeGlobal, this, cacheOptions);
      this.initialize(options);
    };
    inherits(Connection, events.EventEmitter);
    Connection.prototype.initialize = function(options) {
      if (!options.instanceUrl && options.serverUrl) {
        options.instanceUrl = options.serverUrl.split("/").slice(0, 3).join("/");
      }
      this.instanceUrl = options.instanceUrl || options.serverUrl || this.instanceUrl || defaults.instanceUrl;
      this.accessToken = options.sessionId || options.accessToken || this.accessToken;
      this.refreshToken = options.refreshToken || this.refreshToken;
      if (this.refreshToken && !this._refreshDelegate) {
        throw new Error("Refresh token is specified without oauth2 client information or refresh function");
      }
      this.signedRequest = options.signedRequest && parseSignedRequest(options.signedRequest);
      if (this.signedRequest) {
        this.accessToken = this.signedRequest.client.oauthToken;
        if (Transport.CanvasTransport.supported) {
          this._transport = new Transport.CanvasTransport(this.signedRequest);
        }
      }
      if (options.userInfo) {
        this.userInfo = options.userInfo;
      }
      this.limitInfo = {};
      this.sobjects = {};
      this.cache.clear();
      this.cache.get("describeGlobal").removeAllListeners("value");
      this.cache.get("describeGlobal").on("value", _.bind(function(res) {
        if (res.result) {
          var types = _.map(res.result.sobjects, function(so) {
            return so.name;
          });
          types.forEach(this.sobject, this);
        }
      }, this));
      if (this.tooling) {
        this.tooling.initialize();
      }
      this._sessionType = options.sessionId ? "soap" : "oauth2";
    };
    function oauthRefreshFn(conn, callback) {
      conn.oauth2.refreshToken(conn.refreshToken, function(err, res) {
        if (err) {
          return callback(err);
        }
        var userInfo = parseIdUrl(res.id);
        conn.initialize({
          instanceUrl: res.instance_url,
          accessToken: res.access_token,
          userInfo
        });
        callback(null, res.access_token, res);
      });
    }
    function parseSignedRequest(sr) {
      if (_.isString(sr)) {
        if (sr[0] === "{") {
          return JSON.parse(sr);
        } else {
          var msg = sr.split(".").pop();
          var json = Buffer.from(msg, "base64").toString("utf-8");
          return JSON.parse(json);
        }
        return null;
      }
      return sr;
    }
    Connection.prototype._baseUrl = function() {
      return [this.instanceUrl, "services/data", "v" + this.version].join("/");
    };
    Connection.prototype._normalizeUrl = function(url) {
      if (url[0] === "/") {
        if (url.indexOf("/services/") === 0) {
          return this.instanceUrl + url;
        } else {
          return this._baseUrl() + url;
        }
      } else {
        return url;
      }
    };
    Connection.prototype.request = function(request, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = null;
      }
      options = options || {};
      var self = this;
      if (_.isString(request)) {
        request = { method: "GET", url: request };
      }
      request.url = this._normalizeUrl(request.url);
      var httpApi = new HttpApi(this, options);
      httpApi.on("response", function(response) {
        if (response.headers && response.headers["sforce-limit-info"]) {
          var apiUsage = response.headers["sforce-limit-info"].match(/api\-usage=(\d+)\/(\d+)/);
          if (apiUsage) {
            self.limitInfo = {
              apiUsage: {
                used: parseInt(apiUsage[1], 10),
                limit: parseInt(apiUsage[2], 10)
              }
            };
          }
        }
      });
      return httpApi.request(request).thenCall(callback);
    };
    Connection.prototype.requestGet = function(url, options, callback) {
      var request = {
        method: "GET",
        url
      };
      return this.request(request, options, callback);
    };
    Connection.prototype.requestPost = function(url, body, options, callback) {
      var request = {
        method: "POST",
        url,
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" }
      };
      return this.request(request, options, callback);
    };
    Connection.prototype.requestPut = function(url, body, options, callback) {
      var request = {
        method: "PUT",
        url,
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" }
      };
      return this.request(request, options, callback);
    };
    Connection.prototype.requestPatch = function(url, body, options, callback) {
      var request = {
        method: "PATCH",
        url,
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" }
      };
      return this.request(request, options, callback);
    };
    Connection.prototype.requestDelete = function(url, options, callback) {
      var request = {
        method: "DELETE",
        url
      };
      return this.request(request, options, callback);
    };
    function formatDate(date) {
      function pad(number) {
        if (number < 10) {
          return "0" + number;
        }
        return number;
      }
      return date.getUTCFullYear() + "-" + pad(date.getUTCMonth() + 1) + "-" + pad(date.getUTCDate()) + "T" + pad(date.getUTCHours()) + ":" + pad(date.getUTCMinutes()) + ":" + pad(date.getUTCSeconds()) + "+00:00";
    }
    function parseIdUrl(idUrl) {
      var idUrls = idUrl.split("/");
      var userId = idUrls.pop(), orgId = idUrls.pop();
      return {
        id: userId,
        organizationId: orgId,
        url: idUrl
      };
    }
    Connection.prototype.query = function(soql, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var query = new Query(this, soql, options);
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    Connection.prototype.queryAll = function(soql, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var query = new Query(this, soql, options);
      query.scanAll(true);
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    Connection.prototype.queryMore = function(locator, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var query = new Query(this, { locator }, options);
      if (callback) {
        query.run(callback);
      }
      return query;
    };
    Connection.prototype._ensureVersion = function(majorVersion) {
      var versions = this.version.split(".");
      return parseInt(versions[0], 10) >= majorVersion;
    };
    Connection.prototype._supports = function(feature) {
      switch (feature) {
        case "sobject-collection":
          return this._ensureVersion(42);
        default:
          return false;
      }
    };
    Connection.prototype.retrieve = function(type, ids, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      return (_.isArray(ids) ? this._supports("sobject-collection") ? (
        // check whether SObject collection API is supported
        this._retrieveMany(type, ids, options)
      ) : this._retrieveParallel(type, ids, options) : this._retrieveSingle(type, ids, options)).thenCall(callback);
    };
    Connection.prototype._retrieveSingle = function(type, id, options) {
      if (!id) {
        return Promise2.reject(new Error("Invalid record ID. Specify valid record ID value"));
      }
      var url = [this._baseUrl(), "sobjects", type, id].join("/");
      if (options.fields) {
        url += "?fields=" + options.fields.join(",");
      }
      return this.request({
        method: "GET",
        url,
        headers: options.headers
      });
    };
    Connection.prototype._retrieveParallel = function(type, ids, options) {
      if (ids.length > this.maxRequest) {
        return Promise2.reject(new Error("Exceeded max limit of concurrent call"));
      }
      var self = this;
      return Promise2.all(
        ids.map(function(id) {
          return self._retrieveSingle(type, id, options).catch(function(err) {
            if (options.allOrNone || err.errorCode !== "NOT_FOUND") {
              throw err;
            }
            return null;
          });
        })
      );
    };
    Connection.prototype._retrieveMany = function(type, ids, options) {
      if (ids.length === 0) {
        return Promise2.resolve([]);
      }
      var url = [this._baseUrl(), "composite", "sobjects", type].join("/");
      var self = this;
      return (options.fields ? Promise2.resolve(options.fields) : new Promise2(function(resolve, reject) {
        self.describe$(type, function(err, so) {
          if (err) {
            reject(err);
          } else {
            var fields = so.fields.map(function(field) {
              return field.name;
            });
            resolve(fields);
          }
        });
      })).then(function(fields) {
        return self.request({
          method: "POST",
          url,
          body: JSON.stringify({
            ids,
            fields
          }),
          headers: _.defaults(options.headers || {}, {
            "Content-Type": "application/json"
          })
        });
      });
    };
    Connection.prototype._toRecordResult = function(id, err) {
      var error = {
        statusCode: err.errorCode,
        message: err.message
      };
      if (err.content) {
        error.content = err.content;
      }
      if (err.fields) {
        error.fields = err.fields;
      }
      var result = {
        success: false,
        errors: [error]
      };
      if (id) {
        result.id = id;
      }
      return result;
    };
    Connection.prototype.insert = Connection.prototype.create = function(type, records, options, callback) {
      if (!_.isString(type)) {
        callback = options;
        options = records;
        records = type;
        type = null;
      }
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      return (_.isArray(records) ? this._supports("sobject-collection") ? (
        // check whether SObject collection API is supported
        this._createMany(type, records, options)
      ) : this._createParallel(type, records, options) : this._createSingle(type, records, options)).thenCall(callback);
    };
    Connection.prototype._createSingle = function(type, record, options) {
      var sobjectType = type || record.attributes && record.attributes.type || record.type;
      if (!sobjectType) {
        return Promise2.reject(new Error("No SObject Type defined in record"));
      }
      record = _.clone(record);
      delete record.Id;
      delete record.type;
      delete record.attributes;
      var url = [this._baseUrl(), "sobjects", sobjectType].join("/");
      return this.request({
        method: "POST",
        url,
        body: JSON.stringify(record),
        headers: _.defaults(options.headers || {}, {
          "Content-Type": "application/json"
        })
      });
    };
    Connection.prototype._createParallel = function(type, records, options) {
      if (records.length > this.maxRequest) {
        return Promise2.reject(new Error("Exceeded max limit of concurrent call"));
      }
      var self = this;
      return Promise2.all(
        records.map(function(record) {
          return self._createSingle(type, record, options).catch(function(err) {
            if (options.allOrNone || !err.errorCode) {
              throw err;
            }
            return this._toRecordResult(null, err);
          });
        })
      );
    };
    Connection.prototype._createMany = function(type, records, options) {
      if (records.length === 0) {
        return Promise2.resolve([]);
      }
      if (records.length > MAX_DML_COUNT && options.allowRecursive) {
        var self = this;
        return self._createMany(type, records.slice(0, MAX_DML_COUNT), options).then(function(rets1) {
          return self._createMany(type, records.slice(MAX_DML_COUNT), options).then(function(rets2) {
            return rets1.concat(rets2);
          });
        });
      }
      records = _.map(records, function(record) {
        var sobjectType = type || record.attributes && record.attributes.type || record.type;
        if (!sobjectType) {
          return Promise2.reject(new Error("No SObject Type defined in record"));
        }
        record = _.clone(record);
        delete record.Id;
        delete record.type;
        record.attributes = { type: sobjectType };
        return record;
      });
      var url = [this._baseUrl(), "composite", "sobjects"].join("/");
      return this.request({
        method: "POST",
        url,
        body: JSON.stringify({
          allOrNone: options.allOrNone || false,
          records
        }),
        headers: _.defaults(options.headers || {}, {
          "Content-Type": "application/json"
        })
      });
    };
    Connection.prototype.update = function(type, records, options, callback) {
      if (!_.isString(type)) {
        callback = options;
        options = records;
        records = type;
        type = null;
      }
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      return (_.isArray(records) ? this._supports("sobject-collection") ? (
        // check whether SObject collection API is supported
        this._updateMany(type, records, options)
      ) : this._updateParallel(type, records, options) : this._updateSingle(type, records, options)).thenCall(callback);
    };
    Connection.prototype._updateSingle = function(type, record, options) {
      var id = record.Id;
      if (!id) {
        return Promise2.reject(new Error("Record id is not found in record."));
      }
      var sobjectType = type || record.attributes && record.attributes.type || record.type;
      if (!sobjectType) {
        return Promise2.reject(new Error("No SObject Type defined in record"));
      }
      record = _.clone(record);
      delete record.Id;
      delete record.type;
      delete record.attributes;
      var url = [this._baseUrl(), "sobjects", sobjectType, id].join("/");
      return this.request({
        method: "PATCH",
        url,
        body: JSON.stringify(record),
        headers: _.defaults(options.headers || {}, {
          "Content-Type": "application/json"
        })
      }, {
        noContentResponse: { id, success: true, errors: [] }
      });
    };
    Connection.prototype._updateParallel = function(type, records, options) {
      if (records.length > this.maxRequest) {
        return Promise2.reject(new Error("Exceeded max limit of concurrent call"));
      }
      var self = this;
      return Promise2.all(
        records.map(function(record) {
          return self._updateSingle(type, record, options).catch(function(err) {
            if (options.allOrNone || !err.errorCode) {
              throw err;
            }
            return this._toRecordResult(record.Id, err);
          });
        })
      );
    };
    Connection.prototype._updateMany = function(type, records, options) {
      if (records.length === 0) {
        return Promise2.resolve([]);
      }
      if (records.length > MAX_DML_COUNT && options.allowRecursive) {
        var self = this;
        return self._updateMany(type, records.slice(0, MAX_DML_COUNT), options).then(function(rets1) {
          return self._updateMany(type, records.slice(MAX_DML_COUNT), options).then(function(rets2) {
            return rets1.concat(rets2);
          });
        });
      }
      records = _.map(records, function(record) {
        var id = record.Id;
        if (!id) {
          throw new Error("Record id is not found in record.");
        }
        var sobjectType = type || record.attributes && record.attributes.type || record.type;
        if (!sobjectType) {
          throw new Error("No SObject Type defined in record");
        }
        record = _.clone(record);
        delete record.Id;
        record.id = id;
        delete record.type;
        record.attributes = { type: sobjectType };
        return record;
      });
      var url = [this._baseUrl(), "composite", "sobjects"].join("/");
      return this.request({
        method: "PATCH",
        url,
        body: JSON.stringify({
          allOrNone: options.allOrNone || false,
          records
        }),
        headers: _.defaults(options.headers || {}, {
          "Content-Type": "application/json"
        })
      });
    };
    Connection.prototype.upsert = function(type, records, extIdField, options, callback) {
      if (!_.isString(type)) {
        callback = options;
        options = extIdField;
        extIdField = records;
        records = type;
        type = null;
      }
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      var self = this;
      var isArray = _.isArray(records);
      records = isArray ? records : [records];
      if (records.length > this.maxRequest) {
        return Promise2.reject(new Error("Exceeded max limit of concurrent call")).thenCall(callback);
      }
      return Promise2.all(
        _.map(records, function(record) {
          var sobjectType = type || record.attributes && record.attributes.type || record.type;
          var extId = record[extIdField];
          record = _.clone(record);
          delete record[extIdField];
          delete record.type;
          delete record.attributes;
          var url = [self._baseUrl(), "sobjects", sobjectType, extIdField, extId].join("/");
          return self.request({
            method: "PATCH",
            url,
            body: JSON.stringify(record),
            headers: _.defaults(options.headers || {}, {
              "Content-Type": "application/json"
            })
          }, {
            noContentResponse: { success: true, errors: [] }
          }).catch(function(err) {
            if (!isArray || options.allOrNone || !err.errorCode) {
              throw err;
            }
            return self._toRecordResult(null, err);
          });
        })
      ).then(function(results) {
        return !isArray && _.isArray(results) ? results[0] : results;
      }).thenCall(callback);
    };
    Connection.prototype["delete"] = Connection.prototype.del = Connection.prototype.destroy = function(type, ids, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      return (_.isArray(ids) ? this._supports("sobject-collection") ? (
        // check whether SObject collection API is supported
        this._destroyMany(type, ids, options)
      ) : this._destroyParallel(type, ids, options) : this._destroySingle(type, ids, options)).thenCall(callback);
    };
    Connection.prototype._destroySingle = function(type, id, options) {
      var url = [this._baseUrl(), "sobjects", type, id].join("/");
      return this.request({
        method: "DELETE",
        url,
        headers: options.headers || null
      }, {
        noContentResponse: { id, success: true, errors: [] }
      });
    };
    Connection.prototype._destroyParallel = function(type, ids, options) {
      if (ids.length > this.maxRequest) {
        return Promise2.reject(new Error("Exceeded max limit of concurrent call"));
      }
      var self = this;
      return Promise2.all(
        ids.map(function(id) {
          return self._destroySingle(type, id, options).catch(function(err) {
            if (options.allOrNone || !err.errorCode) {
              throw err;
            }
            return this._toRecordResult(id, err);
          });
        })
      );
    };
    Connection.prototype._destroyMany = function(type, ids, options) {
      if (ids.length === 0) {
        return Promise2.resolve([]);
      }
      if (ids.length > MAX_DML_COUNT && options.allowRecursive) {
        var self = this;
        return self._destroyMany(type, ids.slice(0, MAX_DML_COUNT), options).then(function(rets1) {
          return self._destroyMany(type, ids.slice(MAX_DML_COUNT), options).then(function(rets2) {
            return rets1.concat(rets2);
          });
        });
      }
      var url = [this._baseUrl(), "composite", "sobjects?ids="].join("/") + ids.join(",");
      if (options.allOrNone) {
        url += "&allOrNone=true";
      }
      return this.request({
        method: "DELETE",
        url,
        headers: options.headers || null
      });
    };
    Connection.prototype.search = function(sosl, callback) {
      var url = this._baseUrl() + "/search?q=" + encodeURIComponent(sosl);
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.describe = Connection.prototype.describeSObject = function(type, callback) {
      var name = type.type ? type.type : type;
      var url = [this._baseUrl(), "sobjects", name, "describe"].join("/");
      var headers = type.ifModifiedSince ? { "If-Modified-Since": type.ifModifiedSince } : {};
      return this.request({
        method: "GET",
        url,
        headers
      }).then(function(resp) {
        if (resp === "") {
          return Promise2.resolve(void 0);
        } else {
          return Promise2.resolve(resp);
        }
      }).thenCall(callback);
    };
    Connection.prototype.batchDescribe = Connection.prototype.batchDescribeSObjects = function(options, callback) {
      var self = this;
      var types = options.types;
      var autofetch = options.autofetch || false;
      var maxConcurrentRequests = Math.min(options.maxConcurrentRequests || 15, 15);
      var batches = [];
      do {
        var batch = types.length > MAX_BATCH_REQUESTS ? types.slice(0, MAX_BATCH_REQUESTS) : types;
        batches.push(batch);
        types = types.length > MAX_BATCH_REQUESTS ? types.slice(MAX_BATCH_REQUESTS) : [];
      } while (types.length > 0 && autofetch);
      var requestBatches = [];
      do {
        var requestBatch = batches.length > maxConcurrentRequests ? batches.slice(0, maxConcurrentRequests) : batches;
        requestBatches.push(requestBatch);
        batches = batches.length > maxConcurrentRequests ? batches.slice(maxConcurrentRequests) : [];
      } while (batches.length > 0);
      return self.doBatchDescribeRequestBatches(requestBatches).thenCall(callback);
    };
    Connection.prototype.doBatchDescribeRequestBatches = function(requestBatches) {
      var self = this;
      var sobjects = [];
      var firstBatch = requestBatches.shift();
      return self.doBatchOfBatchDescribeRequests(firstBatch).then(
        function(sobjectArray) {
          sobjectArray.forEach(function(sobject) {
            sobjects.push(sobject);
          });
          if (requestBatches.length > 0) {
            return self.doBatchDescribeRequestBatches(requestBatches).then(
              function(results) {
                results.forEach(function(result) {
                  sobjects.push(result);
                });
                return Promise2.resolve(sobjects);
              }
            );
          } else {
            return Promise2.resolve(sobjects);
          }
        }
      );
    };
    Connection.prototype.doBatchOfBatchDescribeRequests = function(requestBatch) {
      var self = this;
      return Promise2.all(
        requestBatch.map(function(batch) {
          return self.doBatchDescribeRequest(batch);
        })
      ).then(function(results) {
        var sobjects = [];
        results.forEach(function(sobjectArray) {
          sobjectArray.forEach(function(sobject) {
            sobjects.push(sobject);
          });
        });
        return Promise2.resolve(sobjects);
      });
    };
    Connection.prototype.doBatchDescribeRequest = function(types) {
      var self = this;
      var sobjects = [];
      var url = [self._baseUrl(), "composite/batch"].join("/");
      var version = "v" + self.version;
      var batchRequests = [];
      types.forEach(function(type) {
        batchRequests.push({
          method: "GET",
          url: [version, "sobjects", type, "describe"].join("/")
        });
      });
      return this.request({
        method: "POST",
        url,
        body: JSON.stringify({ batchRequests }),
        headers: {
          "Content-Type": "application/json"
        }
      }).then(function(response) {
        if (response.results) {
          var i = 0;
          for (var i = 0; i < response.results.length; i++) {
            var subResp = response.results[i];
            if (Array.isArray(subResp.result)) {
              if (subResp.result[0].errorCode && subResp.result[0].message) {
                this._logger.error(
                  "Error: " + subResp.result[0].errorCode + " " + subResp.result[0].message + " - " + typesToFetch[i]
                );
              }
            } else {
              sobjects.push(subResp.result);
            }
          }
        }
        return Promise2.resolve(sobjects);
      });
    };
    Connection.prototype.describeGlobal = function(callback) {
      var url = this._baseUrl() + "/sobjects";
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.sobject = function(type) {
      this.sobjects = this.sobjects || {};
      var sobject = this.sobjects[type] = this.sobjects[type] || new SObject(this, type);
      return sobject;
    };
    Connection.prototype.identity = function(options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      }
      options = options || {};
      var self = this;
      var idUrl = this.userInfo && this.userInfo.url;
      return Promise2.resolve(
        idUrl ? { identity: idUrl } : this.request({ method: "GET", url: this._baseUrl(), headers: options.headers })
      ).then(function(res) {
        var url = res.identity;
        return self.request({ method: "GET", url });
      }).then(function(res) {
        self.userInfo = {
          id: res.user_id,
          organizationId: res.organization_id,
          url: res.id
        };
        return res;
      }).thenCall(callback);
    };
    Connection.prototype.authorize = function(code, params, callback) {
      if (typeof params === "function") {
        callback = params;
        params = {};
      }
      var self = this;
      var logger = this._logger;
      return this.oauth2.requestToken(code, params).then(function(res) {
        var userInfo = parseIdUrl(res.id);
        self.initialize({
          instanceUrl: res.instance_url,
          accessToken: res.access_token,
          refreshToken: res.refresh_token,
          userInfo
        });
        logger.debug("<login> completed. user id = " + userInfo.id + ", org id = " + userInfo.organizationId);
        return userInfo;
      }).thenCall(callback);
    };
    Connection.prototype.login = function(username, password, callback) {
      this._refreshDelegate = new HttpApi.SessionRefreshDelegate(this, createUsernamePasswordRefreshFn(username, password));
      if (this.oauth2 && this.oauth2.clientId && this.oauth2.clientSecret) {
        return this.loginByOAuth2(username, password, callback);
      } else {
        return this.loginBySoap(username, password, callback);
      }
    };
    function createUsernamePasswordRefreshFn(username, password) {
      return function(conn, callback) {
        conn.login(username, password, function(err) {
          if (err) {
            return callback(err);
          }
          callback(null, conn.accessToken);
        });
      };
    }
    Connection.prototype.loginByOAuth2 = function(username, password, callback) {
      var self = this;
      var logger = this._logger;
      return this.oauth2.authenticate(username, password).then(function(res) {
        var userInfo = parseIdUrl(res.id);
        self.initialize({
          instanceUrl: res.instance_url,
          accessToken: res.access_token,
          userInfo
        });
        logger.debug("<login> completed. user id = " + userInfo.id + ", org id = " + userInfo.organizationId);
        return userInfo;
      }).thenCall(callback);
    };
    function esc(str) {
      return str && String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
    Connection.prototype.loginBySoap = function(username, password, callback) {
      var self = this;
      var logger = this._logger;
      var body = [
        '<se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/">',
        "<se:Header/>",
        "<se:Body>",
        '<login xmlns="urn:partner.soap.sforce.com">',
        "<username>" + esc(username) + "</username>",
        "<password>" + esc(password) + "</password>",
        "</login>",
        "</se:Body>",
        "</se:Envelope>"
      ].join("");
      var soapLoginEndpoint = [this.loginUrl, "services/Soap/u", this.version].join("/");
      return this._transport.httpRequest({
        method: "POST",
        url: soapLoginEndpoint,
        body,
        headers: {
          "Content-Type": "text/xml",
          "SOAPAction": '""'
        }
      }).then(function(response) {
        var m;
        if (response.statusCode >= 400) {
          m = response.body.match(/<faultstring>([^<]+)<\/faultstring>/);
          var faultstring = m && m[1];
          throw new Error(faultstring || response.body);
        }
        logger.debug("SOAP response = " + response.body);
        m = response.body.match(/<serverUrl>([^<]+)<\/serverUrl>/);
        var serverUrl = m && m[1];
        m = response.body.match(/<sessionId>([^<]+)<\/sessionId>/);
        var sessionId = m && m[1];
        m = response.body.match(/<userId>([^<]+)<\/userId>/);
        var userId = m && m[1];
        m = response.body.match(/<organizationId>([^<]+)<\/organizationId>/);
        var orgId = m && m[1];
        var idUrl = soapLoginEndpoint.split("/").slice(0, 3).join("/");
        idUrl += "/id/" + orgId + "/" + userId;
        var userInfo = {
          id: userId,
          organizationId: orgId,
          url: idUrl
        };
        self.initialize({
          serverUrl: serverUrl.split("/").slice(0, 3).join("/"),
          sessionId,
          userInfo
        });
        logger.debug("<login> completed. user id = " + userId + ", org id = " + orgId);
        return userInfo;
      }).thenCall(callback);
    };
    Connection.prototype.logout = function(revoke, callback) {
      if (typeof revoke === "function") {
        callback = revoke;
        revoke = false;
      }
      if (this._sessionType === "oauth2") {
        return this.logoutByOAuth2(revoke, callback);
      } else {
        return this.logoutBySoap(revoke, callback);
      }
    };
    Connection.prototype.logoutByOAuth2 = function(revoke, callback) {
      if (typeof revoke === "function") {
        callback = revoke;
        revoke = false;
      }
      var self = this;
      var logger = this._logger;
      return this.oauth2.revokeToken(revoke ? this.refreshToken : this.accessToken).then(function() {
        self.accessToken = null;
        self.userInfo = null;
        self.refreshToken = null;
        self.instanceUrl = null;
        self.cache.clear();
        return void 0;
      }).thenCall(callback);
    };
    Connection.prototype.logoutBySoap = function(revoke, callback) {
      if (typeof revoke === "function") {
        callback = revoke;
        revoke = false;
      }
      var self = this;
      var logger = this._logger;
      var body = [
        '<se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/">',
        "<se:Header>",
        '<SessionHeader xmlns="urn:partner.soap.sforce.com">',
        "<sessionId>" + esc(revoke ? this.refreshToken : this.accessToken) + "</sessionId>",
        "</SessionHeader>",
        "</se:Header>",
        "<se:Body>",
        '<logout xmlns="urn:partner.soap.sforce.com"/>',
        "</se:Body>",
        "</se:Envelope>"
      ].join("");
      return this._transport.httpRequest({
        method: "POST",
        url: [this.instanceUrl, "services/Soap/u", this.version].join("/"),
        body,
        headers: {
          "Content-Type": "text/xml",
          "SOAPAction": '""'
        }
      }).then(function(response) {
        logger.debug("SOAP statusCode = " + response.statusCode + ", response = " + response.body);
        if (response.statusCode >= 400) {
          var m = response.body.match(/<faultstring>([^<]+)<\/faultstring>/);
          var faultstring = m && m[1];
          throw new Error(faultstring || response.body);
        }
        self.accessToken = null;
        self.userInfo = null;
        self.refreshToken = null;
        self.instanceUrl = null;
        self.cache.clear();
        return void 0;
      }).thenCall(callback);
    };
    Connection.prototype.recent = function(type, limit, callback) {
      if (!_.isString(type)) {
        callback = limit;
        limit = type;
        type = void 0;
      }
      if (!_.isNumber(limit)) {
        callback = limit;
        limit = void 0;
      }
      var url;
      if (type) {
        url = [this._baseUrl(), "sobjects", type].join("/");
        return this.request(url).then(function(res) {
          return limit ? res.recentItems.slice(0, limit) : res.recentItems;
        }).thenCall(callback);
      } else {
        url = this._baseUrl() + "/recent";
        if (limit) {
          url += "?limit=" + limit;
        }
        return this.request(url).thenCall(callback);
      }
    };
    Connection.prototype.updated = function(type, start, end, callback) {
      var url = [this._baseUrl(), "sobjects", type, "updated"].join("/");
      if (typeof start === "string") {
        start = new Date(start);
      }
      if (start instanceof Date) {
        start = formatDate(start);
      }
      if (start) {
        url += "?start=" + encodeURIComponent(start);
      }
      if (typeof end === "string") {
        end = new Date(end);
      }
      if (end instanceof Date) {
        end = formatDate(end);
      }
      if (end) {
        url += "&end=" + encodeURIComponent(end);
      }
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.deleted = function(type, start, end, callback) {
      var url = [this._baseUrl(), "sobjects", type, "deleted"].join("/");
      if (typeof start === "string") {
        start = new Date(start);
      }
      if (start instanceof Date) {
        start = formatDate(start);
      }
      if (start) {
        url += "?start=" + encodeURIComponent(start);
      }
      if (typeof end === "string") {
        end = new Date(end);
      }
      if (end instanceof Date) {
        end = formatDate(end);
      }
      if (end) {
        url += "&end=" + encodeURIComponent(end);
      }
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.tabs = function(callback) {
      var url = [this._baseUrl(), "tabs"].join("/");
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.limits = function(callback) {
      var url = [this._baseUrl(), "limits"].join("/");
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.theme = function(callback) {
      var url = [this._baseUrl(), "theme"].join("/");
      return this.request(url).thenCall(callback);
    };
    Connection.prototype.quickActions = function(callback) {
      return this.request("/quickActions").thenCall(callback);
    };
    Connection.prototype.quickAction = function(actionName) {
      return new QuickAction(this, "/quickActions/" + actionName);
    };
  }
});

// lib/soap.js
var require_soap = __commonJS({
  "lib/soap.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var xml2js = require("xml2js");
    var HttpApi = require_http_api();
    var SOAP = module2.exports = function(conn, options) {
      SOAP.super_.apply(this, arguments);
      this._endpointUrl = options.endpointUrl;
      this._xmlns = options.xmlns || "urn:partner.soap.sforce.com";
    };
    inherits(SOAP, HttpApi);
    SOAP.prototype.invoke = function(method, args, schema, callback) {
      if (typeof schema === "function") {
        callback = schema;
        schema = null;
      }
      var message = {};
      message[method] = args;
      return this.request({
        method: "POST",
        url: this._endpointUrl,
        headers: {
          "Content-Type": "text/xml",
          "SOAPAction": '""'
        },
        message
      }).then(function(res) {
        return schema ? convertType(res, schema) : res;
      }).thenCall(callback);
    };
    function convertType(value, schema) {
      if (_.isArray(value)) {
        return value.map(function(v) {
          return convertType(v, schema && schema[0]);
        });
      } else if (_.isObject(value)) {
        if (value.$ && value.$["xsi:nil"] === "true") {
          return null;
        } else if (_.isArray(schema)) {
          return [convertType(value, schema[0])];
        } else {
          var o = {};
          for (var key in value) {
            o[key] = convertType(value[key], schema && schema[key]);
          }
          return o;
        }
      } else {
        if (_.isArray(schema)) {
          return [convertType(value, schema[0])];
        } else if (_.isObject(schema)) {
          return {};
        } else {
          switch (schema) {
            case "string":
              return String(value);
            case "number":
              return Number(value);
            case "boolean":
              return value === "true";
            default:
              return value;
          }
        }
      }
    }
    SOAP.prototype.beforeSend = function(request) {
      request.body = this._createEnvelope(request.message);
    };
    SOAP.prototype.isSessionExpired = function(response) {
      return response.statusCode === 500 && /<faultcode>[a-zA-Z]+:INVALID_SESSION_ID<\/faultcode>/.test(response.body);
    };
    SOAP.prototype.parseError = function(body) {
      var error = lookupValue(body, [/:Envelope$/, /:Body$/, /:Fault$/]);
      return {
        errorCode: error.faultcode,
        message: error.faultstring
      };
    };
    SOAP.prototype.getResponseBody = function(response) {
      var body = SOAP.super_.prototype.getResponseBody.call(this, response);
      return lookupValue(body, [/:Envelope$/, /:Body$/, /.+/]);
    };
    function lookupValue(obj, propRegExps) {
      var regexp = propRegExps.shift();
      if (!regexp) {
        return obj;
      } else {
        for (var prop in obj) {
          if (regexp.test(prop)) {
            return lookupValue(obj[prop], propRegExps);
          }
        }
        return null;
      }
    }
    function toXML(name, value) {
      if (_.isObject(name)) {
        value = name;
        name = null;
      }
      if (_.isArray(value)) {
        return _.map(value, function(v2) {
          return toXML(name, v2);
        }).join("");
      } else {
        var attrs = [];
        var elems = [];
        if (_.isObject(value)) {
          for (var k in value) {
            var v = value[k];
            if (k[0] === "@") {
              k = k.substring(1);
              attrs.push(k + '="' + v + '"');
            } else {
              elems.push(toXML(k, v));
            }
          }
          value = elems.join("");
        } else {
          value = String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
        }
        var startTag = name ? "<" + name + (attrs.length > 0 ? " " + attrs.join(" ") : "") + ">" : "";
        var endTag = name ? "</" + name + ">" : "";
        return startTag + value + endTag;
      }
    }
    SOAP.prototype._createEnvelope = function(message) {
      var header = {};
      var conn = this._conn;
      if (conn.accessToken) {
        header.SessionHeader = { sessionId: this._conn.accessToken };
      }
      if (conn.callOptions) {
        header.CallOptions = conn.callOptions;
      }
      return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"',
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"',
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
        '<soapenv:Header xmlns="' + this._xmlns + '">',
        toXML(header),
        "</soapenv:Header>",
        '<soapenv:Body xmlns="' + this._xmlns + '">',
        toXML(message),
        "</soapenv:Body>",
        "</soapenv:Envelope>"
      ].join("");
    };
  }
});

// lib/_required.js
var require_required = __commonJS({
  "lib/_required.js"(exports2, module2) {
    "use strict";
    module2.exports = {
      "inherits": require("inherits"),
      "util": require("util"),
      "events": require("events"),
      "lodash/core": require("lodash/core"),
      "readable-stream": require("readable-stream"),
      "multistream": require("multistream"),
      "./cache": require_cache(),
      "./connection": require_connection(),
      "./core": require_core(),
      "./csv": require_csv(),
      "./date": require_date(),
      "./http-api": require_http_api(),
      "./logger": require_logger(),
      "./oauth2": require_oauth2(),
      "./process": require_process(),
      "./promise": require_promise(),
      "./query": require_query(),
      "./quick-action": require_quick_action(),
      "./record-stream": require_record_stream(),
      "./record": require_record(),
      "./soap": require_soap(),
      "./sobject": require_sobject(),
      "./soql-builder": require_soql_builder(),
      "./transport": require_transport()
    };
  }
});

// lib/require.js
var require_require = __commonJS({
  "lib/require.js"(exports2, module2) {
    "use strict";
    var required = require_required();
    module2.exports = function(name) {
      if (name === "./jsforce" || name === "jsforce") {
        name = "./core";
      }
      var m = required[name];
      if (typeof m === "undefined") {
        throw new Error("Cannot find module '" + name + "'");
      }
      return m;
    };
  }
});

// lib/core.js
var require_core = __commonJS({
  "lib/core.js"(exports2, module2) {
    "use strict";
    var EventEmitter = require("events").EventEmitter;
    var jsforce = module2.exports = new EventEmitter();
    jsforce.Connection = require_connection();
    jsforce.OAuth2 = require_oauth2();
    jsforce.Date = jsforce.SfDate = require_date();
    jsforce.RecordStream = require_record_stream();
    jsforce.Promise = require_promise();
    jsforce.require = require_require();
  }
});

// lib/api/analytics.js
var require_analytics = __commonJS({
  "lib/api/analytics.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var jsforce = require_core();
    var Promise2 = require_promise();
    var ReportInstance = function(report, id) {
      this._report = report;
      this._conn = report._conn;
      this.id = id;
    };
    ReportInstance.prototype.retrieve = function(callback) {
      var conn = this._conn, report = this._report;
      var url = [conn._baseUrl(), "analytics", "reports", report.id, "instances", this.id].join("/");
      return conn.request(url).thenCall(callback);
    };
    var Report = function(conn, id) {
      this._conn = conn;
      this.id = id;
    };
    Report.prototype.describe = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "reports", this.id, "describe"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    Report.prototype["delete"] = Report.prototype.del = Report.prototype.destroy = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "reports", this.id].join("/");
      return this._conn.request({ method: "DELETE", url }).thenCall(callback);
    };
    Report.prototype.clone = function(name, callback) {
      var url = [this._conn._baseUrl(), "analytics", "reports"].join("/");
      url += "?cloneId=" + this.id;
      var data = { reportMetadata: { name } };
      var params = { method: "POST", url, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) };
      return this._conn.request(params).thenCall(callback);
    };
    Report.prototype.explain = function(callback) {
      var url = "/query/?explain=" + this.id;
      return this._conn.request(url).thenCall(callback);
    };
    Report.prototype.run = Report.prototype.exec = Report.prototype.execute = function(options, callback) {
      options = options || {};
      if (_.isFunction(options)) {
        callback = options;
        options = {};
      }
      var url = [this._conn._baseUrl(), "analytics", "reports", this.id].join("/");
      url += "?includeDetails=" + (options.details ? "true" : "false");
      var params = { method: options.metadata ? "POST" : "GET", url };
      if (options.metadata) {
        params.headers = { "Content-Type": "application/json" };
        params.body = JSON.stringify(options.metadata);
      }
      return this._conn.request(params).thenCall(callback);
    };
    Report.prototype.executeAsync = function(options, callback) {
      options = options || {};
      if (_.isFunction(options)) {
        callback = options;
        options = {};
      }
      var url = [this._conn._baseUrl(), "analytics", "reports", this.id, "instances"].join("/");
      if (options.details) {
        url += "?includeDetails=true";
      }
      var params = { method: "POST", url, body: "" };
      if (options.metadata) {
        params.headers = { "Content-Type": "application/json" };
        params.body = JSON.stringify(options.metadata);
      }
      return this._conn.request(params).thenCall(callback);
    };
    Report.prototype.instance = function(id) {
      return new ReportInstance(this, id);
    };
    Report.prototype.instances = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "reports", this.id, "instances"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    var Dashboard = function(conn, id) {
      this._conn = conn;
      this.id = id;
    };
    Dashboard.prototype.describe = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards", this.id, "describe"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    Dashboard.prototype.components = function(componentIds, callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards", this.id].join("/");
      var data = {};
      if (_.isFunction(componentIds)) {
        callback = componentIds;
      } else if (_.isArray(componentIds)) {
        data.componentIds = componentIds;
      } else if (_.isString(componentIds)) {
        data.componentIds = [componentIds];
      }
      var params = { method: "POST", url, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) };
      return this._conn.request(params).thenCall(callback);
    };
    Dashboard.prototype.status = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards", this.id, "status"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    Dashboard.prototype.refresh = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards", this.id].join("/");
      var params = { method: "PUT", url, body: "" };
      return this._conn.request(params).thenCall(callback);
    };
    Dashboard.prototype.clone = function(name, folderid, callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards"].join("/");
      url += "?cloneId=" + this.id;
      var data = {};
      if (_.isObject(name)) {
        data = name;
        callback = folderid;
      } else {
        data.name = name;
        data.folderId = folderid;
      }
      var params = { method: "POST", url, headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) };
      return this._conn.request(params).thenCall(callback);
    };
    Dashboard.prototype["delete"] = Dashboard.prototype.del = Dashboard.prototype.destroy = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards", this.id].join("/");
      return this._conn.request({ method: "DELETE", url }).thenCall(callback);
    };
    var Analytics = function(conn) {
      this._conn = conn;
    };
    Analytics.prototype.report = function(id) {
      return new Report(this._conn, id);
    };
    Analytics.prototype.reports = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "reports"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    Analytics.prototype.dashboard = function(id) {
      return new Dashboard(this._conn, id);
    };
    Analytics.prototype.dashboards = function(callback) {
      var url = [this._conn._baseUrl(), "analytics", "dashboards"].join("/");
      return this._conn.request(url).thenCall(callback);
    };
    jsforce.on("connection:new", function(conn) {
      conn.analytics = new Analytics(conn);
    });
    module2.exports = Analytics;
  }
});

// lib/api/apex.js
var require_apex = __commonJS({
  "lib/api/apex.js"(exports2, module2) {
    "use strict";
    var jsforce = require_core();
    var Apex = function(conn) {
      this._conn = conn;
    };
    Apex.prototype._baseUrl = function() {
      return this._conn.instanceUrl + "/services/apexrest";
    };
    Apex.prototype._createRequestParams = function(method, path, body, options) {
      var params = {
        method,
        url: this._baseUrl() + path
      }, _headers = {};
      if (options && "object" === typeof options["headers"]) {
        _headers = options["headers"];
      }
      if (!/^(GET|DELETE)$/i.test(method)) {
        _headers["Content-Type"] = "application/json";
      }
      params.headers = _headers;
      if (body) {
        var contentType = params.headers["Content-Type"];
        if (!contentType || contentType === "application/json") {
          params.body = JSON.stringify(body);
        } else {
          params.body = body;
        }
      }
      return params;
    };
    Apex.prototype.get = function(path, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      return this._conn.request(this._createRequestParams("GET", path, void 0, options)).thenCall(callback);
    };
    Apex.prototype.post = function(path, body, options, callback) {
      if (typeof body === "function") {
        callback = body;
        body = void 0;
        options = void 0;
      }
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var params = this._createRequestParams("POST", path, body, options);
      return this._conn.request(params).thenCall(callback);
    };
    Apex.prototype.put = function(path, body, options, callback) {
      if (typeof body === "function") {
        callback = body;
        body = void 0;
        options = void 0;
      }
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var params = this._createRequestParams("PUT", path, body, options);
      return this._conn.request(params).thenCall(callback);
    };
    Apex.prototype.patch = function(path, body, options, callback) {
      if (typeof body === "function") {
        callback = body;
        body = void 0;
        options = void 0;
      }
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      var params = this._createRequestParams("PATCH", path, body, options);
      return this._conn.request(params).thenCall(callback);
    };
    Apex.prototype.del = Apex.prototype["delete"] = function(path, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = void 0;
      }
      return this._conn.request(this._createRequestParams("DELETE", path, void 0, options)).thenCall(callback);
    };
    jsforce.on("connection:new", function(conn) {
      conn.apex = new Apex(conn);
    });
    module2.exports = Apex;
  }
});

// lib/api/bulk.js
var require_bulk = __commonJS({
  "lib/api/bulk.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var stream = require("readable-stream");
    var Duplex = stream.Duplex;
    var events = require("events");
    var _ = require("lodash/core");
    var joinStreams = require("multistream");
    var jsforce = require_core();
    var RecordStream = require_record_stream();
    var Promise2 = require_promise();
    var HttpApi = require_http_api();
    var Job = function(bulk, type, operation, options, jobId) {
      this._bulk = bulk;
      this.type = type;
      this.operation = operation;
      this.options = options || {};
      this.id = jobId;
      this.state = this.id ? "Open" : "Unknown";
      this._batches = {};
    };
    inherits(Job, events.EventEmitter);
    Job.prototype.info = function(callback) {
      var self = this;
      if (!this._jobInfo) {
        this._jobInfo = this.check();
      }
      return this._jobInfo.thenCall(callback);
    };
    Job.prototype.open = function(callback) {
      var self = this;
      var bulk = this._bulk;
      var logger = bulk._logger;
      if (!this._jobInfo) {
        var operation = this.operation.toLowerCase();
        if (operation === "harddelete") {
          operation = "hardDelete";
        }
        var body = [
          '<?xml version="1.0" encoding="UTF-8"?>',
          '<jobInfo  xmlns="http://www.force.com/2009/06/asyncapi/dataload">',
          "<operation>" + operation + "</operation>",
          "<object>" + this.type + "</object>",
          this.options.extIdField ? "<externalIdFieldName>" + this.options.extIdField + "</externalIdFieldName>" : "",
          this.options.concurrencyMode ? "<concurrencyMode>" + this.options.concurrencyMode + "</concurrencyMode>" : "",
          this.options.assignmentRuleId ? "<assignmentRuleId>" + this.options.assignmentRuleId + "</assignmentRuleId>" : "",
          "<contentType>CSV</contentType>",
          "</jobInfo>"
        ].join("");
        this._jobInfo = bulk._request({
          method: "POST",
          path: "/job",
          body,
          headers: {
            "Content-Type": "application/xml; charset=utf-8"
          },
          responseType: "application/xml"
        }).then(function(res) {
          self.emit("open", res.jobInfo);
          self.id = res.jobInfo.id;
          self.state = res.jobInfo.state;
          return res.jobInfo;
        }, function(err) {
          self.emit("error", err);
          throw err;
        });
      }
      return this._jobInfo.thenCall(callback);
    };
    Job.prototype.createBatch = function() {
      var batch = new Batch(this);
      var self = this;
      batch.on("queue", function() {
        self._batches[batch.id] = batch;
      });
      return batch;
    };
    Job.prototype.batch = function(batchId) {
      var batch = this._batches[batchId];
      if (!batch) {
        batch = new Batch(this, batchId);
        this._batches[batchId] = batch;
      }
      return batch;
    };
    Job.prototype.check = function(callback) {
      var self = this;
      var bulk = this._bulk;
      var logger = bulk._logger;
      this._jobInfo = this._waitAssign().then(function() {
        return bulk._request({
          method: "GET",
          path: "/job/" + self.id,
          responseType: "application/xml"
        });
      }).then(function(res) {
        logger.debug(res.jobInfo);
        self.id = res.jobInfo.id;
        self.type = res.jobInfo.object;
        self.operation = res.jobInfo.operation;
        self.state = res.jobInfo.state;
        return res.jobInfo;
      });
      return this._jobInfo.thenCall(callback);
    };
    Job.prototype._waitAssign = function(callback) {
      return (this.id ? Promise2.resolve({ id: this.id }) : this.open()).thenCall(callback);
    };
    Job.prototype.list = function(callback) {
      var self = this;
      var bulk = this._bulk;
      var logger = bulk._logger;
      return this._waitAssign().then(function() {
        return bulk._request({
          method: "GET",
          path: "/job/" + self.id + "/batch",
          responseType: "application/xml"
        });
      }).then(function(res) {
        logger.debug(res.batchInfoList.batchInfo);
        var batchInfoList = res.batchInfoList;
        batchInfoList = _.isArray(batchInfoList.batchInfo) ? batchInfoList.batchInfo : [batchInfoList.batchInfo];
        return batchInfoList;
      }).thenCall(callback);
    };
    Job.prototype.close = function() {
      var self = this;
      return this._changeState("Closed").then(function(jobInfo) {
        self.id = null;
        self.emit("close", jobInfo);
        return jobInfo;
      }, function(err) {
        self.emit("error", err);
        throw err;
      });
    };
    Job.prototype.abort = function() {
      var self = this;
      return this._changeState("Aborted").then(function(jobInfo) {
        self.id = null;
        self.emit("abort", jobInfo);
        return jobInfo;
      }, function(err) {
        self.emit("error", err);
        throw err;
      });
    };
    Job.prototype._changeState = function(state, callback) {
      var self = this;
      var bulk = this._bulk;
      var logger = bulk._logger;
      this._jobInfo = this._waitAssign().then(function() {
        var body = [
          '<?xml version="1.0" encoding="UTF-8"?>',
          '<jobInfo xmlns="http://www.force.com/2009/06/asyncapi/dataload">',
          "<state>" + state + "</state>",
          "</jobInfo>"
        ].join("");
        return bulk._request({
          method: "POST",
          path: "/job/" + self.id,
          body,
          headers: {
            "Content-Type": "application/xml; charset=utf-8"
          },
          responseType: "application/xml"
        });
      }).then(function(res) {
        logger.debug(res.jobInfo);
        self.state = res.jobInfo.state;
        return res.jobInfo;
      });
      return this._jobInfo.thenCall(callback);
    };
    var Batch = function(job, batchId) {
      Batch.super_.call(this, { objectMode: true });
      this.job = job;
      this.id = batchId;
      this._bulk = job._bulk;
      this._deferred = Promise2.defer();
      this._setupDataStreams();
    };
    inherits(Batch, stream.Writable);
    Batch.prototype._setupDataStreams = function() {
      var batch = this;
      var converterOptions = { nullValue: "#N/A" };
      this._uploadStream = new RecordStream.Serializable();
      this._uploadDataStream = this._uploadStream.stream("csv", converterOptions);
      this._downloadStream = new RecordStream.Parsable();
      this._downloadDataStream = this._downloadStream.stream("csv", converterOptions);
      this.on("finish", function() {
        batch._uploadStream.end();
      });
      this._uploadDataStream.once("readable", function() {
        batch.job.open().then(function() {
          batch._uploadDataStream.pipe(batch._createRequestStream());
        });
      });
      var dataStream = this._dataStream = new Duplex();
      dataStream._write = function(data, enc, cb) {
        batch._uploadDataStream.write(data, enc, cb);
      };
      dataStream.on("finish", function() {
        batch._uploadDataStream.end();
      });
      this._downloadDataStream.on("readable", function() {
        dataStream.read(0);
      });
      this._downloadDataStream.on("end", function() {
        dataStream.push(null);
      });
      dataStream._read = function(size) {
        var chunk;
        while ((chunk = batch._downloadDataStream.read()) !== null) {
          dataStream.push(chunk);
        }
      };
    };
    Batch.prototype._createRequestStream = function() {
      var batch = this;
      var bulk = batch._bulk;
      var logger = bulk._logger;
      return bulk._request({
        method: "POST",
        path: "/job/" + batch.job.id + "/batch",
        headers: {
          "Content-Type": "text/csv"
        },
        responseType: "application/xml"
      }, function(err, res) {
        if (err) {
          batch.emit("error", err);
        } else {
          logger.debug(res.batchInfo);
          batch.id = res.batchInfo.id;
          batch.emit("queue", res.batchInfo);
        }
      }).stream();
    };
    Batch.prototype._write = function(record, enc, cb) {
      record = _.clone(record);
      if (this.job.operation === "insert") {
        delete record.Id;
      } else if (this.job.operation === "delete") {
        record = { Id: record.Id };
      }
      delete record.type;
      delete record.attributes;
      this._uploadStream.write(record, enc, cb);
    };
    Batch.prototype.stream = function() {
      return this._dataStream;
    };
    Batch.prototype.run = Batch.prototype.exec = Batch.prototype.execute = function(input, callback) {
      var self = this;
      if (typeof input === "function") {
        callback = input;
        input = null;
      }
      if (this._result) {
        throw new Error("Batch already executed.");
      }
      var rdeferred = Promise2.defer();
      this._result = rdeferred.promise;
      this._result.then(function(res) {
        self._deferred.resolve(res);
      }, function(err) {
        self._deferred.reject(err);
      });
      this.once("response", function(res) {
        rdeferred.resolve(res);
      });
      this.once("error", function(err) {
        rdeferred.reject(err);
      });
      if (_.isObject(input) && _.isFunction(input.pipe)) {
        input.pipe(this._dataStream);
      } else {
        var data;
        if (_.isArray(input)) {
          _.forEach(input, function(record) {
            Object.keys(record).forEach(function(key) {
              if (typeof record[key] === "boolean") {
                record[key] = String(record[key]);
              }
            });
            self.write(record);
          });
          self.end();
        } else if (_.isString(input)) {
          data = input;
          this._dataStream.write(data, "utf8");
          this._dataStream.end();
        }
      }
      return this.thenCall(callback);
    };
    Batch.prototype.then = function(onResolved, onReject, onProgress) {
      return this._deferred.promise.then(onResolved, onReject, onProgress);
    };
    Batch.prototype.thenCall = function(callback) {
      if (_.isFunction(callback)) {
        this.then(function(res) {
          process.nextTick(function() {
            callback(null, res);
          });
        }, function(err) {
          process.nextTick(function() {
            callback(err);
          });
        });
      }
      return this;
    };
    Batch.prototype.check = function(callback) {
      var self = this;
      var bulk = this._bulk;
      var logger = bulk._logger;
      var jobId = this.job.id;
      var batchId = this.id;
      if (!jobId || !batchId) {
        throw new Error("Batch not started.");
      }
      return bulk._request({
        method: "GET",
        path: "/job/" + jobId + "/batch/" + batchId,
        responseType: "application/xml"
      }).then(function(res) {
        logger.debug(res.batchInfo);
        return res.batchInfo;
      }).thenCall(callback);
    };
    Batch.prototype.poll = function(interval, timeout) {
      var self = this;
      var jobId = this.job.id;
      var batchId = this.id;
      if (!jobId || !batchId) {
        throw new Error("Batch not started.");
      }
      var startTime = (/* @__PURE__ */ new Date()).getTime();
      var poll = function() {
        var now = (/* @__PURE__ */ new Date()).getTime();
        if (startTime + timeout < now) {
          var err = new Error("Polling time out. Job Id = " + jobId + " , batch Id = " + batchId);
          err.name = "PollingTimeout";
          err.jobId = jobId;
          err.batchId = batchId;
          self.emit("error", err);
          return;
        }
        self.check(function(err2, res) {
          if (err2) {
            self.emit("error", err2);
          } else {
            if (res.state === "Failed") {
              if (parseInt(res.numberRecordsProcessed, 10) > 0) {
                self.retrieve();
              } else {
                self.emit("error", new Error(res.stateMessage));
              }
            } else if (res.state === "Completed") {
              self.retrieve();
            } else {
              self.emit("progress", res);
              setTimeout(poll, interval);
            }
          }
        });
      };
      setTimeout(poll, interval);
    };
    Batch.prototype.retrieve = function(callback) {
      var self = this;
      var bulk = this._bulk;
      var jobId = this.job.id;
      var job = this.job;
      var batchId = this.id;
      if (!jobId || !batchId) {
        throw new Error("Batch not started.");
      }
      return job.info().then(function(jobInfo) {
        return bulk._request({
          method: "GET",
          path: "/job/" + jobId + "/batch/" + batchId + "/result"
        });
      }).then(function(res) {
        var results;
        if (job.operation === "query") {
          var conn = bulk._conn;
          var resultIds = res["result-list"].result;
          results = res["result-list"].result;
          results = _.map(_.isArray(results) ? results : [results], function(id) {
            return {
              id,
              batchId,
              jobId
            };
          });
        } else {
          results = _.map(res, function(ret) {
            return {
              id: ret.Id || null,
              success: ret.Success === "true",
              errors: ret.Error ? [ret.Error] : []
            };
          });
        }
        self.emit("response", results);
        return results;
      }).fail(function(err) {
        self.emit("error", err);
        throw err;
      }).thenCall(callback);
    };
    Batch.prototype.result = function(resultId) {
      var jobId = this.job.id;
      var batchId = this.id;
      if (!jobId || !batchId) {
        throw new Error("Batch not started.");
      }
      var resultStream = new RecordStream.Parsable();
      var resultDataStream = resultStream.stream("csv");
      var reqStream = this._bulk._request({
        method: "GET",
        path: "/job/" + jobId + "/batch/" + batchId + "/result/" + resultId,
        responseType: "application/octet-stream"
      }).stream().pipe(resultDataStream);
      return resultStream;
    };
    var BulkApi = function() {
      BulkApi.super_.apply(this, arguments);
    };
    inherits(BulkApi, HttpApi);
    BulkApi.prototype.beforeSend = function(request) {
      request.headers = request.headers || {};
      request.headers["X-SFDC-SESSION"] = this._conn.accessToken;
    };
    BulkApi.prototype.isSessionExpired = function(response) {
      return response.statusCode === 400 && /<exceptionCode>InvalidSessionId<\/exceptionCode>/.test(response.body);
    };
    BulkApi.prototype.hasErrorInResponseBody = function(body) {
      return !!body.error;
    };
    BulkApi.prototype.parseError = function(body) {
      return {
        errorCode: body.error.exceptionCode,
        message: body.error.exceptionMessage
      };
    };
    var Bulk = function(conn) {
      this._conn = conn;
      this._logger = conn._logger;
    };
    Bulk.prototype.pollInterval = 1e3;
    Bulk.prototype.pollTimeout = 1e4;
    Bulk.prototype._request = function(request, callback) {
      var conn = this._conn;
      request = _.clone(request);
      var baseUrl = [conn.instanceUrl, "services/async", conn.version].join("/");
      request.url = baseUrl + request.path;
      var options = { responseType: request.responseType };
      delete request.path;
      delete request.responseType;
      return new BulkApi(this._conn, options).request(request).thenCall(callback);
    };
    Bulk.prototype.load = function(type, operation, options, input, callback) {
      var self = this;
      if (!type || !operation) {
        throw new Error("Insufficient arguments. At least, 'type' and 'operation' are required.");
      }
      if (!_.isObject(options) || options.constructor !== Object) {
        callback = input;
        input = options;
        options = null;
      }
      var job = this.createJob(type, operation, options);
      job.once("error", function(error) {
        if (batch) {
          batch.emit("error", error);
        }
      });
      var batch = job.createBatch();
      var cleanup = function() {
        batch = null;
        job.close();
      };
      var cleanupOnError = function(err) {
        if (err.name !== "PollingTimeout") {
          cleanup();
        }
      };
      batch.on("response", cleanup);
      batch.on("error", cleanupOnError);
      batch.on("queue", function() {
        batch.poll(self.pollInterval, self.pollTimeout);
      });
      return batch.execute(input, callback);
    };
    Bulk.prototype.query = function(soql) {
      var m = soql.replace(/\([\s\S]+\)/g, "").match(/FROM\s+(\w+)/i);
      if (!m) {
        throw new Error("No sobject type found in query, maybe caused by invalid SOQL.");
      }
      var type = m[1];
      var self = this;
      var recordStream = new RecordStream.Parsable();
      var dataStream = recordStream.stream("csv");
      this.load(type, "query", soql).then(function(results) {
        var streams = results.map(function(result) {
          return self.job(result.jobId).batch(result.batchId).result(result.id).stream();
        });
        joinStreams(streams).pipe(dataStream);
      }).fail(function(err) {
        recordStream.emit("error", err);
      });
      return recordStream;
    };
    Bulk.prototype.createJob = function(type, operation, options) {
      return new Job(this, type, operation, options);
    };
    Bulk.prototype.job = function(jobId) {
      return new Job(this, null, null, null, jobId);
    };
    jsforce.on("connection:new", function(conn) {
      conn.bulk = new Bulk(conn);
    });
    module2.exports = Bulk;
  }
});

// lib/api/chatter.js
var require_chatter = __commonJS({
  "lib/api/chatter.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var jsforce = require_core();
    var Promise2 = require_promise();
    var Chatter = module2.exports = function(conn) {
      this._conn = conn;
    };
    Chatter.prototype._request = function(params, callback) {
      if (/^(put|post|patch)$/i.test(params.method)) {
        if (_.isObject(params.body)) {
          params.headers = {
            "Content-Type": "application/json"
          };
          params.body = JSON.stringify(params.body);
        }
      }
      params.url = this._normalizeUrl(params.url);
      return this._conn.request(params, callback);
    };
    Chatter.prototype._normalizeUrl = function(url) {
      if (url.indexOf("/chatter/") === 0 || url.indexOf("/connect/") === 0) {
        return "/services/data/v" + this._conn.version + url;
      } else if (/^\/v[\d]+\.[\d]+\//.test(url)) {
        return "/services/data" + url;
      } else if (url.indexOf("/services/") !== 0 && url[0] === "/") {
        return "/services/data/v" + this._conn.version + "/chatter" + url;
      } else {
        return url;
      }
    };
    Chatter.prototype.request = function(params, callback) {
      return new Request(this, params).thenCall(callback);
    };
    Chatter.prototype.resource = function(url, queryParams) {
      return new Resource(this, url, queryParams);
    };
    Chatter.prototype.batch = function(requests, callback) {
      var self = this;
      var batchRequests = [], batchDeferreds = [];
      _.forEach(requests, function(request) {
        var deferred = Promise2.defer();
        request._promise = deferred.promise;
        batchRequests.push(request.batchParams());
        batchDeferreds.push(deferred);
      });
      var params = {
        method: "POST",
        url: this._normalizeUrl("/connect/batch"),
        body: {
          batchRequests
        }
      };
      return this.request(params).then(function(res) {
        _.forEach(res.results, function(result, i) {
          var deferred = batchDeferreds[i];
          if (result.statusCode >= 400) {
            deferred.reject(result.result);
          } else {
            deferred.resolve(result.result);
          }
        });
        return res;
      }).thenCall(callback);
    };
    var Request = function(chatter, params) {
      this._chatter = chatter;
      this._params = params;
      this._promise = null;
    };
    Request.prototype.batchParams = function() {
      var params = this._params;
      var batchParams = {
        method: params.method,
        url: this._chatter._normalizeUrl(params.url)
      };
      if (this._params.body) {
        batchParams.richInput = this._params.body;
      }
      return batchParams;
    };
    Request.prototype.promise = function() {
      return this._promise || this._chatter._request(this._params);
    };
    Request.prototype.stream = function() {
      return this._chatter._request(this._params).stream();
    };
    Request.prototype.then = function(onResolve, onReject) {
      return this.promise().then(onResolve, onReject);
    };
    Request.prototype.thenCall = function(callback) {
      return _.isFunction(callback) ? this.promise().thenCall(callback) : this;
    };
    var Resource = function(chatter, url, queryParams) {
      if (queryParams) {
        var qstring = _.map(_.keys(queryParams), function(name) {
          return name + "=" + encodeURIComponent(queryParams[name]);
        }).join("&");
        url += (url.indexOf("?") > 0 ? "&" : "?") + qstring;
      }
      Resource.super_.call(this, chatter, { method: "GET", url });
      this._url = url;
    };
    inherits(Resource, Request);
    Resource.prototype.create = function(data, callback) {
      return this._chatter.request({
        method: "POST",
        url: this._url,
        body: data
      }).thenCall(callback);
    };
    Resource.prototype.retrieve = function(callback) {
      return this.thenCall(callback);
    };
    Resource.prototype.update = function(data, callback) {
      return this._chatter.request({
        method: "PATCH",
        url: this._url,
        body: data
      }).thenCall(callback);
    };
    Resource.prototype.del = Resource.prototype["delete"] = function(callback) {
      return this._chatter.request({
        method: "DELETE",
        url: this._url
      }).thenCall(callback);
    };
    jsforce.on("connection:new", function(conn) {
      conn.chatter = new Chatter(conn);
    });
  }
});

// lib/api/metadata.js
var require_metadata = __commonJS({
  "lib/api/metadata.js"(exports2, module2) {
    "use strict";
    var inherits = require("inherits");
    var events = require("events");
    var stream = require("readable-stream");
    var _ = require("lodash/core");
    var jsforce = require_core();
    var Promise2 = require_promise();
    var SOAP = require_soap();
    var Metadata = module2.exports = function(conn) {
      this._conn = conn;
    };
    Metadata.prototype.pollInterval = 1e3;
    Metadata.prototype.pollTimeout = 1e4;
    Metadata.prototype._invoke = function(method, message, callback) {
      var soapEndpoint = new SOAP(this._conn, {
        xmlns: "http://soap.sforce.com/2006/04/metadata",
        endpointUrl: this._conn.instanceUrl + "/services/Soap/m/" + this._conn.version
      });
      return soapEndpoint.invoke(method, message).then(function(res) {
        return res.result;
      }).thenCall(callback);
    };
    Metadata.prototype.createAsync = function(type, metadata, callback) {
      if (Number(this._conn.version) > 30) {
        throw new Error("Async metadata CRUD calls are not supported on ver 31.0 or later.");
      }
      var convert = function(md) {
        md["@xsi:type"] = type;
        return md;
      };
      var isArray = _.isArray(metadata);
      metadata = isArray ? _.map(metadata, convert) : convert(metadata);
      var res = this._invoke("create", { metadata });
      return new AsyncResultLocator(this, res, isArray).thenCall(callback);
    };
    function convertToSaveResult(result) {
      var saveResult = _.clone(result);
      saveResult.success = saveResult.success === "true";
      return saveResult;
    }
    function convertToUpsertResult(result) {
      var upsertResult = convertToSaveResult(result);
      upsertResult.created = upsertResult.created === "true";
      return upsertResult;
    }
    Metadata.prototype.createSync = Metadata.prototype.create = function(type, metadata, callback) {
      var convert = function(md) {
        md["@xsi:type"] = type;
        return md;
      };
      var isArray = _.isArray(metadata);
      metadata = isArray ? _.map(metadata, convert) : convert(metadata);
      return this._invoke("createMetadata", { metadata }).then(function(results) {
        return _.isArray(results) ? _.map(results, convertToSaveResult) : convertToSaveResult(results);
      }).thenCall(callback);
    };
    function convertToMetadataInfo(rec) {
      var metadataInfo = _.clone(rec);
      delete metadataInfo.$;
      return metadataInfo;
    }
    Metadata.prototype.readSync = Metadata.prototype.read = function(type, fullNames, callback) {
      return this._invoke("readMetadata", { type, fullNames }).then(function(res) {
        return _.isArray(res.records) ? _.map(res.records, convertToMetadataInfo) : convertToMetadataInfo(res.records);
      }).thenCall(callback);
    };
    Metadata.prototype.updateAsync = function(type, updateMetadata, callback) {
      if (Number(this._conn.version) > 30) {
        throw new Error("Async metadata CRUD calls are not supported on ver 31.0 or later.");
      }
      var convert = function(umd) {
        umd.metadata["@xsi:type"] = type;
        return umd;
      };
      var isArray = _.isArray(updateMetadata);
      updateMetadata = isArray ? _.map(updateMetadata, convert) : convert(updateMetadata);
      var res = this._invoke("update", { updateMetadata });
      return new AsyncResultLocator(this, res, isArray).thenCall(callback);
    };
    Metadata.prototype.updateSync = Metadata.prototype.update = function(type, metadata, callback) {
      var convert = function(md) {
        md["@xsi:type"] = type;
        return md;
      };
      var isArray = _.isArray(metadata);
      metadata = isArray ? _.map(metadata, convert) : convert(metadata);
      return this._invoke("updateMetadata", { metadata }).then(function(results) {
        return _.isArray(results) ? _.map(results, convertToSaveResult) : convertToSaveResult(results);
      }).thenCall(callback);
    };
    Metadata.prototype.upsertSync = Metadata.prototype.upsert = function(type, metadata, callback) {
      var convert = function(md) {
        md["@xsi:type"] = type;
        return md;
      };
      var isArray = _.isArray(metadata);
      metadata = isArray ? _.map(metadata, convert) : convert(metadata);
      return this._invoke("upsertMetadata", { metadata }).then(function(results) {
        return _.isArray(results) ? _.map(results, convertToUpsertResult) : convertToUpsertResult(results);
      }).thenCall(callback);
    };
    Metadata.prototype.deleteAsync = function(type, metadata, callback) {
      if (Number(this._conn.version) > 30) {
        throw new Error("Async metadata CRUD calls are not supported on ver 31.0 or later.");
      }
      var convert = function(md) {
        if (_.isString(md)) {
          md = { fullName: md };
        }
        md["@xsi:type"] = type;
        return md;
      };
      var isArray = _.isArray(metadata);
      metadata = isArray ? _.map(metadata, convert) : convert(metadata);
      var res = this._invoke("delete", { metadata });
      return new AsyncResultLocator(this, res, isArray).thenCall(callback);
    };
    Metadata.prototype.del = Metadata.prototype.deleteSync = Metadata.prototype["delete"] = function(type, fullNames, callback) {
      return this._invoke("deleteMetadata", { type, fullNames }).then(function(results) {
        return _.isArray(results) ? _.map(results, convertToSaveResult) : convertToSaveResult(results);
      }).thenCall(callback);
    };
    Metadata.prototype.rename = function(type, oldFullName, newFullName, callback) {
      return this._invoke("renameMetadata", { type, oldFullName, newFullName }).then(function(result) {
        return convertToSaveResult(result);
      }).thenCall(callback);
    };
    Metadata.prototype.checkStatus = function(ids, callback) {
      var isArray = _.isArray(ids);
      var res = this._invoke("checkStatus", { asyncProcessId: ids });
      return new AsyncResultLocator(this, res, isArray).thenCall(callback);
    };
    Metadata.prototype.describe = function(version, callback) {
      if (!_.isString(version)) {
        callback = version;
        version = this._conn.version;
      }
      return this._invoke("describeMetadata", { asOfVersion: version }).then(function(res) {
        res.metadataObjects = _.isArray(res.metadataObjects) ? res.metadataObjects : [res.metadataObjects];
        res.metadataObjects = _.map(res.metadataObjects, function(mo) {
          if (mo.childXmlNames) {
            mo.childXmlNames = _.isArray(mo.childXmlNames) ? mo.childXmlNames : [mo.childXmlNames];
          }
          mo.inFolder = mo.inFolder === "true";
          mo.metaFile = mo.metaFile === "true";
          return mo;
        });
        res.partialSaveAllowed = res.partialSaveAllowed === "true";
        res.testRequired = res.testRequired === "true";
        return res;
      }).thenCall(callback);
    };
    Metadata.prototype.list = function(queries, version, callback) {
      if (!_.isString(version)) {
        callback = version;
        version = this._conn.version;
      }
      if (!_.isArray(queries)) {
        queries = [queries];
      }
      return this._invoke("listMetadata", { queries, asOfVersion: version }, callback);
    };
    Metadata.prototype.retrieve = function(request, callback) {
      var res = this._invoke("retrieve", { request });
      return new RetrieveResultLocator(this, res).thenCall(callback);
    };
    Metadata.prototype.checkRetrieveStatus = function(id, callback) {
      return this._invoke("checkRetrieveStatus", { asyncProcessId: id }, callback);
    };
    Metadata.prototype.deploy = function(zipInput, options, callback) {
      if (!options || _.isFunction(options)) {
        callback = options;
        options = {};
      }
      var deferred = Promise2.defer();
      if (_.isObject(zipInput) && _.isFunction(zipInput.pipe)) {
        var bufs = [];
        zipInput.on("data", function(d) {
          bufs.push(d);
        });
        zipInput.on("end", function() {
          deferred.resolve(Buffer.concat(bufs).toString("base64"));
        });
      } else if (zipInput instanceof Buffer) {
        deferred.resolve(zipInput.toString("base64"));
      } else if (zipInput instanceof String || typeof zipInput === "string") {
        deferred.resolve(zipInput);
      } else {
        throw "Unexpected zipInput type";
      }
      var self = this;
      var res = deferred.promise.then(function(zipContentB64) {
        return self._invoke("deploy", {
          ZipFile: zipContentB64,
          DeployOptions: options
        }, callback);
      });
      return new DeployResultLocator(this, res).thenCall(callback);
    };
    Metadata.prototype.checkDeployStatus = function(id, includeDetails, callback) {
      if (_.isObject(includeDetails) || _.isBoolean(includeDetails)) {
        includeDetails = !!includeDetails;
      } else {
        callback = includeDetails;
        includeDetails = false;
      }
      return this._invoke("checkDeployStatus", {
        asyncProcessId: id,
        includeDetails
      }).then(function(res) {
        res.done = res.done === "true";
        res.success = res.success === "true";
        res.checkOnly = res.checkOnly === "true";
        res.runTestsEnabled = res.runTestsEnabled === "true";
        if (res.ignoreWarnings) {
          res.ignoreWarnings = res.ignoreWarnings === "true";
        }
        if (res.rollbackOnError) {
          res.rollbackOnError = res.rollbackOnError === "true";
        }
        res.numberComponentErrors = Number(res.numberComponentErrors);
        res.numberComponentsDeployed = Number(res.numberComponentsDeployed);
        res.numberComponentsTotal = Number(res.numberComponentsTotal);
        res.numberTestErrors = Number(res.numberTestErrors);
        res.numberTestsCompleted = Number(res.numberTestsCompleted);
        res.numberTestsTotal = Number(res.numberTestsTotal);
        return res;
      }).thenCall(callback);
    };
    var AsyncResultLocator = function(meta, results, isArray) {
      this._meta = meta;
      this._results = results;
      this._isArray = isArray;
    };
    inherits(AsyncResultLocator, events.EventEmitter);
    AsyncResultLocator.prototype.then = function(onResolve, onReject) {
      var self = this;
      return this._results.then(function(results) {
        var convertType = function(res) {
          if (res.$ && res.$["xsi:nil"] === "true") {
            return null;
          }
          res.done = res.done === "true";
          return res;
        };
        results = _.isArray(results) ? _.map(results, convertType) : convertType(results);
        if (self._isArray && !_.isArray(results)) {
          results = [results];
        }
        return onResolve(results);
      }, onReject);
    };
    AsyncResultLocator.prototype.thenCall = function(callback) {
      return _.isFunction(callback) ? this.then(function(res) {
        process.nextTick(function() {
          callback(null, res);
        });
      }, function(err) {
        process.nextTick(function() {
          callback(err);
        });
      }) : this;
    };
    AsyncResultLocator.prototype.check = function(callback) {
      var self = this;
      var meta = this._meta;
      return this.then(function(results) {
        var ids = _.isArray(results) ? _.map(results, function(res) {
          return res.id;
        }) : results.id;
        self._ids = ids;
        return meta.checkStatus(ids);
      }).thenCall(callback);
    };
    AsyncResultLocator.prototype.poll = function(interval, timeout) {
      var self = this;
      var startTime = (/* @__PURE__ */ new Date()).getTime();
      var poll = function() {
        var now = (/* @__PURE__ */ new Date()).getTime();
        if (startTime + timeout < now) {
          var errMsg = "Polling time out.";
          if (self._ids) {
            errMsg += " Process Id = " + self._ids;
          }
          self.emit("error", new Error(errMsg));
          return;
        }
        self.check().then(function(results) {
          var done = true;
          var resultArr = _.isArray(results) ? results : [results];
          for (var i = 0, len = resultArr.length; i < len; i++) {
            var result = resultArr[i];
            if (result && !result.done) {
              self.emit("progress", result);
              done = false;
            }
          }
          if (done) {
            self.emit("complete", results);
          } else {
            setTimeout(poll, interval);
          }
        }, function(err) {
          self.emit("error", err);
        });
      };
      setTimeout(poll, interval);
    };
    AsyncResultLocator.prototype.complete = function(callback) {
      var deferred = Promise2.defer();
      this.on("complete", function(results) {
        deferred.resolve(results);
      });
      this.on("error", function(err) {
        deferred.reject(err);
      });
      var meta = this._meta;
      this.poll(meta.pollInterval, meta.pollTimeout);
      return deferred.promise.thenCall(callback);
    };
    var RetrieveResultLocator = function(meta, result) {
      RetrieveResultLocator.super_.call(this, meta, result);
    };
    inherits(RetrieveResultLocator, AsyncResultLocator);
    RetrieveResultLocator.prototype.complete = function(callback) {
      var meta = this._meta;
      return RetrieveResultLocator.super_.prototype.complete.call(this).then(function(result) {
        return meta.checkRetrieveStatus(result.id);
      }).thenCall(callback);
    };
    RetrieveResultLocator.prototype.stream = function() {
      var self = this;
      var resultStream = new stream.Readable();
      var reading = false;
      resultStream._read = function() {
        if (reading) {
          return;
        }
        reading = true;
        self.complete(function(err, result) {
          if (err) {
            resultStream.emit("error", err);
          } else {
            resultStream.push(Buffer.from(result.zipFile, "base64"));
            resultStream.push(null);
          }
        });
      };
      return resultStream;
    };
    var DeployResultLocator = function(meta, result) {
      DeployResultLocator.super_.call(this, meta, result);
    };
    inherits(DeployResultLocator, AsyncResultLocator);
    DeployResultLocator.prototype.complete = function(includeDetails, callback) {
      if (_.isFunction(includeDetails)) {
        callback = includeDetails;
        includeDetails = false;
      }
      var meta = this._meta;
      return DeployResultLocator.super_.prototype.complete.call(this).then(function(result) {
        return meta.checkDeployStatus(result.id, includeDetails);
      }).thenCall(callback);
    };
    jsforce.on("connection:new", function(conn) {
      conn.metadata = new Metadata(conn);
    });
  }
});

// lib/api/soap.js
var require_soap2 = __commonJS({
  "lib/api/soap.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var jsforce = require_core();
    var SOAP = require_soap();
    var SoapApi = module2.exports = function(conn) {
      this._conn = conn;
    };
    SoapApi.prototype._invoke = function(method, message, schema, callback) {
      var soapEndpoint = new SOAP(this._conn, {
        xmlns: "urn:partner.soap.sforce.com",
        endpointUrl: this._conn.instanceUrl + "/services/Soap/u/" + this._conn.version
      });
      return soapEndpoint.invoke(method, message, { result: schema }).then(function(res) {
        return res.result;
      }).thenCall(callback);
    };
    var Schemas = {};
    SoapApi.prototype.convertLead = function(leadConverts, callback) {
      var schema = _.isArray(leadConverts) ? [Schemas.LeadConvertResult] : Schemas.LeadConvertResult;
      return this._invoke("convertLead", { leadConverts }, schema, callback);
    };
    Schemas.LeadConvertResult = {
      success: "boolean",
      errors: [],
      leadId: "string",
      accountId: "string",
      contactId: "string",
      opportunityId: "string"
    };
    SoapApi.prototype.merge = function(mergeRequests, callback) {
      var schema = _.isArray(mergeRequests) ? [Schemas.MergeResult] : Schemas.MergeResult;
      return this._invoke("merge", { mergeRequests }, schema, callback);
    };
    Schemas.MergeResult = {
      success: "boolean",
      errors: [],
      id: "string",
      mergedRecordIds: ["string"],
      updatedRelatedIds: ["string"]
    };
    SoapApi.prototype.emptyRecycleBin = function(ids, callback) {
      return this._invoke("emptyRecycleBin", { ids }, [Schemas.EmptyRecycleBinResult], callback);
    };
    Schemas.EmptyRecycleBinResult = {
      id: "string",
      success: "boolean",
      errors: []
    };
    SoapApi.prototype.describeTabs = function(callback) {
      return this._invoke("describeTabs", {}, [Schemas.DescribeTabSetResult], callback);
    };
    Schemas.DescribeTabSetResult = {
      label: "string",
      logoUrl: "string",
      namespace: "string",
      selected: "boolean",
      tabs: [{
        colors: [{
          theme: "string",
          color: "string",
          context: "string"
        }],
        iconUrl: "string",
        icons: [{
          theme: "string",
          height: "number",
          width: "number",
          url: "string",
          contentType: "string"
        }],
        label: "string",
        custom: "boolean",
        miniIconUrl: "string",
        name: "string",
        sobjectName: "string",
        url: "string"
      }]
    };
    SoapApi.prototype.getServerTimestamp = function(callback) {
      return this._invoke("getServerTimestamp", {}, Schemas.GetServerTimestampResult, callback);
    };
    Schemas.GetServerTimestampResult = {
      timestamp: "string"
    };
    SoapApi.prototype.getUserInfo = function(callback) {
      return this._invoke("getUserInfo", {}, Schemas.GetUserInfoResult, callback);
    };
    Schemas.GetUserInfoResult = {
      accessibilityMode: "boolean",
      currencySymbol: "string",
      orgAttachmentFileSizeLimit: "number",
      orgDefaultCurrencyIsoCode: "string",
      orgDisallowHtmlAttachments: "boolean",
      orgHasPersonAccounts: "boolean",
      organizationId: "string",
      organizationMultiCurrency: "boolean",
      organizationName: "string",
      profileId: "string",
      roleId: "string",
      sessionSecondsValid: "number",
      userDefaultCurrencyIsoCode: "string",
      userEmail: "string",
      userFullName: "string",
      userId: "string",
      userLanguage: "string",
      userLocale: "string",
      userName: "string",
      userTimeZone: "string",
      userType: "string",
      userUiSkin: "string"
    };
    SoapApi.prototype.setPassword = function(userId, password, callback) {
      return this._invoke("setPassword", { userId, password }, callback);
    };
    SoapApi.prototype.resetPassword = function(userId, callback) {
      return this._invoke("resetPassword", { userId }, callback);
    };
    SoapApi.prototype.create = function(sObjects, callback) {
      var schema = _.isArray(sObjects) ? [Schemas.SaveResult] : Schemas.SaveResult;
      var args = {
        "@xmlns": "urn:partner.soap.sforce.com",
        "@xmlns:ns1": "sobject.partner.soap.sforce.com",
        "ns1:sObjects": sObjects
      };
      return this._invoke("create", args, schema, callback);
    };
    SoapApi.prototype.update = function(sObjects, callback) {
      var schema = _.isArray(sObjects) ? [Schemas.SaveResult] : Schemas.SaveResult;
      var args = {
        "@xmlns": "urn:partner.soap.sforce.com",
        "@xmlns:ns1": "sobject.partner.soap.sforce.com",
        "ns1:sObjects": sObjects
      };
      return this._invoke("update", args, schema, callback);
    };
    Schemas.SaveResult = {
      success: "boolean",
      errors: [],
      id: "string"
    };
    SoapApi.prototype.upsert = function(externalIdFieldName, sObjects, callback) {
      var schema = _.isArray(sObjects) ? [Schemas.UpsertResult] : Schemas.UpsertResult;
      var args = {
        "@xmlns": "urn:partner.soap.sforce.com",
        "@xmlns:ns1": "sobject.partner.soap.sforce.com",
        "ns1:externalIDFieldName": externalIdFieldName,
        "ns1:sObjects": sObjects
      };
      return this._invoke("upsert", args, schema, callback);
    };
    Schemas.UpsertResult = {
      created: "boolean",
      success: "boolean",
      errors: [],
      id: "string"
    };
    SoapApi.prototype.delete = function(ids, callback) {
      var schema = _.isArray(ids) ? [Schemas.DeleteResult] : Schemas.DeleteResult;
      var args = {
        "@xmlns": "urn:partner.soap.sforce.com",
        "@xmlns:ns1": "sobject.partner.soap.sforce.com",
        "ns1:ids": ids
      };
      return this._invoke("delete", args, schema, callback);
    };
    Schemas.DeleteResult = {
      success: "boolean",
      errors: [],
      id: "string"
    };
    jsforce.on("connection:new", function(conn) {
      conn.soap = new SoapApi(conn);
    });
    module2.exports = SoapApi;
  }
});

// lib/api/streaming-extension.js
var require_streaming_extension = __commonJS({
  "lib/api/streaming-extension.js"(exports2, module2) {
    var StreamingExtension = {};
    StreamingExtension.AuthFailure = function(failureCallback) {
      this.incoming = function(message, callback) {
        if ((message.channel === "/meta/connect" || message.channel === "/meta/handshake") && message.advice && message.advice.reconnect == "none") {
          failureCallback(message);
        } else {
          callback(message);
        }
      };
    };
    StreamingExtension.Replay = function(channel, replayId) {
      var REPLAY_FROM_KEY = "replay";
      var _extensionEnabled = replayId != null ? true : false;
      var _replay = replayId;
      var _channel = channel;
      this.setExtensionEnabled = function(extensionEnabled) {
        _extensionEnabled = extensionEnabled;
      };
      this.setReplay = function(replay) {
        _replay = parseInt(replay, 10);
      };
      this.setChannel = function(channel2) {
        _channel = channel2;
      };
      this.incoming = function(message, callback) {
        if (message.channel === "/meta/handshake") {
          if (message.ext && message.ext[REPLAY_FROM_KEY] == true) {
            _extensionEnabled = true;
          }
        } else if (message.channel === _channel && message.data && message.data.event && message.data.event.replayId) {
          _replay = message.data.event.replayId;
        }
        callback(message);
      };
      this.outgoing = function(message, callback) {
        if (message.channel === "/meta/subscribe" && message.subscription === _channel) {
          if (_extensionEnabled) {
            if (!message.ext) {
              message.ext = {};
            }
            var replayFromMap = {};
            replayFromMap[_channel] = _replay;
            message.ext[REPLAY_FROM_KEY] = replayFromMap;
          }
        }
        callback(message);
      };
    };
    module2.exports = StreamingExtension;
  }
});

// lib/api/streaming.js
var require_streaming = __commonJS({
  "lib/api/streaming.js"(exports2, module2) {
    "use strict";
    var events = require("events");
    var inherits = require("inherits");
    var _ = require("lodash/core");
    var Faye = require("faye");
    var StreamingExtension = require_streaming_extension();
    var jsforce = require_core();
    var Topic = function(streaming, name) {
      this._streaming = streaming;
      this.name = name;
    };
    Topic.prototype.subscribe = function(listener) {
      return this._streaming.subscribe(this.name, listener);
    };
    Topic.prototype.unsubscribe = function(listener) {
      this._streaming.unsubscribe(this.name, listener);
      return this;
    };
    var Channel = function(streaming, name) {
      this._streaming = streaming;
      this._name = name;
    };
    Channel.prototype.subscribe = function(listener) {
      return this._streaming.subscribe(this._name, listener);
    };
    Channel.prototype.unsubscribe = function(listener) {
      this._streaming.unsubscribe(this._name, listener);
      return this;
    };
    Channel.prototype.push = function(events2, callback) {
      var isArray = _.isArray(events2);
      events2 = isArray ? events2 : [events2];
      var conn = this._streaming._conn;
      if (!this._id) {
        this._id = conn.sobject("StreamingChannel").findOne({ Name: this._name }, "Id").then(function(rec) {
          return rec.Id;
        });
      }
      return this._id.then(function(id) {
        var channelUrl = "/sobjects/StreamingChannel/" + id + "/push";
        return conn.requestPost(channelUrl, { pushEvents: events2 });
      }).then(function(rets) {
        return isArray ? rets : rets[0];
      }).thenCall(callback);
    };
    var Streaming = function(conn) {
      this._conn = conn;
    };
    inherits(Streaming, events.EventEmitter);
    Streaming.prototype._createClient = function(forChannelName, extensions) {
      var needsReplayFix = typeof forChannelName === "string" && forChannelName.indexOf("/u/") === 0;
      var endpointUrl = [
        this._conn.instanceUrl,
        // special endpoint "/cometd/replay/xx.x" is only available in 36.0.
        // See https://releasenotes.docs.salesforce.com/en-us/summer16/release-notes/rn_api_streaming_classic_replay.htm
        "cometd" + (needsReplayFix === true && this._conn.version === "36.0" ? "/replay" : ""),
        this._conn.version
      ].join("/");
      var fayeClient = new Faye.Client(endpointUrl, {});
      fayeClient.setHeader("Authorization", "OAuth " + this._conn.accessToken);
      if (extensions instanceof Array) {
        extensions.forEach(function(extension) {
          fayeClient.addExtension(extension);
        });
      }
      if (fayeClient._dispatcher.getConnectionTypes().indexOf("callback-polling") === -1) {
        fayeClient._dispatcher.selectTransport("long-polling");
        fayeClient._dispatcher._transport.batching = false;
      }
      return fayeClient;
    };
    Streaming.prototype._getFayeClient = function(channelName) {
      var isGeneric = channelName.indexOf("/u/") === 0;
      var clientType = isGeneric ? "generic" : "pushTopic";
      if (!this._fayeClients || !this._fayeClients[clientType]) {
        this._fayeClients = this._fayeClients || {};
        this._fayeClients[clientType] = this._createClient(channelName);
      }
      return this._fayeClients[clientType];
    };
    Streaming.prototype.topic = function(name) {
      this._topics = this._topics || {};
      var topic = this._topics[name] = this._topics[name] || new Topic(this, name);
      return topic;
    };
    Streaming.prototype.channel = function(channelId) {
      return new Channel(this, channelId);
    };
    Streaming.prototype.subscribe = function(name, listener) {
      var channelName = name.indexOf("/") === 0 ? name : "/topic/" + name;
      var fayeClient = this._getFayeClient(channelName);
      return fayeClient.subscribe(channelName, listener);
    };
    Streaming.prototype.unsubscribe = function(name, listener) {
      var channelName = name.indexOf("/") === 0 ? name : "/topic/" + name;
      var fayeClient = this._getFayeClient(channelName);
      fayeClient.unsubscribe(channelName, listener);
      return this;
    };
    Streaming.prototype.createClient = function(extensions) {
      return this._createClient(null, extensions);
    };
    jsforce.on("connection:new", function(conn) {
      conn.streaming = new Streaming(conn);
    });
    jsforce.StreamingExtension = StreamingExtension;
    module2.exports = Streaming;
  }
});

// lib/api/tooling.js
var require_tooling = __commonJS({
  "lib/api/tooling.js"(exports2, module2) {
    "use strict";
    var jsforce = require_core();
    var _ = require("lodash/core");
    var Cache = require_cache();
    var Tooling = function(conn) {
      this._conn = conn;
      this._logger = conn._logger;
      var delegates = [
        "query",
        "queryMore",
        "_toRecordResult",
        "create",
        "_createSingle",
        "_createParallel",
        "_createMany",
        "insert",
        "retrieve",
        "_retrieveSingle",
        "_retrieveParallel",
        "_retrieveMany",
        "update",
        "_updateSingle",
        "_updateParallel",
        "_updateMany",
        "upsert",
        "del",
        "delete",
        "destroy",
        "_destroySingle",
        "_destroyParallel",
        "_destroyMany",
        "describe",
        "describeGlobal",
        "sobject"
      ];
      delegates.forEach(function(method) {
        this[method] = conn.constructor.prototype[method];
      }, this);
      this.cache = new Cache();
      var cacheOptions = {
        key: function(type) {
          return type ? "describe." + type : "describe";
        }
      };
      this.describe$ = this.cache.makeCacheable(this.describe, this, cacheOptions);
      this.describe = this.cache.makeResponseCacheable(this.describe, this, cacheOptions);
      this.describeSObject$ = this.describe$;
      this.describeSObject = this.describe;
      cacheOptions = { key: "describeGlobal" };
      this.describeGlobal$ = this.cache.makeCacheable(this.describeGlobal, this, cacheOptions);
      this.describeGlobal = this.cache.makeResponseCacheable(this.describeGlobal, this, cacheOptions);
      this.initialize();
    };
    Tooling.prototype.initialize = function() {
      this.sobjects = {};
      this.cache.clear();
      this.cache.get("describeGlobal").removeAllListeners("value");
      this.cache.get("describeGlobal").on("value", _.bind(function(res) {
        if (res.result) {
          var types = _.map(res.result.sobjects, function(so) {
            return so.name;
          });
          types.forEach(this.sobject, this);
        }
      }, this));
    };
    Tooling.prototype._baseUrl = function() {
      return this._conn._baseUrl() + "/tooling";
    };
    Tooling.prototype._supports = function(feature) {
      if (feature === "sobject-collection") {
        return false;
      }
      return this._conn._supports.apply(this._conn, arguments);
    };
    Tooling.prototype.request = function() {
      return this._conn.request.apply(this._conn, arguments);
    };
    Tooling.prototype.executeAnonymous = function(body, callback) {
      var url = this._baseUrl() + "/executeAnonymous?anonymousBody=" + encodeURIComponent(body);
      return this.request(url).thenCall(callback);
    };
    Tooling.prototype.runTestsAsynchronous = function(classids, callback) {
      var url = this._baseUrl() + "/runTestsAsynchronous/";
      return this._conn.requestPost(url, { classids: classids.join(",") }, void 0, callback);
    };
    Tooling.prototype.runTestsSynchronous = function(classnames, callback) {
      var url = this._baseUrl() + "/runTestsSynchronous/";
      return this._conn.requestPost(url, { classnames: classnames.join(",") }, void 0, callback);
    };
    Tooling.prototype.completions = function(type, callback) {
      if (!_.isString(type)) {
        callback = type;
        type = "apex";
      }
      var url = this._baseUrl() + "/completions?type=" + encodeURIComponent(type);
      return this.request(url).thenCall(callback);
    };
    jsforce.on("connection:new", function(conn) {
      conn.tooling = new Tooling(conn);
    });
    module2.exports = Tooling;
  }
});

// lib/api/index.js
var require_api = __commonJS({
  "lib/api/index.js"() {
    require_analytics();
    require_apex();
    require_bulk();
    require_chatter();
    require_metadata();
    require_soap2();
    require_streaming();
    require_tooling();
  }
});

// lib/registry/registry.js
var require_registry = __commonJS({
  "lib/registry/registry.js"(exports2, module2) {
    "use strict";
    var _ = require("lodash/core");
    var Connection = require_connection();
    var Registry = function(configFilePath) {
      this._registryConfig = {};
    };
    Registry.prototype._saveConfig = function() {
      throw new Error("_saveConfig must be implemented in subclass");
    };
    Registry.prototype._getClients = function() {
      return this._registryConfig.clients || (this._registryConfig.clients = {});
    };
    Registry.prototype._getConnections = function() {
      return this._registryConfig.connections || (this._registryConfig.connections = {});
    };
    Registry.prototype.getConnectionNames = function() {
      return Object.keys(this._getConnections());
    };
    Registry.prototype.getConnection = function(name) {
      return new Connection(this.getConnectionConfig(name));
    };
    Registry.prototype.getConnectionConfig = function(name) {
      if (!name) {
        name = this._registryConfig["default"];
      }
      var connections = this._getConnections();
      var connConfig = connections[name];
      if (connConfig) {
        connConfig = _.clone(connConfig);
        if (connConfig.client) {
          connConfig.oauth2 = _.clone(this.getClient(connConfig.client));
        }
        delete connConfig.client;
      }
      return connConfig;
    };
    Registry.prototype.saveConnectionConfig = function(name, connConfig) {
      var connections = this._getConnections();
      connConfig = _.clone(connConfig);
      if (connConfig.oauth2) {
        var clientName = this._findClientName(connConfig.oauth2);
        if (clientName) {
          connConfig.client = clientName;
        }
        delete connConfig.oauth2;
      }
      connections[name] = connConfig;
      this._saveConfig();
    };
    Registry.prototype._findClientName = function(clientConfig) {
      var clients = this._getClients();
      for (var name in clients) {
        var client = clients[name];
        if (client.clientId === clientConfig.clientId && (client.loginUrl || "https://login.salesforce.com") === clientConfig.loginUrl) {
          return name;
        }
      }
      return null;
    };
    Registry.prototype.setDefaultConnection = function(name) {
      this._registryConfig["default"] = name;
      this._saveConfig();
    };
    Registry.prototype.removeConnectionConfig = function(name) {
      var connections = this._getConnections();
      delete connections[name];
      this._saveConfig();
    };
    Registry.prototype.getClient = function(name) {
      var clientConfig = this._getClients()[name];
      return clientConfig && _.clone(clientConfig);
    };
    Registry.prototype.getClientNames = function() {
      return Object.keys(this._getClients());
    };
    Registry.prototype.registerClient = function(name, clientConfig) {
      var clients = this._getClients();
      clients[name] = clientConfig;
      this._saveConfig();
    };
    module2.exports = Registry;
  }
});

// lib/registry/file-registry.js
var require_file_registry = __commonJS({
  "lib/registry/file-registry.js"(exports2, module2) {
    var inherits = require("inherits");
    var fs = require("fs");
    var path = require("path");
    var Registry = require_registry();
    var FileRegistry = function(configFilePath) {
      FileRegistry.super_.call(this);
      this._configFilePath = configFilePath || this._getDefaultConfigFilePath();
      try {
        var data = fs.readFileSync(this._configFilePath, "utf-8");
        this._registryConfig = JSON.parse(data);
      } catch (e) {
      }
    };
    inherits(FileRegistry, Registry);
    FileRegistry.prototype._getDefaultConfigFilePath = function() {
      var homeDir = process.env[process.platform === "win32" ? "USERPROFILE" : "HOME"];
      var configDir = homeDir + "/.jsforce";
      return configDir + "/config.json";
    };
    FileRegistry.prototype._saveConfig = function() {
      var data = JSON.stringify(this._registryConfig, null, 4);
      try {
        fs.writeFileSync(this._configFilePath, data);
        fs.chmodSync(this._configFilePath, "600");
      } catch (e) {
        var configDir = path.dirname(this._configFilePath);
        fs.mkdirSync(configDir);
        fs.chmodSync(configDir, "700");
        fs.writeFileSync(this._configFilePath, data);
        fs.chmodSync(this._configFilePath, "600");
      }
    };
    module2.exports = FileRegistry;
  }
});

// lib/registry/index.js
var require_registry2 = __commonJS({
  "lib/registry/index.js"() {
    var jsforce = require_core();
    var FileRegistry = require_file_registry();
    jsforce.registry = new FileRegistry();
  }
});

// lib/jsforce.js
require_api();
require_registry2();
module.exports = require_core();
