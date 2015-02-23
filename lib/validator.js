/*************************************************************************
 * Copyright(c) 2012-2015 Jim Pravetz <jpravetz@epdoc.com>
 * May be freely distributed under the MIT license.
 **************************************************************************/

var Validator = require('validator').Validator;
var check = require('validator').check;
var sanitize = require('validator').sanitize;

// var ModelData = require('../data/modeldata');
var _u = require('underscore');

// const PARENT_FIELDS = [ 'sTitle', 'sTooltip', 'sPlaceholder', 'sText', 'rules' ];

/**
 * Class is used to check and sanitize the properties on an API input object.
 * Uses the tables in ModelData to determine the validation rules.
 * @param tablename (Optional) If specified then gets columns from the specified table in ModelData
 */

module.exports = function (defname) {

    var self = this;
    this.errors = [];
    this.model;
    this.validator = new Validator();

    /**
     * Push a form validation error
     * @param error { param, msg, title, value }
     */
    self.pushError = function (error) {
        if (typeof error === 'string')
            self.errors.push({ msg: error });
        else
            self.errors.push(error);
    };

    self.i18nErrors = function (req) {
        var result = [];
        _u.each(self.errors, function (error) {
            result.push({
                title: error.title ? req.i18n.__(error.title) : error.title,
                msg: error.msg ? req.i18n.__r(error.msg, error.params) : error.msg,
                key: error.key,
                value: sanitize(error.value).xss()
            });
        });
        return result;
    };

    this.reset = function () {
        self.errors = [];
        self.result = {};
        return self;
    };

    /**
     * Set the model. This is equivalent to passing in the defname in the constructor.
     * @param defname The name of the definition file, minus the .def.js extension. Give the same
     * name as you would use with require(), except excluding the .def.js extension.
     */
    this.setModel = function (defname) {
        // console.log( '../data/'+type+'/'+model+'.data' );
        if (defname) {
            // Get the model
            self.model = require(defname + '.def');
            // Patch if necessary (need to do once, then in memory object is good for life of process)
            if (self.model.bRequiresPatch) {
                var ModelDef = require('./modeldef');
                var model = new ModelDef(defname);
                model.mergeIncludes();
            }
            // Set the columns that are used by validateItem if called without a columns parameter
            self.columns = self.model.methods ? self.model.methods : self.model.columns;
        }
        return self;
    };

    self.setModel(defname);

    /**
     * Main entry point for validating an object. The object to be validated can be a simple object
     * (e.g. used in CRUD), a method object (contains method and params properties) or a more complex,
     * nested object including support for arrays. The simple and complex objects are treated the same.
     * The method object is special-cased and the .def.js file for the method object is different as well.
     * @param obj The object to be validated.
     * @return {*}
     */
    this.validateData = function (obj) {
        // console.log( "Validating %s", JSON.stringify(obj) );
        self.reset();
        var result;
        if (_u.isObject(obj)) {
            if (self.model.methods) {
                if (typeof obj.method === 'string' && obj.method.length < 64 && self.model.methods[obj.method]) {
                    result = { method: obj.method };
                    var columns = self.model.methods[obj.method].columns;
                    result.params = self._validateColumns(obj.params ? obj.params : {}, columns);
                } else {
                    self.errors.push({ title: "Method", msg: "Not valid", value: clip(obj.method, 32) });
                }
            } else {
                // self.result = self._validateColumns(obj[self.model.name],self.model.columns);
                result = self._validateColumns(obj, self.model.columns);
            }
        } else {
            self.errors.push({ msg: "Missing data" });
        }
        return result;
    };

    /**
     * Validate all properties of obj that appear in self.columns
     * @param obj The object to validate
     * @param roles Not used
     * @return {*} The validated and sanitized object
     */
    this._validateColumns = function (obj, columns) {
        // console.log( "_validateColumns %s %s", JSON.stringify(obj), JSON.stringify(columns))
        columns = columns || self.columns;
        if (_u.isObject(obj)) {
            if (columns) {
                var result = {};
                _u.each(columns, function (entry, key) {
                    var val = self.validateItem(key, obj[key], columns);
                    if (val || ( typeof val === 'string' && val.length === 0 ) || ( typeof val === 'boolean' ))
                        result[key] = val;
                });
                return result;
            }
        } else {
            self.errors.push({ msg: "Missing data" });
        }
        return undefined;
    };

    this.validateId = function (id) {
        var r = parseInt(id, 10);
        if (!r)
            self.errors.push({ msg: "Missing object identifier" });
        return r;
    };

    /**
     * Validate one entry (key) from columns for this object. This can work
     * recursively, if the item entry contains columns or an array rather then rules.
     * Please be sure to call reset() before calling this, as this method does not call reset.
     * @param key The name of the property in the columns spec
     * @param value The value that we are validating and sanitizing
     * @param columms The spec for the item will be drawn from columns[key]
     * @param bRequired If true and this is a non object then this value is required.
     * @return The validated and sanitized value
     */
    this.validateItem = function (key, value, columns, bRequired ) {
        // console.log( "validateItem %s, %s, %s", key, value, columns?JSON.stringify(columns[key]):"");
        var result;
        columns = columns || self.columns;
        if (key && columns && columns[key]) {

            // The column is either a direct or indirect object
            // If indirect then permanently patch the column with validation data from the parent
//            if( columns[key].parent )
//                self._extendColumnFromParent( columns[key] );

            var column = columns[key];
            if (column && column.rules) {
                result = self.validateItemDef(value, columns[key], key, bRequired);
            } else if (column && column.columns) {
                if (value) {
                    result = self._validateColumns(value, column.columns);
                } else if (column.bRequired) {
                    self.errors.push({ msg: "is missing", param: key, title: (column.sTitle ? column.sTitle : key) });
                }
            } else if (column && column.array) {
                if (_u.isArray(value)) {
                    if (column.min && value.length < column.min) {
                        self.errors.push({ param: key, msg: "minimum array length not met", title: (column.sTitle ? column.sTitle : key) });
                    } else if (column.max && value.length > column.max) {
                        self.errors.push({ param: key, msg: "maximum array length exceeded", title: (column.sTitle ? column.sTitle : key) });
                    } else {
                        result = [];
                        if (column.array.columns) {
                            _u.each(value, function (entry) {
                                result.push(self._validateColumns(entry, column.array.columns));
                            });
                        } else if (column.array.rules) {
                            _u.each(value, function (entry) {
                                self._applyCheckRules(entry, column.array.rules.validators, 'array', key, false);
                            });
                        }
                    }
                } else if (column.bRequired) {
                    self.errors.push({ param: key, msg: "is missing", title: (column.sTitle ? column.sTitle : key) });
                } else if (value) {
                    self.errors.push({ param: key, msg: "is not an array", title: (column.sTitle ? column.sTitle : key) });
                }
            } else if (column && column.bRequired && !value) {
                self.errors.push({ param: key, msg: "is missing", title: (column.sTitle ? column.sTitle : key) });
            }
        }
        return result;
    };

    /**
     * Validate the value using the provided column def. Errors are added to the errors array.
     * @param value The value to be validated
     * @param colSpec The column spec against which to validate (contains, sTitle, rules, bRequired)
     * @param key (Optional) key, used only for reporting, may also be set as mData in column (this is the only use for mData,
     * and would only be use when calling validateItemDef directly).
     */
    this.validateItemDef = function (value, colSpec, key, bRequired) {
        // console.log( "validateItem %s %s rules %s", key, value, JSON.stringify(colSpec.rules) );
        var result;
        var title = colSpec.sTitle;
        var rules = colSpec.rules;
        if ((colSpec.bRequired || rules.bRequired || bRequired) && !value) {
            self.errors.push({ param: key, msg: "is missing", title: title });
        } else if (value) {
            var val;
            if (rules.type === 'int') {
                val = parseInt(value, 10);
            } else if (rules.type === 'array') {
                val = value;
            } else if (rules.type === 'boolean') {
                val = value;
            } else {
                val = String(value);
                if (rules.trim !== false) val = val.trim();
            }
            // self.applyPermissionRules( key, roles, rules.permissions );
            result = applySanitizeRules(val, rules.sanitizers);
            self._applyCheckRules(result, rules.validators, (key ? key : colSpec.mData), title, colSpec.bPassword);
        } else if (typeof value === 'string' && value.length === 0) {
            // Pass empty strings thru without validation
            result = value;
        }
        return result;
    };

    /**
     * Use to check the validation rules for a single end point. Does not recurse.
     * @param value The value to check
     * @param rules The rules object
     * @param key (Optional) Used only for reporting
     * @param title (Optional) The title, used only for reporting
     * @param bPassword (Optional) Used to indicate that the value should be included when reporting
     */
    this._applyCheckRules = function (value, rules, key, title, bPassword) {
        self.validator.error = function (msg, params) {
            var error = { msg: msg, params: params };
            if (key) error.key = key;
            if (title || key) error.title = title ? title : key;
            if (!bPassword) error.value = clip(value, 32);
            self.errors.push(error);
        };
        if (typeof rules === 'string') {
            self.validator.check(value)[rules]();
        } else if (rules instanceof Array) {    // an array
            rules.forEach(function (rule) {
                if (typeof rule === 'string') {
                    self.validator.check(value)[rule]();
                } else if (rule instanceof Array) {    // an array with method, arguments
                    var args = _u.clone(rule);
                    var method = args.shift();
                    self.validator.check(value)[method].apply(self.validator, args);
                }
            });
        }
    };

};

function applySanitizeRules(value, rules) {
    var r = value; //.trim();
    if (typeof rules === 'string') {
        r = sanitize(r)[rules]()
    } else if (rules instanceof Array) {    // an array
        rules.forEach(function (rule) {
            if (typeof rule === 'string') {
                r = sanitize(r)[rule]();
            } else if (rule instanceof Array) {    // an array with method, arguments
                var args = _u.clone(rule);
                var method = args.shift();
                r = sanitize(r)[method].apply(this, args);
            }
        });
    }
    return r;
}

function clip(s, len) {
    if (typeof s === 'string' && s.length > (len + 12))
        return s.substr(0, len) + "...(" + s.length + "bytes)";
    return s;
}

/******************************************************************************
 * Extend validator module with custom sanitizers and checkers.
 *****************************************************************************/

// Existing validators
var validators = require('validator').validators;

var Filter = require('validator').Filter;

Filter.prototype.toLowerCase = function () {
    this.modify(this.str.toLowerCase());
    return this.str;
}

Validator.prototype.isBookmarkUrl = function () {
    var self = this;
    if (!validators.isUrl(this.str) && !isMountPoint(this.str) && !isDomain(this.str) && !isPath(this.str) && !this.str.match(/https?:\/\//i)) {
        self.error(self.msg || 'Not a valid address');
    }
    return self;
}

function isMountPoint(str) {
    return str.match(/^\/\/[\w\-\.\$]+(\/[\w\-\.\$\ ]+)*\/?$/);
}

Validator.prototype.isAddressWithPath = function () {
    var self = this;
    var p = this.str.split('/');
    var q = p.shift().split(':');
    var addr = q.shift();
    if (!validators.isIPNet(addr) && !isDomainWithUpper(addr) /* && !validators.isUrl(this.str) */) {
        self.error(self.msg || 'Not a valid address');
    } else if (q.length) {
        if (!q[0].match(/^\d+$/)) {
            self.error(self.msg || 'Not a valid address');
        }
    } else if (p.length) {
        var remainder = p.join('/');
        var bDone = false;
        for (var adx = 0; adx < p.length && !bDone; ++adx) {
            if (!p[adx].match(/^[\w\.\-]*$/)) {
                self.error(self.msg || 'Not a valid address');
                bDone = true;
            }
        }
    }
    return self;
}

Validator.prototype.isAddress = function () {
    var self = this;
    if (!validators.isIPNet(this.str) && !isDomain(this.str) /* && !validators.isUrl(this.str) */) {
        self.error(self.msg || 'Not a valid address');
    }
    return self;
}

function isAddress(str) {

}

Validator.prototype.isLoginId = function () {
    var self = this;
    if (!validators.isEmail(this.str) && !isUsername(this.str)) {
        self.error(self.msg || 'Not a valid username or email address');
    }
    return self;
}

// We are replacing existing routine so we get different error messages for short and long strings
Validator.prototype.len = function (min, max) {
    if (this.str.length < min) {
        this.error(this.msg || 'Must be at least _LEN_ characters in length', {len: min});
    } else if (this.str.length > max) {
        this.error(this.msg || 'Must be less than _LEN_ characters in length', {len: max});
    }
    return this;
}

// We are replacing existing routine so we get different error messages for short and long strings
Validator.prototype.range = function (min, max) {
    if (parseInt(this.str, 10) <= min) {
        this.error(this.msg || 'Must be greater than or equal to _LEN_', {len: min});
    } else if (parseInt(this.str, 10) >= max) {
        this.error(this.msg || 'Must be less than or equal to _LEN_', {len: max});
    }
    return this;
}

Validator.prototype.isDomain = function () {
    if (!isDomain(this.str)) {
        this.error(this.msg || 'Not a valid domain');
    }
    return this;
}

function isDomain(str) {
    return str.match(/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$/);
}
module.exports.isDomain = isDomain;

function isDomainWithUpper(str) {
    return str.match(/^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,5}$/);
}

Validator.prototype.isAlphanumericExt = function () {
    if (!isAlphanumericExt(this.str)) {
        this.error(this.msg || 'Not a valid string');
    }
    return this;
}

function isAlphanumericExt(str) {
    return str.match(/^[a-zA-Z0-9_\-\.\@]+$/);
}

Validator.prototype.isHttpUrl = function () {
    if (!this.str.match(/^(?:(?:https?):\/\/)(?:\S+(?::\S*)?@)?(?:(?:(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]+-?)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))|localhost)(?::\d{2,5})?(?:\/[^\s]*)?$/i)) {
        this.error(this.msg || 'Not a valid HTTP or HTTPS URL');
    }
    return this; //Allow method chaining
}

Validator.prototype.isDbName = function () {
    if (!this.str.match(/^[a-zA-Z][a-zA-Z0-9_\-]+$/)) {
        this.error(this.msg || 'Not a valid database name', { str: this.str });
    }
    return this; //Allow method chaining
}

Validator.prototype.isUsername = function () {
    if (!isUsername(this.str)) {
        this.error(this.msg || 'Not a valid username', { str: this.str});
    }
    return this;
}

function isUsername(str) {
    if (str && str.match(/^[a-zA-Z0-9_\-\.\@]+$/))
        return true;
    return false;
}


Validator.prototype.isVpnDomain = function () {
    if (!this.str.match(/^[a-zA-Z0-9_\-\.\@ ]+$/)) {
        this.error(this.msg || 'Not a valid domain', { str: this.str});
    }
    return this; //Allow method chaining
}

Validator.prototype.isISODate = function () {
    if (!this.str.match(/^(\d{4})\D?(0[1-9]|1[0-2])\D?([12]\d|0[1-9]|3[01])(\D?([01]\d|2[0-3])\D?([0-5]\d)\D?([0-5]\d)?\D?(\d{3})?([zZ]|([\+-])([01]\d|2[0-3])\D?([0-5]\d)?)?)?$/)) {
        this.error(this.msg || 'Not a valid ISO date');
    }
    return this;
}

Validator.prototype.isRole = function () {
    if (!this.str.match(/^[a-zA-Z\,]*$/)) {
        this.error(this.msg || 'Not a valid role');
    }
    return this; //Allow method chaining
}

Validator.prototype.isUrn = function () {
    if (!this.str.match(/^[a-zA-Z0-9_\-\.]+$/)) {
        this.error(this.msg || 'Not a valid URN name', { str: this.str});
    }
    return this; //Allow method chaining
}

Validator.prototype.isVpnPath = function () {
    if (!this.str.match(/^[a-zA-Z0-9_\-]+$/)) {
        this.error(this.msg || 'Not a valid VPN path', { str: this.str});
    }
    return this;
}

Validator.prototype.isPath = function () {
    if (!isPath(this.str)) {
        this.error(this.msg || 'Not a valid path');
    }
    return this;
}

function isPath(str) {
    if (str && str.match(/^[a-zA-Z0-9_\-\/]+$/))
        return true;
    return false;
}


Validator.prototype.isDbDriver = function () {
    if (!this.str.match(/^(mysql)$/)) {
        this.error(this.msg || 'Not a supported database driver');
    }
    return this;
}

Validator.prototype.isToken = function () {
    if (!this.str.match(/^[a-zA-Z0-9_\-]+$/)) {
        this.error(this.msg || 'Not a valid token');
    }
    return this;
}

Validator.prototype.isPemCert = function () {
    if (!this.str.match(/^\s*\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-\s*[a-zA-Z0-9\+\/\s]+[=]+\s*\-\-\-\-\-END CERTIFICATE\-\-\-\-\-\s*$/)) {
        this.error(this.msg || 'Not a PEM cert');
    }
    return this;
}

Validator.prototype.isPemCerts = function () {
    if (!this.str.match(/^\s*(\-\-\-\-\-BEGIN CERTIFICATE\-\-\-\-\-\s*[a-zA-Z0-9\+\/\s]+[=]+\s*\-\-\-\-\-END CERTIFICATE\-\-\-\-\-\s*)+$/)) {
        this.error(this.msg || 'Not a PEM cert');
    }
    return this;
}

Validator.prototype.isImageDataUrl = function () {
    if (!isImageDataUrl(this.str)) {
        this.error(this.msg || 'Not a valid image');
    }
    return this;
}

function isImageDataUrl(str) {
    if (str && str.match(/^data:image\/(gif|jpeg|jpg|png|svg\+xml);base64,[A-Za-z0-9+/%]{35,}/i))
        return true;
    return false;
}

Validator.prototype.isJson = function () {
    try {
        var x = JSON.parse(this.str);
    } catch (e) {
        this.error(this.msg || 'Not valid JSON');
    }
    return this;
}

Validator.prototype.isPcf = function () {
    if (!this.str.match(/^[a-zA-Z0-9_\-]+$/)) {
        this.error(this.msg || 'Not a valid PCF');
    }
    return this;
}


Validator.prototype.isRoutes = function () {
    var arr = this.str.split( /[\s\r\n,]+/ );
    var bErr = false;
    for( var idx=0;idx<arr.length && !bErr; ++idx ) {
        if( !isIPCDIR(arr[idx]) ) {
            bErr = true;
        }
    }
    if (bErr) {
        this.error(this.msg || 'Not a valid address');
    }
    return this;
};

// The following function is duplicated in onboarding.js, so if you change it here, change it there as well.
var iPv4CDIRRegEx = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$/;
var iPv6CDIRRegEx = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/(\d|\d\d|1[0-1]\d|12[0-8]))$/;

function isIPCDIR(str) {
    if( !str ) {
        return 0;
    } else if( iPv4CDIRRegEx.test(str) ) {
        return 4;
    } else if( iPv6CDIRRegEx.test(str) ) {
        return 6;
    } else {
        return 0;
    }
};


Filter.prototype.toRoutes = function () {
    this.modify(filterRoutes(this.str));
    return this.str;
};

function filterRoutes(str) {
    if (str) {
        return str.match(/[^\s\r\n,]+/g).join(',');
    }
};


Filter.prototype.toPcf = function () {
    this.modify(filterPcf(this.str));
    return this.str;
};


var b64RegEx = /^\s*(-----BEGIN[^-]*-----)\s*((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)\s*(-----END[^-]*-----)\s*$/;

// Sanitizes PCF and OpenVPN and rewrites
function filterPcf(str) {
    if (str.match(/^\s*\[main]/i)) {
        var r = {};
        var lines = str.split(/\r\n|\r|\n/);
        _u.each(lines, function (line) {
            var p = line.split('=');
            if (p.length > 1)
                r[p[0].trim()] = p[1].trim();
        });
        var s = "[main]\n";
        _u.each(r, function (value, key) {
            s += key + "=" + value + "\n";
        });
        return s;
    } else {
        // OpenVPN file
        var r = {};
        var lines = str.split(/\r\n|\r|\n/);
        var commentRegex = /^\s*[;#]/;
        var inRegex = /^\s*\<\s*([^\s\>]+)\s*\>/;
        var outRegex = /^\s*\<\/\s*([^\s\>])+\s*\>/;
        var bInElement = false;
        var elName;
        var elText = '';
        _u.each(lines, function (line) {
            if (!bInElement) {
                var p = line.match(inRegex);
                if (p) {
                    bInElement = true;
                    elName = p[1];
                } else if (!line.match(commentRegex)) {
                    var q = line.trim().split(/\s+/);
                    var key = q.shift();
                    if (key && key.length) {
                        r[key] = q;
                    }
                }
            } else {
                var p = line.match(outRegex);
                if (p) {
                    r[elName] = elText;
                    elText = '';
                    bInElement = false;
                } else {
                    elText += line;
                }
            }
        });
        var s = "";
        _u.each(r, function (value, key) {
            var a = (typeof value === 'string' ) ? value.match(b64RegEx) : undefined;
            if (a && a.length > 3) {
                s += '<' + key + '>\n' + a[1] + '\n';
                var strLen = a[2].length;
                for (var offset = 0; offset < strLen; offset += 64) {
                    s += a[2].slice(offset,64+offset) + '\n';
                }
                s += a[3] + '\n</' + key + '>\n'
            } else {
                if (value instanceof Array) {
                    if( value.length > 0 ) {
                        s += key + " " + value.join(' ') + "\n";
                    } else {
                        s += key + "\n";
                    }
                } else {
                    s += key + " " + value + "\n";
                }
            }
        });
        return s;
    }
}
