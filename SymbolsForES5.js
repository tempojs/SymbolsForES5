(function(exports) {

	'use strict';

	if (
	/* If this is not an ES5 environment, we can't do anything.
	 * We'll at least need the following functions.
	 * While not exhaustive, this should be a good enough list to make sure
	 * we're in an ES5 environment.
	 */
		!Object.getOwnPropertyNames
		|| !Object.getOwnPropertyDescriptor
		|| !Object.defineProperty
		|| !Object.defineProperties
		|| !Object.keys
		|| !Object.create
		|| !Object.freeze
		|| !Object.isFrozen
		|| !Object.isExtensible
		) return;

	/* Retrieve the global object using an indirect eval.
	 * This should work in ES5 compliant environments.
	 * See: http://perfectionkills.com/global-eval-what-are-the-options/#indirect_eval_call_theory
	 */
	var _global = (0, eval)('this'),
		undefined;

	// If Symbol is already defined, there's nothing to do.
	if (_global.Symbol) return;

	var Secrets = (function(Object, String) {

	// We capture the built-in functions and methods as they are now and store them as references so that we can
	// maintain some integrity. This is done to prevent scripts which run later from mischievously trying to get
	// details about or alter the secrets stored on an object.
	var lazyBind = Function.prototype.bind.bind(Function.prototype.call),

		// ES5 functions
		create = Object.create,
		getPrototypeOf = Object.getPrototypeOf,
		isExtensible = Object.isExtensible,
		isFrozen = Object.isFrozen,
		freeze = Object.freeze,
		keys = Object.keys,
		getOwnPropertyNames = Object.getOwnPropertyNames,
		getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor,
		defineProperty = Object.defineProperty,
		hasOwn = lazyBind(Object.prototype.hasOwnProperty),
		push = lazyBind(Array.prototype.push),
		forEach = lazyBind(Array.prototype.forEach),
		map = lazyBind(Array.prototype.map),
		filter = lazyBind(Array.prototype.filter),
		join = lazyBind(Array.prototype.join),
		fromCharCode = String.fromCharCode,
		apply = lazyBind(Function.prototype.apply),
		bind = lazyBind(Function.prototype.bind),

		// ES Harmony functions
		getPropertyNames = Object.getPropertyNames,

		// ES.next strawman functions
		getPropertyDescriptors = Object.getPropertyDescriptors,
		getOwnPropertyDescriptors = Object.getOwnPropertyDescriptors,

		// ES Harmony constructors
		_Proxy = typeof Proxy == 'undefined' ? undefined : Proxy,

		// A property name can be prepped to be exposed when object[SECRET_KEY] is accessed.
		preppedName,
		// Note: freezable is an old proprety on Symbol that was passed in as a variable. It has been
		// removed from Symbol due to it not being needed anymore and its non-standardness. I'm leaving
		// the freezable logic in Secrets for now just in case we decide to go back to making Symbols
		// non-freezable. There's really no loss in having this unused logic here. However, after time
		// it may be good to remove freezable as an option once and for all.
		freezable = true,

		// Determines whether object[SECRET_KEY] on an object which doesn't have a SECRET_KEY property
		// should define itself. This is turned off when checking the prototype chain.
		autoDefine = true,

		// Determines whether object[SECRET_KEY] should expose the secret map.
		locked = true,

		random = getRandomGenerator(),
		// idNum will ensure identifiers are unique.
		idNum = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
		preIdentifier = randStr(7) + '0',
		SECRET_KEY = '!S:' + getIdentifier();

	// Override Object.create to add Secrets to any object created with it. It is necessary to add Secrets to any
	// object created with Object.create(null) since it won't inherit from Object.prototype, so Symbols would fail
	// if we didn't go ahead and add Secrets to it. It's not technically necessary to add Secrets to all objects;
	// we could just add Secrets to objects where value === null here. However, we go ahead anyway since it protects
	// against cases where, for example, someone might use a different frame's Object.freeze to freeze an object
	// created with this frame's Object.create. It's not foolproof, and it's a case that will probably never occur
	// in practice, but since we can catch it here, we go ahead and prevent the possibility.
	Object.create = function(value, props) {
		var obj = apply(create, this, arguments);
		Secrets(obj);
		return obj;
	};

	(function() {
		// Override get(Own)PropertyNames and get(Own)PropertyDescriptors

		var overrides = create(null);

		overrides.getOwnPropertyNames = getOwnPropertyNames
		if (getPropertyNames) overrides.getPropertyNames = getPropertyNames;

		keys(overrides).forEach(function(u) {
			var original = overrides[u];
			defineProperty(Object, u, {
				value: function(obj) {
					return filter(apply(original, this, arguments), function(u) {
						return u != SECRET_KEY;
					});
				},
				enumerable: false,
				writable: true,
				configurable: true
			});
		});

		overrides = create(null);

		if (getPropertyDescriptors) overrides.getPropertyDescriptors = getPropertyDescriptors;
		if (getOwnPropertyDescriptors) overrides.getOwnPropertyDescriptors = getOwnPropertyDescriptors;

		keys(overrides).forEach(function(u) {
			var original = overrides[u];
			defineProperty(Object, u, {
				value: function(obj) {
					var desc = apply(original, this, arguments);
					delete desc[SECRET_KEY];
					return desc;
				},
				enumerable: false,
				writable: true,
				configurable: true
			});
		});

	})();

	// Override functions which prevent extensions on objects to go ahead and add a secret map first.
	[ 'preventExtensions', 'seal', 'freeze' ].forEach(function(u) {
		var original = Object[u];
		defineProperty(Object, u, {
			value: function(obj) {
				// Define the secret map.
				Secrets(obj);
				return apply(original, this, arguments);
			}
		});
	});

	if (typeof _Proxy == 'function') {

		Proxy = (function() {
			/* TODO: This works for "direct_proxies", the current ES6 draft; however, some browsers have
			 * support for an old draft (such as FF 17 and below) which uses Proxy.create(). Should this
			 * version be overridden to protect against discovery of SECRET_KEY on these browsers also?
			 */

			var trapBypasses = create(null);
			trapBypasses.defineProperty = defineProperty;
			trapBypasses.hasOwn = hasOwn;
			trapBypasses.get = function(target, name) { return target[name]; };

			return function Proxy(target, traps) {

				if (!(this instanceof Proxy)) {
					// TODO: The new keyword wasn't used. What should be done?
					return new Proxy(target, traps);
				}

				var _traps = create(traps);

				forEach(keys(trapBypasses), function(trapName) {
					var bypass = trapBypasses[trapName];
					if (typeof traps[trapName] == 'function') {
						// Override traps which could discover SECRET_KEY.
						_traps[trapName] = function(target, name) {
							if (name === SECRET_KEY) {
								// Bypass any user defined trap when name === SECRET_KEY.
								return apply(bypass, null, arguments);
							}
							return apply(traps[trapName], this, arguments);
						};
					}
				});

				return new _Proxy(target, _traps);
			};

		})();

	} else if (_Proxy && _Proxy.create) {

//		Proxy.create = (function() {
//
//			return function create(traps, proto) {
//				// TODO
//			};
//
//		})();

	}

	// Allow Symbol properties to be accessed as keys.
	// Note: this monkey patch prevents Object.prototype from having its own secretMap.
	// Therefore, Secrets(Object.prototype) will fail.
	defineProperty(Object.prototype, SECRET_KEY, {

		get: function() {
			if (!autoDefine) return;
			if (this === Object.prototype) return;
			if (preppedName === undefined) return;
			// null and undefined can't have properties and are non-coercible.
			if (this == null) return;
			var name = preppedName;
			preppedName = undefined;
			autoDefine = false;
			var value = Secrets(this, name);
			autoDefine = true;
			return value;
		},

		set: function(value) {
			if (!autoDefine) return;
			if (this === Object.prototype) return;
			if (preppedName === undefined) return;
			// null and undefined can't have properties and are non-coercible.
			if (this == null) return;
			Secrets(this);
			this[SECRET_KEY] = value;
		},

		enumerable: false,
		configurable: false

	});

	// Override hasOwnProperty to work with preppedNames.
	defineProperty(Object.prototype, 'hasOwnProperty', {

		value: function hasOwnProperty(name) {

			var N = String(name),
				value;

			if (N == SECRET_KEY) {

				if (locked) {
					if (!preppedName) return false;
					var _name = preppedName;
					preppedName = undefined;
					value = Secrets(this).hasOwn(_name);
					return value;
				}

				return hasOwn(this, SECRET_KEY);

			} else return hasOwn(this, name);

		},

		enumerable: false,
		writable: true,
		configurable: true

	});

	var methods = {

		set: function setSecretProperty(O, name, value) {

			// Prevent secret properties from disobeying Object.freeze and Object.preventExtensions
			// unless freezable is false.
			if (!permitChange(this, O, name, true))
				throw new TypeError('Can\'t set property; object is frozen or not extensible.');

			locked = false;
			O[SECRET_KEY][name] = value;

			return value;

		},

		get: function getSecretProperty(O, name) {
			var secretMap, secretProp;
			name = String(name);
			// Turn off autoDefine because we'll be checking the prototype chain
			autoDefine = false;
			do {
				locked = false;
				secretMap = O[SECRET_KEY];
				// We check in case the prototype doesn't have a secret map.
				secretProp = secretMap && secretMap[name];
				if (secretProp !== undefined) {
					autoDefine = true;
					return secretProp;
				}
			} while (O = getPrototypeOf(O));
			autoDefine = true;
		},

		getOwn: function getOwnSecretProperty(O, name) {
			locked = false;
			return O[SECRET_KEY][name];
		},

		has: function hasSecretProperty(O, name) {
			// Doesn't use get because can't distinguish between value *set* to undefined and unassigned.
			var secretMap;
			name = String(name);
			// Turn off autoDefine because we'll be checking the prototype chain
			autoDefine = false;
			do {
				locked = false;
				secretMap = O[SECRET_KEY];
				if (secretMap && name in secretMap) {
					autoDefine = true;
					return true;
				}
			} while (O = getPrototypeOf(O));
			autoDefine = true;
			return false;
		},

		hasOwn: function hasOwnSecretProperty(O, name) {
			locked = false;
			return name in O[SECRET_KEY];
		},

		delete: function deleteSecretProperty(O, name, _freezable) {
			freezable = _freezable;
			if (!permitChange(this, O, name, true))
				throw new TypeError('Can\'t delete property from ' + O);
			locked = false;
			return delete O[SECRET_KEY][name];
		}

	};

	extend(Secrets, {

		// Note to users of this library:
		// Consider deleting the following properties if they are not used by the outside.

		SECRET_KEY: SECRET_KEY,

		prepName: function prepName(name, _freezable) {
			// Allows one access to Secrets(object).get(preppedName)
			// via object[SECRET_KEY] while in locked mode.
			freezable = _freezable;
			preppedName = String(name);
		},

		getIdentifier: getIdentifier

	});

	return Secrets;

	function Secrets(O, name) {
		// Returns undefined if object doesn't already have Secrets and the object is non-extensible. This should
		// really only happen if an object is passed in from another frame, because in this frame preventExtensions
		// is overridden to add a Secrets property first.
		if(O === Object.prototype) return;
		if (O !== Object(O)) throw new Error('Not an object: ' + O);
		if (!hasOwn(O, SECRET_KEY)) {
			if (!autoDefine) return;
			if (!isExtensible(O)) return;
			defineProperty(O, SECRET_KEY, own({

				get: (function() {
					var secretMap = create(
						// Prevent the secret map from having a prototype chain.
						null,
						own({
							Secrets: { value: preloadMethods(methods, O) }
						})
					);
					return function getSecret() {
						var value;
						// The lock protects against retrieval in the event that the SECRET_KEY is found.
						if (locked) {
							if (!preppedName) return;
							var name = preppedName;
							preppedName = undefined;
							value = secretMap.Secrets.get(name);
							return value;
						}
						locked = true;
						return secretMap;
					};
				})(),

				set: function setSecret(value) {
					// Weird Chrome behavior where getOwnPropretyNames seems to call object[key] = true...
					// Let's ignore it.
					if(preppedName === undefined) return;
					var ret;
					locked = false;
					var name = preppedName;
					preppedName = undefined;
					ret = this[SECRET_KEY].Secrets.set(name, value);
					return ret;
				},

				enumerable: false,
				configurable: false

			}));
		}
		locked = false;
		if (name) return O[SECRET_KEY].Secrets.get(name);
		return O[SECRET_KEY].Secrets;
	}

	function getIdentifier() {
		var range = 125 - 65, idS = '';
		idNum[0]++;
		for(var i = 0; i < idNum.length; i++) {
			if (idNum[i] > range) {
				idNum[i] = 0;
				if (i < idNum.length) idNum[i + 1]++;
				else idNum = map(idNum, function() { return 0; });
			}
			idS += encodeStr(idNum[i]);
		}
		return preIdentifier + ':' + join(getRandStrs(8, 11), '/') + ':' + idS;
	}

	function permitChange(methods, O, name, checkExtensible) {
		var _freezable = freezable;
		freezable = true;
		return !(_freezable && (
				isFrozen(O)
				|| checkExtensible && !isExtensible(O) && !methods.hasOwn(name)
			));
	}

	function encodeStr(num) {
		return fromCharCode(num + 65);
	}

	function getRandStrs(count, length) {
		var r = [ ];
		for(var i = 0; i < count; i++) {
			push(r, randStr(length));
		}
		return r;
	}

	function randStr(length) {
		var s = '';
		for (var i = 0; i < length; i++) {
			s += encodeStr(random() * (125 - 65 + 1));
		}
		return s;
	}

	function getRandomGenerator() {
		var getRandomValues
			= typeof crypto != 'undefined' && crypto != null
				? (function() {
					var f = crypto.random || crypto.getRandomValues;
					if (f) return f.bind(crypto);
					return undefined;
				})()
				: undefined;
		if (getRandomValues) {
			// Firefox (15 & 16) seems to be throwing a weird "not implemented" error on getRandomValues.
			// Not sure why?
			try { getRandomValues(new Uint8Array(4)); }
			catch(x) { getRandomValues = undefined }
		}
		if (typeof getRandomValues == 'function' && typeof Uint8Array == 'function') {
			return (function() {
				var values = new Uint8Array(4), index = 4;
				return function random() {
					if (index >= values.length) {
						getRandomValues(values);
						index = 0;
					}
					return values[index++] / 256;
				};
			})();
		} else return Math.random;
	}

	function preloadMethods(methods, arg) {
		var bound = create(null);
		forEach(keys(methods), function(method) {
			bound[method] = bind(methods[method], bound, arg);
		});
		return bound;
	}

	function extend(extendWhat, extendWith) {
		forEach(keys(extendWith), function(key) {
			defineProperty(extendWhat, key, getOwnPropertyDescriptor(extendWith, key));
		});
	}

	function own(obj) {

		var O = create(null);

		forEach(getOwnPropertyNames(obj), function(key) {
			defineProperty(O, key,
				getOwnPropertyDescriptor(obj, key));
		});

		return O;

	}

// We pass in Object and String to ensure that they cannot be changed later to something else.
})(Object, String);

var Symbol = (function() {

	function Symbol(/* params */) {
		// TODO: I think some of the code that's intended to make Symbol work should be pulled
		// out of Secrets and put here instead ... such as the Object.prototype[SECRET_KEY] getter.

		Secrets(this).set('id', '!Y:' + Secrets.getIdentifier());

	}

	// Not sure if the spec will have this property locked, but it's being locked here for
	// security reasons so that a symbol's toString can't be changed.
	Object.defineProperty(Symbol, 'prototype', {
		value: Symbol.prototype,
		writable: false,
		configurable: false
	});

	Object.defineProperties(Symbol.prototype, {

		// Note: Due to this required toString behavior, shimmed Symbols cannot implement any
		// specified toString method.
		toString: {
			value: function() {
				var S = Secrets(this);
				Secrets.prepName(S.get('id'), true);
				return Secrets.SECRET_KEY;
			},
			enumerable: false,
			// This property is locked for added security.
			writable: false,
			configurable: false
		}

	});

	Object.defineProperties(Symbol, {

		// We can't simulate `delete obj[symbol]` in ES5. So we'll have to resort to
		// `Symbol.__deleteSymbol__(obj, symbol)` in this situation.
		__deleteSymbol__: {
			value: function __deleteSymbol__(obj, $symbol) {

				if (!($symbol instanceof Symbol))
					throw new TypeError('Symbol expected.');

				var S = Secrets(obj), T = Secrets($symbol);

				if (!S || !T)
					return false;

				return S.delete(T.get('id'), true);

			},
			enumerable: false,
			writable: false,
			configurable: false
		},

		// We also can't simulate `symbol in obj` in ES5. So we'll have to resort to
		// `Symbol.__hasSymbol__(obj, symbol)` in this situation.
		__hasSymbol__: {
			value: function __hasSymbol__(obj, $symbol) {

				if (!($symbol instanceof Symbol))
					throw new TypeError('Symbol expected.');

				var S = Secrets(obj), T = Secrets($symbol);

				if (!S || !T)
					return false;

				return S.has(T.get('id'));

			},
			enumerable: false,
			writable: false,
			configurable: false
		}

	});

	return Symbol;

})();

	_global.Symbol = Symbol;

	if (exports)
		exports.Secrets = Secrets;

})(typeof _SymbolsForES5_exports == 'undefined' ? undefined : _SymbolsForES5_exports);
