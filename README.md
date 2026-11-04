# Clio DOSGuard reachable assertion (remote process termination)

One unauthenticated HTTP POST terminates the `clio_server` process.

**Affected:** XRPLF Clio 2.7.0 through 2.8.0, and `develop` at `8ef41ce47038518846120cc6426df65a8c559769`.

**Precondition:** ng web server enabled (`server.__ng_web_server: true`, or `-w`) and at least one entry in `dos_guard.__ng_weights`.

## What happens

`web::dosguard::Weights::requestWeight` asserts that `params` is a non-empty array whose first element is an object:

```cpp
ASSERT(request.at(JS(params)).is_array() and not ...empty() and ...at(0).is_object(), "params should be [{{}}]");
```

In the ng web server the DOS guard runs before `params` is normalised:

```cpp
if (not dosguard_.get().request(connectionMetadata.ip(), parsedObject)) { ... }   // first
if (not connectionMetadata.wasUpgraded() and shouldReplaceParams(parsedObject)) { // too late
    parsedObject[JS(params)] = boost::json::array({boost::json::object{}}); }
```

The legacy web server normalises first and is unaffected. `ASSERT` is not guarded by `NDEBUG` and its handler calls `std::exit(EXIT_FAILURE)`, so release builds die rather than skipping the check.

Any `params` that is present but not `[{...}]` triggers it: `"pwn"`, `1`, `[1]`, `{}`.

## Reproduce

```
./poc.sh <host> <port>     # against a running instance
./repro-local.sh           # uses ghcr.io/xrplf/clio:nightly (might not work after patch youll have to install a vulnerable version)
```

`params: [{}]` returns HTTP 200 and the process stays up. `params: "pwn"` drops the connection and the process is gone, with `Assertion failed` in the log.

## Fix

```cpp
auto const it = request.find(JS(params));
if (it == request.end() or not it->value().is_array() or it->value().as_array().empty() or not it->value().as_array().at(0).is_object())
    return defaultWeight_;

Or normalise params before invoking the DOS guard, matching the legacy ordering.
```

## Disclosure

Reported to the vendor on 2026-05-05. Re-tested against `ghcr.io/xrplf/clio:nightly` on 2026-11-04, still reproduces 
