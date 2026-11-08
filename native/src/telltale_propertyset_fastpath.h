#pragma once

class DynarmicHost;

// Installs an exact-version, fail-closed native fast path for
// PropertySet::GetKeyInfo. Returns true only when the guest entry point was
// fingerprinted and patched successfully.
bool InstallTelltaleGetKeyInfoAcceleration(DynarmicHost& host);
