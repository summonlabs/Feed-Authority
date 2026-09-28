#pragma once

// Protected-load obligations.
//
// The obligation type is declared in policy.hpp, next to the plan that contains it,
// because a policy set owns its obligations and the two are never meaningful apart.
// This header exists so that code which is about obligations can include the name it
// means. The semantics are documented on ProtectedObligation itself.

#include "feed_authority/policy.hpp"
