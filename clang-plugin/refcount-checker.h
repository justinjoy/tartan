/* -*- Mode: C++; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * Tartan
 * Copyright © 2014 Philip Withnall
 *
 * Tartan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tartan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tartan.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Philip Withnall <philip@tecnocode.co.uk>
 */

#ifndef TARTAN_REFCOUNT_CHECKER_H
#define TARTAN_REFCOUNT_CHECKER_H

#include <clang/AST/AST.h>
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>

#include "checker.h"
#include "gir-manager.h"

namespace tartan {

using namespace clang;
using namespace ento;

class RefcountChecker : public ento::Checker<check::PostStmt<CallExpr>> {
public:
	explicit RefcountChecker () :
		_gir_manager () {};

private:
	/* TODO: Share this with other checkers. */
	GirManager _gir_manager;

	/* Cached function identifiers. */
	mutable IdentifierInfo *_g_object_ref_identifier;
	mutable IdentifierInfo *_g_object_unref_identifier;

	void _initialise_identifiers (ASTContext &context) const;

	/* Cached bug reports. */
	mutable OwningPtr<BuiltinBug> _unref_bug;

	void _initialise_bug_reports () const;

	void _check_g_object_ref (const CallExpr *call,
	                          CheckerContext &context) const;
	void _check_g_object_unref (const CallExpr *call,
	                            CheckerContext &context) const;

public:
	void checkPostStmt (const CallExpr *call, CheckerContext &context) const;

	/* TODO: doesn't implement tartan::Checker */
	const std::string get_name () const { return "refcount"; }
};

} /* namespace tartan */

#endif /* !TARTAN_REFCOUNT_CHECKER_H */
